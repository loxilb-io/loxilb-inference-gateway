// metric-manifest extracts the repository's Prometheus metric definitions by
// parsing Go source (go/ast), not by grepping string literals. It emits one
// JSON document on stdout describing every metric family constructor found:
// name (with Namespace/Subsystem composition resolved), value type, label
// schema, help text, defining file:line, and registration mechanism.
//
// The output is the ground truth consumed by
// deploy/monitoring/ci/gen-metric-manifest.py, which merges human-owned
// applicability/activation metadata and enforces the monitoring ownership
// contract in CI.
//
// Scope rules:
//   - every non-test .go file under the repository root is scanned
//   - the eBPF submodule, vendored code, and third-party trees are skipped
//   - const/var string bindings are resolved within each package directory,
//     so `Name: MetricFoo` and label-name constants yield real strings
//
// Usage:
//
//	go run ./tools/metric-manifest -root . [-pretty]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Def is one discovered metric family definition.
type Def struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`   // counter|gauge|histogram|summary|desc
	Vec        bool     `json:"vec"`    // label-vector constructor
	Labels     []string `json:"labels"` // variable label names ([] for scalars)
	Help       string   `json:"help,omitempty"`
	File       string   `json:"file"` // repo-relative
	Line       int      `json:"line"`
	Mechanism  string   `json:"mechanism"`            // promauto|manual|desc
	Unresolved bool     `json:"unresolved,omitempty"` // name could not be reduced to a string
}

var skipDirs = map[string]bool{
	".git": true, "loxilb-ebpf": true, "vendor": true, "node_modules": true,
	"3rdparty": true, "__pycache__": true,
}

var ctorType = map[string]string{
	"NewCounter": "counter", "NewCounterVec": "counter", "NewCounterFunc": "counter",
	"NewGauge": "gauge", "NewGaugeVec": "gauge", "NewGaugeFunc": "gauge",
	"NewHistogram": "histogram", "NewHistogramVec": "histogram",
	"NewSummary": "summary", "NewSummaryVec": "summary",
}

func main() {
	root := flag.String("root", ".", "repository root")
	pretty := flag.Bool("pretty", false, "indent JSON output")
	flag.Parse()

	pkgs := map[string][]string{} // dir -> files
	err := filepath.Walk(*root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir := filepath.Dir(path)
		pkgs[dir] = append(pkgs[dir], path)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk:", err)
		os.Exit(2)
	}

	var defs []Def
	fset := token.NewFileSet()
	for dir, files := range pkgs {
		consts := map[string]string{}
		slices := map[string][]string{}
		parsed := map[string]*ast.File{}
		for _, f := range files {
			af, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "parse %s: %v\n", f, err)
				continue
			}
			parsed[f] = af
			collectStringBindings(af, consts)
		}
		for _, af := range parsed {
			collectSliceBindings(af, consts, slices)
		}
		// A prometheus.NewDesc call cannot state the runtime type -- the type
		// is chosen later, where the Desc is turned into a metric. Both halves
		// are statically resolvable, so resolve them: which variable holds each
		// Desc, and which value kind that variable is emitted with.
		descVar := map[token.Pos]string{}
		descRuntime := map[string]string{}
		for _, af := range parsed {
			collectDescBindings(af, descVar)
			collectDescRuntimeTypes(af, descRuntime)
		}
		_ = dir
		for f, af := range parsed {
			rel, _ := filepath.Rel(*root, f)
			ast.Inspect(af, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				fn := sel.Sel.Name
				if t, isCtor := ctorType[fn]; isCtor && callerIsPrometheus(sel.X) {
					d := extractOpts(call, t, fn, consts, slices)
					if d != nil {
						d.File = filepath.ToSlash(rel)
						d.Line = fset.Position(call.Pos()).Line
						if base, okX := sel.X.(*ast.Ident); okX && base.Name == "promauto" {
							d.Mechanism = "promauto"
						} else if _, isCall := sel.X.(*ast.CallExpr); isCall {
							d.Mechanism = "promauto" // promauto.With(reg).NewX
						} else {
							d.Mechanism = "manual"
						}
						defs = append(defs, *d)
					}
					return true
				}
				if fn == "NewDesc" && callerIsPrometheus(sel.X) {
					d := extractDesc(call, consts, slices)
					if d != nil {
						d.File = filepath.ToSlash(rel)
						d.Line = fset.Position(call.Pos()).Line
						// Mechanism stays "desc"; Type becomes the type the
						// collector actually emits. A Desc that is never
						// emitted, emitted inconsistently, or not bound to a
						// variable keeps Type "desc", which the manifest
						// generation gate rejects rather than shipping.
						if v, ok := descVar[call.Pos()]; ok {
							if rt, ok := descRuntime[v]; ok && rt != "" {
								d.Type = rt
							}
						}
						defs = append(defs, *d)
					}
				}
				return true
			})
		}
	}

	sort.Slice(defs, func(i, j int) bool {
		if defs[i].Name != defs[j].Name {
			return defs[i].Name < defs[j].Name
		}
		return defs[i].File < defs[j].File
	})
	enc := json.NewEncoder(os.Stdout)
	if *pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(defs); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(2)
	}
}

// callerIsPrometheus reports whether the selector base can be a prometheus or
// promauto factory: the package idents themselves, or a promauto.With(...)
// call chain.
func callerIsPrometheus(x ast.Expr) bool {
	switch v := x.(type) {
	case *ast.Ident:
		return v.Name == "prometheus" || v.Name == "promauto"
	case *ast.CallExpr:
		if s, ok := v.Fun.(*ast.SelectorExpr); ok {
			if id, ok := s.X.(*ast.Ident); ok {
				return id.Name == "promauto" && s.Sel.Name == "With"
			}
		}
	}
	return false
}

// collectStringBindings records `const x = "..."` / `var x = "..."` (grouped
// or single) so identifiers used as Name:/label values resolve to strings.
func collectStringBindings(f *ast.File, out map[string]string) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil {
						out[name.Name] = s
					}
				}
			}
		}
	}
}

// collectSliceBindings records `var x = []string{...}` package-level slices so
// a shared label-schema variable passed to a constructor resolves to names.
func collectSliceBindings(f *ast.File, consts map[string]string, out map[string][]string) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				cl, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					continue
				}
				var vals []string
				good := true
				for _, el := range cl.Elts {
					s, ok := resolveString(el, consts)
					if !ok {
						good = false
						break
					}
					vals = append(vals, s)
				}
				if good && vals != nil {
					out[name.Name] = vals
				}
			}
		}
	}
}

func resolveString(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			if s, err := strconv.Unquote(v.Value); err == nil {
				return s, true
			}
		}
	case *ast.Ident:
		if s, ok := consts[v.Name]; ok {
			return s, true
		}
	case *ast.SelectorExpr:
		// pkg.Const from another package: fall back to the bare selector name
		// lookup (same-repo const collection is per-package, so this stays a
		// best effort and is reported unresolved when it misses).
		if s, ok := consts[v.Sel.Name]; ok {
			return s, true
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			l, lok := resolveString(v.X, consts)
			r, rok := resolveString(v.Y, consts)
			if lok && rok {
				return l + r, true
			}
		}
	}
	return "", false
}

func resolveLabels(e ast.Expr, consts map[string]string, slices map[string][]string) []string {
	if id, ok := e.(*ast.Ident); ok {
		if id.Name == "nil" {
			return nil
		}
		if v, ok := slices[id.Name]; ok {
			return v
		}
		return []string{"?"}
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var out []string
	for _, el := range cl.Elts {
		if s, ok := resolveString(el, consts); ok {
			out = append(out, s)
		} else {
			out = append(out, "?")
		}
	}
	return out
}

// extractOpts handles NewCounter[Vec]/NewGauge[Vec]/... calls: first arg is a
// *Opts composite literal; Vec forms carry the label slice as the second arg.
func extractOpts(call *ast.CallExpr, typ, fn string, consts map[string]string, slices map[string][]string) *Def {
	if len(call.Args) == 0 {
		return nil
	}
	cl, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return nil
	}
	// Only prometheus.XxxOpts literals define metric families here.
	if s, ok := cl.Type.(*ast.SelectorExpr); !ok || !strings.HasSuffix(s.Sel.Name, "Opts") {
		return nil
	}
	var name, ns, sub, help string
	unresolved := false
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		val, resolved := resolveString(kv.Value, consts)
		switch key.Name {
		case "Name":
			name = val
			if !resolved {
				unresolved = true
			}
		case "Namespace":
			ns = val
		case "Subsystem":
			sub = val
		case "Help":
			help = val
		}
	}
	if name == "" && !unresolved {
		return nil
	}
	full := joinFQ(ns, sub, name)
	d := &Def{Name: full, Type: typ, Help: help, Unresolved: unresolved}
	if strings.HasSuffix(fn, "Vec") {
		d.Vec = true
		if len(call.Args) > 1 {
			d.Labels = resolveLabels(call.Args[1], consts, slices)
		}
	}
	if d.Labels == nil {
		d.Labels = []string{}
	}
	return d
}

// extractDesc handles prometheus.NewDesc(fqName, help, variableLabels, const).
func extractDesc(call *ast.CallExpr, consts map[string]string, slices map[string][]string) *Def {
	if len(call.Args) < 2 {
		return nil
	}
	var name string
	unresolved := false
	switch a := call.Args[0].(type) {
	case *ast.CallExpr:
		// prometheus.BuildFQName(ns, sub, name)
		if s, ok := a.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "BuildFQName" && len(a.Args) == 3 {
			var parts []string
			for _, arg := range a.Args {
				v, ok := resolveString(arg, consts)
				if !ok {
					unresolved = true
				}
				parts = append(parts, v)
			}
			name = joinFQ(parts[0], parts[1], parts[2])
		} else {
			unresolved = true
		}
	default:
		v, ok := resolveString(a, consts)
		if !ok {
			unresolved = true
		}
		name = v
	}
	help, _ := resolveString(call.Args[1], consts)
	d := &Def{Name: name, Type: "desc", Help: help, Mechanism: "desc", Unresolved: unresolved}
	if len(call.Args) > 2 {
		d.Labels = resolveLabels(call.Args[2], consts, slices)
		d.Vec = len(d.Labels) > 0
	}
	if d.Labels == nil {
		d.Labels = []string{}
	}
	return d
}

func joinFQ(ns, sub, name string) string {
	var parts []string
	for _, p := range []string{ns, sub, name} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "_")
}

// constMetricType maps the constructor that consumes a Desc to the runtime
// metric type it produces. MustNewConstMetric carries the kind in its second
// argument instead, and is handled separately.
var constMetricType = map[string]string{
	"MustNewConstHistogram":         "histogram",
	"NewConstHistogram":             "histogram",
	"MustNewConstSummary":           "summary",
	"NewConstSummary":               "summary",
	"MustNewConstMetricWithCreated": "",
	"NewConstMetricWithCreated":     "",
}

// valueType maps a prometheus value-kind selector to the manifest type name.
var valueType = map[string]string{
	"CounterValue": "counter",
	"GaugeValue":   "gauge",
	"UntypedValue": "untyped",
}

// descConflict marks a Desc emitted with more than one runtime type. It is
// stored in place of a type so the manifest gate rejects it: a family whose
// type depends on which branch ran is not a family the manifest can describe.
const descConflict = "conflict"

// collectDescBindings records, for each prometheus.NewDesc call, the variable
// it is assigned to. Both `var x = prometheus.NewDesc(...)` and `x :=
// prometheus.NewDesc(...)` bind; an unassigned call is left out, so its type
// cannot be resolved and stays "desc".
func collectDescBindings(af *ast.File, out map[token.Pos]string) {
	bind := func(lhs []ast.Expr, rhs []ast.Expr) {
		if len(lhs) != len(rhs) {
			return
		}
		for i, r := range rhs {
			call, ok := r.(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewDesc" || !callerIsPrometheus(sel.X) {
				continue
			}
			if id, ok := lhs[i].(*ast.Ident); ok {
				out[call.Pos()] = id.Name
			}
		}
	}
	ast.Inspect(af, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			names := make([]ast.Expr, 0, len(v.Names))
			for _, id := range v.Names {
				names = append(names, id)
			}
			bind(names, v.Values)
		case *ast.AssignStmt:
			bind(v.Lhs, v.Rhs)
		}
		return true
	})
}

// collectDescRuntimeTypes records the runtime type each Desc variable is
// emitted with. A variable emitted with two different types is recorded as a
// conflict rather than resolved arbitrarily.
func collectDescRuntimeTypes(af *ast.File, out map[string]string) {
	record := func(name, typ string) {
		if name == "" || typ == "" {
			return
		}
		if prev, seen := out[name]; seen && prev != typ {
			out[name] = descConflict
			return
		}
		out[name] = typ
	}
	ast.Inspect(af, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !callerIsPrometheus(sel.X) || len(call.Args) == 0 {
			return true
		}
		desc, ok := call.Args[0].(*ast.Ident)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "MustNewConstMetric", "NewConstMetric":
			// The value kind is the second argument.
			if len(call.Args) < 2 {
				return true
			}
			kind, ok := call.Args[1].(*ast.SelectorExpr)
			if !ok {
				return true
			}
			record(desc.Name, valueType[kind.Sel.Name])
		default:
			if t, known := constMetricType[sel.Sel.Name]; known {
				record(desc.Name, t)
			}
		}
		return true
	})
}
