// Command sync-swagger preserves the source contract in generated SwaggerJSON.
// go-swagger 0.30.3's OrigSpec clone loses pointers to zero-valued minima.
// FlatSwaggerJSON and generated validators are deliberately left untouched.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func jsonValue(v any) (any, error) {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			next, err := jsonValue(value)
			if err != nil {
				return nil, err
			}
			out[key] = next
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			var name string
			switch key := key.(type) {
			case string:
				name = key
			case int:
				name = fmt.Sprint(key) // YAML response status keys.
			default:
				return nil, fmt.Errorf("unsupported YAML mapping key %T", key)
			}
			if _, exists := out[name]; exists {
				return nil, fmt.Errorf("colliding JSON key %q", name)
			}
			next, err := jsonValue(value)
			if err != nil {
				return nil, err
			}
			out[name] = next
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, value := range v {
			next, err := jsonValue(value)
			if err != nil {
				return nil, err
			}
			out[i] = next
		}
		return out, nil
	default:
		return v, nil
	}
}

func sourceJSON(raw []byte) ([]byte, error) {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one YAML document: %v", err)
	}
	value, err := jsonValue(value)
	if err != nil {
		return nil, err
	}
	doc, ok := value.(map[string]any)
	if !ok || doc["swagger"] != "2.0" {
		return nil, fmt.Errorf("expected a Swagger 2.0 object")
	}
	return json.MarshalIndent(doc, "", "  ")
}

func synchronize(spec, source []byte) ([]byte, error) {
	raw, err := sourceJSON(spec)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "embedded_spec.go", source, 0)
	if err != nil {
		return nil, err
	}
	var target ast.Expr
	count := 0
	flatCount := 0
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if ok && id.Name == "FlatSwaggerJSON" {
			flatCount++
		}
		if ok && id.Name == "SwaggerJSON" {
			count++
			target = assign.Rhs[0]
		}
		return true
	})
	if count != 1 {
		return nil, fmt.Errorf("expected one SwaggerJSON assignment, found %d", count)
	}
	if flatCount != 1 {
		return nil, fmt.Errorf("expected one FlatSwaggerJSON assignment, found %d", flatCount)
	}
	// Keep a readable raw literal and safely encode Markdown backticks.
	quoted := strings.ReplaceAll(string(raw), "`", "` + \"`\" + `")
	replacement := "json.RawMessage([]byte(`" + quoted + "`))"
	start, end := fset.Position(target.Pos()).Offset, fset.Position(target.End()).Offset
	out := append([]byte(nil), source[:start]...)
	out = append(out, replacement...)
	out = append(out, source[end:]...)
	if _, err := parser.ParseFile(token.NewFileSet(), "embedded_spec.go", out, 0); err != nil {
		return nil, err
	}
	return out, nil
}

func run(specPath, generatedPath string, check bool) error {
	info, err := os.Lstat(generatedPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("generated target must be a regular file, not a symlink or directory")
	}
	spec, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	source, err := os.ReadFile(generatedPath)
	if err != nil {
		return err
	}
	out, err := synchronize(spec, source)
	if err != nil {
		return err
	}
	if bytes.Equal(out, source) {
		return nil
	}
	if check {
		return fmt.Errorf("SwaggerJSON source drift: run sync-swagger without -check")
	}
	tmp, err := os.CreateTemp(filepath.Dir(generatedPath), ".embedded-spec-*.go")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), generatedPath)
}

func main() {
	spec := flag.String("spec", "api/swagger.yml", "source Swagger YAML")
	generated := flag.String("generated", "api/restapi/embedded_spec.go", "generated Go file")
	check := flag.Bool("check", false, "fail on drift without writing")
	flag.Parse()
	if err := run(*spec, *generated, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("PASS: SwaggerJSON preserves the source contract; flattened spec untouched")
}
