// Command sync-model-validators wires persistent model validation into freshly
// generated code without replacing the generator's schema-derived checks.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
)

const hook = "validateEndPointHostStateTuple"

func synchronize(source []byte) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "end_point_host_state.go", source, 0)
	if err != nil {
		return nil, err
	}
	if file.Name.Name != "models" {
		return nil, fmt.Errorf("expected package models")
	}
	var target *ast.FuncDecl
	var receiver string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Validate" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		field := fn.Recv.List[0]
		ptr, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		id, ok := ptr.X.(*ast.Ident)
		if !ok || id.Name != "EndPointHostState" {
			continue
		}
		if target != nil || len(field.Names) != 1 || fn.Body == nil ||
			fn.Type.Params.NumFields() != 1 || fn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("unexpected EndPointHostState.Validate signature")
		}
		param, ok := fn.Type.Params.List[0].Type.(*ast.SelectorExpr)
		if !ok || param.Sel.Name != "Registry" {
			return nil, fmt.Errorf("unexpected validation registry parameter")
		}
		pkg, ok := param.X.(*ast.Ident)
		result, resultOK := fn.Type.Results.List[0].Type.(*ast.Ident)
		if !ok || pkg.Name != "strfmt" || !resultOK || result.Name != "error" || field.Names[0].Name == "_" {
			return nil, fmt.Errorf("unexpected validation signature")
		}
		target, receiver = fn, field.Names[0].Name
	}
	if target == nil {
		return nil, fmt.Errorf("missing EndPointHostState.Validate method")
	}
	calls := 0
	ast.Inspect(target.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == hook {
				calls++
			}
		}
		return true
	})
	prefix := "\n\tif err := " + hook + "(" + receiver + "); err != nil {\n\t\treturn err\n\t}\n"
	start := fset.Position(target.Body.Lbrace).Offset + 1
	if calls != 0 {
		if calls != 1 || !bytes.HasPrefix(source[start:], []byte(prefix)) {
			return nil, fmt.Errorf("validation hook is duplicated or not the first check")
		}
		return source, nil
	}
	out := append([]byte(nil), source[:start]...)
	out = append(out, prefix...)
	out = append(out, source[start:]...)
	return format.Source(out)
}

func run(path string, check bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("generated model must be a regular file")
	}
	source, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, err := synchronize(source)
	if err != nil || bytes.Equal(out, source) {
		return err
	}
	if check {
		return fmt.Errorf("model validation hook missing: regenerate the API")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".model-validation-*.go")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := f.Write(out); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func main() {
	generated := flag.String("generated", "api/models/end_point_host_state.go", "generated model")
	check := flag.Bool("check", false, "fail on drift without writing")
	flag.Parse()
	if err := run(*generated, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
