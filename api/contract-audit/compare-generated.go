//go:build ignore

// Compare generated Go syntax without comments before copying documentation updates.
// Usage: go run compare-generated.go ORIGINAL_DIR GENERATED_DIR
package main

import (
	"bytes"
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
)

func normalized(path string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0) // No ParseComments.
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = printer.Fprint(&b, token.NewFileSet(), f)
	return b.Bytes(), err
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: compare-generated ORIGINAL_DIR GENERATED_DIR")
		os.Exit(2)
	}
	entries, err := os.ReadDir(os.Args[2])
	if err != nil {
		panic(err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		old := filepath.Join(os.Args[1], e.Name())
		candidate := filepath.Join(os.Args[2], e.Name())
		a, err := normalized(old)
		if err != nil {
			panic(err)
		}
		b, err := normalized(candidate)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(a, b) {
			fmt.Fprintln(os.Stderr, "NON-COMMENT CHANGE:", e.Name())
			os.Exit(1)
		}
		count++
	}
	fmt.Printf("PASS: %d generated model files have identical non-comment Go syntax\n", count)
}
