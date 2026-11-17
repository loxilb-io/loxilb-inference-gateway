// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

package tk

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLoxilibImportsAreConfinedToFacade(t *testing.T) {
	root := filepath.Join("..", "..")
	facade := filepath.Join(root, "internal", "tk")
	files := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch path {
			case filepath.Join(root, ".git"), filepath.Join(root, ".review"),
				filepath.Join(root, "vendor"), filepath.Join(root, "loxilb-ebpf"):
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || filepath.Dir(path) == facade {
			return nil
		}
		file, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			module, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if module == "github.com/loxilb-io/loxilib" {
				t.Errorf("%s: import github.com/loxilb-io/loxilb/internal/tk instead", files.Position(spec.Pos()))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
