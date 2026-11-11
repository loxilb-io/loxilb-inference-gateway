package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = `package models
import "github.com/go-openapi/strfmt"
type EndPointHostState struct { EpPort int64 }
func (value *EndPointHostState) Validate(formats strfmt.Registry) error {
 if value.EpPort > 65535 { return fieldError() }
 return nil
}
func (value *EndPointHostState) ContextValidate() error { return nil }
`

func TestSynchronizePreservesGeneratedChecksAndIsIdempotent(t *testing.T) {
	out, err := synchronize([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("if value.EpPort > 65535")) ||
		!bytes.Contains(out, []byte("ContextValidate() error")) {
		t.Fatal("generated field or context validation was removed")
	}
	if bytes.Index(out, []byte(hook+"(value)")) > bytes.Index(out, []byte("value.EpPort > 65535")) {
		t.Fatal("custom check must run before generated dereferences")
	}
	again, err := synchronize(out)
	if err != nil || !bytes.Equal(out, again) || bytes.Count(out, []byte(hook+"(")) != 1 {
		t.Fatalf("not idempotent: %v", err)
	}
}

func TestUnexpectedGeneratedShapeFailsClosed(t *testing.T) {
	for name, source := range map[string]string{
		"syntax":       "package",
		"package":      strings.Replace(fixture, "package models", "package other", 1),
		"missing":      strings.Replace(fixture, " Validate(", " Other(", 1),
		"duplicate":    fixture + "func (m *EndPointHostState) Validate(f strfmt.Registry) error { return nil }",
		"wrong-result": strings.Replace(fixture, ") error {", ") int {", 1),
		"wrong-param":  strings.Replace(fixture, "formats strfmt.Registry", "formats string", 1),
		"late-hook":    strings.Replace(fixture, " return nil", " _ = "+hook+"(value)\n return nil", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := synchronize([]byte(source)); err == nil {
				t.Fatal("unexpected generated shape was accepted")
			}
		})
	}
}

func TestCheckAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.go")
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(path, true); err == nil {
		t.Fatal("check accepted missing hook")
	}
	before, _ := os.ReadFile(path)
	if !bytes.Equal(before, []byte(fixture)) {
		t.Fatal("check mutated the source")
	}
	link := filepath.Join(dir, "link.go")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := run(link, false); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := run(path, false); err != nil {
		t.Fatal(err)
	}
	if err := run(path, true); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("permissions changed")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".model-validation-*"))
	if len(leftovers) != 0 {
		t.Fatal("temporary files leaked")
	}
}
