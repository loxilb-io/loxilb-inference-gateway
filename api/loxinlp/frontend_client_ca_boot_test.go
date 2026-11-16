package loxinlp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestFrontendClientCAStartupPrune(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, cmn.FrontendClientCADir)
	if err := os.Mkdir(managed, 0700); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(managed, strings.Repeat("a", 64)+".pem")
	orphan := filepath.Join(managed, strings.Repeat("b", 64)+".pem")
	crl := filepath.Join(managed, "crl.pem")
	for _, name := range []string{pinned, orphan, crl} {
		if err := os.WriteFile(name, []byte("test material"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "explicit-ca.pem")
	if err := os.Symlink(pinned, alias); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeRoot, err := filepath.Rel(cwd, root)
	if err != nil {
		t.Fatal(err)
	}
	rules := []cmn.LbRuleMod{{Serv: cmn.LbServiceArg{
		MTLSFrontend: &cmn.MTLSFrontendConfig{ClientCertMode: "required", ClientCAPath: alias},
	}}}
	if err := pruneFrontendClientCAs(relativeRoot, rules); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{pinned, crl} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("file should be retained: %v", err)
		}
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("orphan should be removed: %v", err)
	}
}
