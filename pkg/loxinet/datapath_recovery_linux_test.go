// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatapathRecoveryJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datapath.json")
	journal, err := openDatapathJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.lock.Close()

	if other, err := openDatapathJournal(path); err == nil {
		other.lock.Close()
		t.Fatal("opened recovery journal while the Gateway holds its lock")
	}
	if err := journal.save(nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected state file permissions %v", info.Mode())
	}

	foreign := journal.receipt
	foreign.NetNS = "foreign"
	data, err := json.Marshal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := journal.detach(io.Discard); err == nil || !strings.Contains(err.Error(), "another network namespace") {
		t.Fatalf("foreign namespace accepted: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("foreign record was removed: %v", err)
	}

	if err := journal.save(nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := journal.detach(io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file survived cleanup: %v", err)
	}
}
