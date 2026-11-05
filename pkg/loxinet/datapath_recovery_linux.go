// SPDX-License-Identifier: Apache-2.0

package loxinet

/*
#include "datapath_detach_linux.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type datapathReceipt struct {
	BootID string                  `json:"boot_id"`
	NetNS  string                  `json:"network_namespace"`
	Links  map[string]datapathHook `json:"links"`
}

type datapathHook struct {
	Index   int    `json:"ifindex"`
	Generic uint32 `json:"xdp_generic"`
	Native  uint32 `json:"xdp_native"`
	Ingress uint32 `json:"tc_ingress"`
	Egress  uint32 `json:"tc_egress"`
}

type datapathJournal struct {
	path    string
	lock    *os.File
	receipt datapathReceipt
}

// The live Gateway holds the journal lock until process exit, including after
// the graceful detach stage. An offline invocation must acquire the same lock.
var activeDatapathJournal *datapathJournal

func openDatapathJournal(path string) (*datapathJournal, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("datapath state path must be absolute")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &ns); err != nil {
		return nil, err
	}

	path = filepath.Clean(path)
	fd, err := unix.Open(path+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), path+".lock")
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("datapath state %s is locked: %w", path, err)
	}
	return &datapathJournal{
		path: path,
		lock: lock,
		receipt: datapathReceipt{
			BootID: strings.TrimSpace(string(boot)),
			NetNS:  fmt.Sprintf("%d:%d", ns.Dev, ns.Ino),
		},
	}, nil
}

func (j *datapathJournal) clear() error {
	err := os.Remove(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (j *datapathJournal) save(links map[string]datapathLinkPrograms) error {
	j.receipt.Links = make(map[string]datapathHook, len(links))
	for name, link := range links {
		j.receipt.Links[name] = datapathHook{
			Index: link.index, Generic: uint32(link.ids.skb), Native: uint32(link.ids.drv),
			Ingress: uint32(link.ids.ingress), Egress: uint32(link.ids.egress),
		}
	}

	temp, err := os.CreateTemp(filepath.Dir(j.path), ".datapath-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	writeErr := json.NewEncoder(temp).Encode(j.receipt)
	if err := errors.Join(writeErr, temp.Close()); err != nil {
		return err
	}
	return os.Rename(temp.Name(), j.path)
}

func (j *datapathJournal) detach(out io.Writer) error {
	fd, err := unix.Open(j.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), j.path)
	defer f.Close()
	const maxReceiptSize = 1 << 20
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxReceiptSize {
		return fmt.Errorf("invalid datapath state file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxReceiptSize+1))
	if err != nil {
		return err
	}
	var state datapathReceipt
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("invalid datapath state: %w", err)
	}
	if state.BootID == "" || state.NetNS == "" || state.Links == nil {
		return fmt.Errorf("incomplete datapath state")
	}
	if state.BootID != j.receipt.BootID {
		return j.clear()
	}
	if state.NetNS != j.receipt.NetNS {
		return fmt.Errorf("datapath state belongs to another network namespace")
	}

	var detachErr error
	for name, link := range state.Links {
		if link.Index <= 0 || int64(link.Index) > 1<<31-1 {
			return fmt.Errorf("invalid interface index for %s", name)
		}
	}
	for name, link := range state.Links {
		var detached C.int
		ids := C.struct_llb_link_programs{
			skb: C.__u32(link.Generic), drv: C.__u32(link.Native),
			ingress: C.__u32(link.Ingress), egress: C.__u32(link.Egress),
		}
		ret := C.llb_shutdown_detach(C.int(link.Index), ids, &detached)
		if detached > 0 {
			fmt.Fprintf(out, "detached %d datapath programs on %s\n", int(detached), name)
		}
		if ret < 0 {
			detachErr = errors.Join(detachErr, fmt.Errorf("detach on %s: %w", name, syscall.Errno(-ret)))
		}
	}
	if detachErr != nil {
		return detachErr
	}
	return j.clear()
}

// PrepareDatapathRecovery locks the optional state file before datapath startup.
func PrepareDatapathRecovery(path string) error {
	if path == "" {
		return nil
	}
	journal, err := openDatapathJournal(path)
	if err != nil {
		return err
	}
	if err := journal.detach(os.Stdout); err != nil {
		journal.lock.Close()
		return err
	}
	if err := journal.save(nil); err != nil {
		journal.lock.Close()
		return err
	}
	activeDatapathJournal = journal
	return nil
}

// RecoverDatapath removes attachments recorded by a stopped Gateway instance.
func RecoverDatapath(path string) error {
	journal, err := openDatapathJournal(path)
	if err != nil {
		return err
	}
	defer journal.lock.Close()
	return journal.detach(os.Stdout)
}
