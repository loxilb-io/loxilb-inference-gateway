// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package bfd

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/common"
)

var electionTableFile = flag.String("ha-election-table", "", "write the checked election decision table as TSV")

func TestElectionTable(t *testing.T) {
	ranks := []uint32{0, 1, 2, 3, 4, 5, 6, ^uint32(0)}
	states := []struct {
		state electionState
		name  string
	}{
		{electionWaiting, "admin_down"},
		{electionWaiting, "down"},
		{electionWaiting, "init"},
		{electionUp, "up"},
		{electionPeerLost, "peer_lost"},
		{electionStartExpired, "start_expired"},
		{electionStartWithoutBFD, "start_without_bfd"},
	}
	const (
		backup = common.CIBackupStateString
		master = common.CIMasterStateString
	)
	reasons := map[byte]electionDecision{
		'B': {backup, "waiting_for_peer"}, 'M': {master, "waiting_for_peer"},
		'W': {master, "peer_withdrawn"}, 'E': {backup, "equal_rank"},
		'L': {backup, "legacy_peer"}, 'P': {master, "preferred_rank"},
		'R': {backup, "peer_preferred"}, 'I': {backup, "invalid_local_rank"},
		'X': {backup, "ineligible"}, 'S': {backup, "shutdown_withdrawal"},
		'T': {master, "peer_timeout"}, 'A': {master, "active_alone"}, 'N': {master, "active_without_bfd"},
	}
	// UP table columns are unknown, withdrawn, backup-low, backup-high,
	// master-low, master-high, legacy-min, legacy-max.
	up := []string{
		"IIIIIIII",
		"XXXXXXXX",
		"BWERRRLL",
		"BWPERRLL",
		"MWPPERLL",
		"MWPPPELL",
		"IIIIIIII",
		"IIIIIIII",
	}
	var report strings.Builder
	report.WriteString("local_rank\tremote_rank\tbfd_state\tlocal_eligible\tshutting_down\trole\treason\n")
	for li, local := range ranks {
		for ri, remote := range ranks {
			for _, s := range states {
				for _, eligible := range []bool{false, true} {
					for _, shutdown := range []bool{false, true} {
						code := "IXBBMMII"[li]
						switch {
						case shutdown:
							code = 'S'
						case !eligible:
							code = 'X'
						case s.state == electionUp:
							code = up[li][ri]
						case code == 'B' || code == 'M':
							switch s.state {
							case electionPeerLost:
								code = 'T'
							case electionStartExpired:
								code = 'A'
							case electionStartWithoutBFD:
								code = 'N'
							}
						}
						want := reasons[code]
						got := elect(local, remote, s.state, eligible, shutdown)
						if got != want {
							t.Errorf("elect(%d,%d,%s,%t,%t)=%+v, want %+v", local, remote, s.name, eligible, shutdown, got, want)
						}
						fmt.Fprintf(&report, "%d\t%d\t%s\t%t\t%t\t%s\t%s\n", local, remote, s.name, eligible, shutdown, got.role, got.reason)
					}
				}
			}
		}
	}
	if *electionTableFile != "" && !t.Failed() {
		if err := os.WriteFile(*electionTableFile, []byte(report.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

type electionRecorder struct {
	roles []string
}

func (n *electionRecorder) BFDSessionNotify(_, _, role string) {
	n.roles = append(n.roles, role)
}

func TestElectionReceiveAndTimeoutOrder(t *testing.T) {
	for _, tc := range []struct {
		name         string
		timeoutFirst bool
		want         string
	}{
		{"receive before timeout", false, ""},
		{"timeout before receive", true, "MASTER,BACKUP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			n := &electionRecorder{}
			b := &bfdSession{
				pairElection: true, backupRank: lowBackupRank, MyDisc: lowBackupRank,
				RemDisc: highMasterRank, State: BFDUp, CiState: common.CIBackupStateString,
				LastRxTS: now.Add(-time.Second), openAt: now.Add(-time.Minute), TimeOut: 100,
				ReqMinRxInt: 100, MyMulti: 3, Notify: n, Fin: make(chan bool), ops: make(chan struct{}, 1),
			}
			raw := &WireRaw{State: BFDUp, Multi: 3, Disc: highMasterRank, DesMinTxInt: 100}
			if tc.timeoutFirst {
				b.checkSessTimeoutAt(now)
			}
			for range 32 {
				b.RunSessionSM(raw)
			}
			b.checkSessTimeoutAt(now)
			if got := strings.Join(n.roles, ","); got != tc.want {
				t.Fatalf("role transitions %q, want %q", got, tc.want)
			}
		})
	}
}

func TestElectionLoneStartUsesOpenGate(t *testing.T) {
	now := time.Now()
	gate := make(chan struct{})
	n := &electionRecorder{}
	b := &bfdSession{
		pairElection: true, backupRank: lowBackupRank, MyDisc: lowBackupRank,
		State: BFDDown, StartGate: gate, openAt: now,
		startExpired: func() bool { return true }, MyMulti: 3, ReqMinRxInt: 100000,
		Notify: n, Fin: make(chan bool), ops: make(chan struct{}, 1),
	}
	b.checkSessTimeoutAt(now)
	if len(n.roles) != 0 {
		t.Fatalf("elected before gate: %v", n.roles)
	}
	close(gate)
	b.checkSessTimeoutAt(now)
	if got := strings.Join(n.roles, ","); got != "MASTER" {
		t.Fatalf("lone start role: %q", got)
	}
}

type blockingElectionRecorder struct {
	entered chan struct{}
	release chan struct{}
	roles   []string
}

func (n *blockingElectionRecorder) BFDSessionNotify(_, _, role string) {
	n.roles = append(n.roles, role)
	if len(n.roles) == 1 {
		close(n.entered)
		<-n.release
	}
}

func TestElectionSerializesReceiveBehindTimeoutNotification(t *testing.T) {
	now := time.Now()
	n := &blockingElectionRecorder{entered: make(chan struct{}), release: make(chan struct{})}
	b := &bfdSession{
		pairElection: true, backupRank: lowBackupRank, MyDisc: lowBackupRank,
		RemDisc: highMasterRank, State: BFDUp, CiState: common.CIBackupStateString,
		LastRxTS: now.Add(-time.Second), openAt: now.Add(-time.Minute), TimeOut: 100,
		ReqMinRxInt: 100, MyMulti: 3, Notify: n, Fin: make(chan bool), ops: make(chan struct{}, 1),
	}
	timeoutDone, receiveDone := make(chan struct{}), make(chan struct{})
	go func() { b.checkSessTimeoutAt(now); close(timeoutDone) }()
	<-n.entered
	go func() {
		b.RunSessionSM(&WireRaw{State: BFDUp, Multi: 3, Disc: highMasterRank, DesMinTxInt: 100})
		close(receiveDone)
	}()
	close(n.release)
	<-timeoutDone
	<-receiveDone
	if got := strings.Join(n.roles, ","); got != "MASTER,BACKUP" {
		t.Fatalf("role transitions %q, want MASTER,BACKUP", got)
	}
}

func TestElectionDoesNotPromoteOnXSyncFailureWithRecentBFD(t *testing.T) {
	now := time.Now()
	n := &electionRecorder{}
	b := &bfdSession{
		pairElection: true, backupRank: lowBackupRank, MyDisc: lowBackupRank,
		State: BFDDown, openAt: now, LastRxTS: now.Add(-50 * time.Millisecond),
		startExpired: func() bool { return true }, MyMulti: 3, ReqMinRxInt: 100000,
		Notify: n, Fin: make(chan bool), ops: make(chan struct{}, 1),
	}
	b.checkSessTimeoutAt(now)
	if len(n.roles) != 0 {
		t.Fatalf("XSync-only failure changed the role: %v", n.roles)
	}
}
