// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package bfd

import (
	"errors"

	"github.com/loxilb-io/loxilb/common"
)

// PairState controls the local two-node election while the gateway changes
// VIP ownership. Holding freezes the elected rank until address withdrawal
// is attempted. Withdrawn publishes rank 1 on the existing BFD session.
type PairState uint32

const (
	PairEligible PairState = iota
	PairHolding
	PairWithdrawn
)

func (b *bfdSession) syncPairStateLocked() PairState {
	if !b.pairElection || b.pairState == nil {
		return PairEligible
	}
	state := b.pairState()
	if state == PairWithdrawn {
		b.withdrawn = true
		b.MyDisc = withdrawnRank
	} else if state == PairEligible && b.withdrawn {
		b.withdrawn = false
		b.rejoining = true
		b.peerLost = false
		b.MyDisc = b.backupRank
		b.CiState = common.CIBackupStateString
	}
	return state
}

// AnnouncePair sends the new rank immediately on a running paired session.
// If the startup gate is still closed, the ticker will send it when it opens.
func (bs *Struct) AnnouncePair(peer string) error {
	bs.BFDMtx.RLock()
	sess := bs.BFDSessMap[peer]
	bs.BFDMtx.RUnlock()
	if sess == nil || !sess.pairElection {
		return errors.New("paired BFD session unavailable")
	}
	if !sess.beginWork() {
		return errors.New("paired BFD session is stopping")
	}
	defer sess.work.Done()
	if !sess.active() {
		return nil
	}
	return sess.sendBFDPacket()
}

// electionState describes what the BFD session knows about peer availability.
// Loss and gate expiry are separate from ordinary BFD Down during negotiation.
type electionState uint8

const (
	electionWaiting electionState = iota
	electionUp
	electionPeerLost
	electionStartExpired
	electionStartWithoutBFD
)

const (
	withdrawnRank  uint32 = 1
	lowBackupRank  uint32 = 2
	highBackupRank uint32 = 3
	lowMasterRank  uint32 = 4
	highMasterRank uint32 = 5
)

type electionDecision struct {
	role   string
	reason string
}

func elect(local, peer uint32, state electionState, eligible, shuttingDown bool) electionDecision {
	switch {
	case shuttingDown:
		return electionDecision{common.CIBackupStateString, "shutdown_withdrawal"}
	case !eligible || local == withdrawnRank:
		return electionDecision{common.CIBackupStateString, "ineligible"}
	case local < lowBackupRank || local > highMasterRank:
		return electionDecision{common.CIBackupStateString, "invalid_local_rank"}
	}

	switch state {
	case electionStartWithoutBFD:
		return electionDecision{common.CIMasterStateString, "active_without_bfd"}
	case electionStartExpired:
		return electionDecision{common.CIMasterStateString, "active_alone"}
	case electionPeerLost:
		return electionDecision{common.CIMasterStateString, "peer_timeout"}
	case electionUp:
		switch {
		case peer > highMasterRank:
			return electionDecision{common.CIBackupStateString, "legacy_peer"}
		case peer == withdrawnRank:
			return electionDecision{common.CIMasterStateString, "peer_withdrawn"}
		case peer == local:
			return electionDecision{common.CIBackupStateString, "equal_rank"}
		case peer != 0 && local > peer:
			return electionDecision{common.CIMasterStateString, "preferred_rank"}
		case peer != 0:
			return electionDecision{common.CIBackupStateString, "peer_preferred"}
		}
	}
	if local >= lowMasterRank {
		return electionDecision{common.CIMasterStateString, "waiting_for_peer"}
	}
	return electionDecision{common.CIBackupStateString, "waiting_for_peer"}
}
