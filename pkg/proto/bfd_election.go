// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package bfd

import "github.com/loxilb-io/loxilb/common"

// electionState describes what the BFD session knows about peer availability.
// Loss and gate expiry are separate from ordinary BFD Down during negotiation.
type electionState uint8

const (
	electionWaiting electionState = iota
	electionUp
	electionPeerLost
	electionStartExpired
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
