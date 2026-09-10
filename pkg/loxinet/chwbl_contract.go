/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package loxinet

import (
	"errors"
	"fmt"

	cmn "github.com/loxilb-io/loxilb/common"
)

func isCHWBLSelector(sel cmn.EpSelect) bool {
	return sel == cmn.LbSelCHWBL || sel == cmn.LbSelWRRHash
}

func hasCHWBLDeclaration(serv *cmn.LbServiceArg) bool {
	present := serv.CHWBLPrefixHashLevelPresent || serv.CHWBLPrefixHashFlagsPresent ||
		serv.CHWBLMeanLoadFactorPresent || serv.CHWBLReplicationPresent ||
		serv.CHWBLEnableCacheSaltPresent
	if serv.CHWBLPresenceTracked {
		return present
	}
	return present || serv.CHWBLPrefixHashLevel != 0 ||
		serv.CHWBLPrefixHashFlags != 0 || serv.CHWBLMeanLoadFactor != 0 ||
		serv.CHWBLReplication != 0 || serv.CHWBLEnableCacheSalt
}

// resolveCHWBLContract materializes the five effective values before change
// detection and before any rule/data-plane mutation. A replace omission keeps
// the previous effective value; a create omission resolves to the public
// default. Direct in-process callers without presence metadata retain legacy
// compatibility: a non-zero value (or true bool) is treated as explicit.
func resolveCHWBLContract(serv *cmn.LbServiceArg, existing *ruleEnt, eps []ruleLBEp) error {
	if !isCHWBLSelector(serv.Sel) {
		if hasCHWBLDeclaration(serv) {
			return errors.New("CHWBL fields require mode=4 and sel=8 or sel=10")
		}
		return nil
	}
	if cmn.LBMode(serv.Mode) != cmn.LBModeFullProxy {
		return errors.New("CHWBL fields require mode=4 and sel=8 or sel=10")
	}

	preserve := existing != nil && isCHWBLSelector(existing.act.action.(*ruleLBActs).sel)
	levelExplicit := serv.CHWBLPrefixHashLevelPresent ||
		(!serv.CHWBLPresenceTracked && serv.CHWBLPrefixHashLevel != 0)
	flagsExplicit := serv.CHWBLPrefixHashFlagsPresent ||
		(!serv.CHWBLPresenceTracked && serv.CHWBLPrefixHashFlags != 0)
	meanExplicit := serv.CHWBLMeanLoadFactorPresent ||
		(!serv.CHWBLPresenceTracked && serv.CHWBLMeanLoadFactor != 0)
	replicationExplicit := serv.CHWBLReplicationPresent ||
		(!serv.CHWBLPresenceTracked && serv.CHWBLReplication != 0)
	cacheSaltExplicit := serv.CHWBLEnableCacheSaltPresent ||
		(!serv.CHWBLPresenceTracked && serv.CHWBLEnableCacheSalt)

	if !levelExplicit {
		if preserve {
			serv.CHWBLPrefixHashLevel = existing.chwblPrefixHashLevel
		} else {
			serv.CHWBLPrefixHashLevel = cmn.CHWBLPrefixHashLevelDefault
		}
	}
	if !flagsExplicit {
		if preserve {
			serv.CHWBLPrefixHashFlags = existing.chwblPrefixHashFlags
		} else {
			serv.CHWBLPrefixHashFlags = 0
		}
	}
	if !meanExplicit {
		if preserve {
			serv.CHWBLMeanLoadFactor = existing.chwblMeanLoadFactor
		} else {
			serv.CHWBLMeanLoadFactor = cmn.CHWBLMeanLoadFactorDefault
		}
	}
	if !replicationExplicit {
		if preserve {
			serv.CHWBLReplication = existing.chwblReplication
		} else {
			serv.CHWBLReplication = cmn.CHWBLReplicationDefault
		}
	}
	if !cacheSaltExplicit {
		if preserve {
			serv.CHWBLEnableCacheSalt = existing.chwblEnableCacheSalt
		} else {
			serv.CHWBLEnableCacheSalt = false
		}
	}

	if serv.CHWBLPrefixHashLevel < 1 || serv.CHWBLPrefixHashLevel > 3 {
		return errors.New("chwbl_prefix_hash_level must be within 1..3")
	}
	if serv.CHWBLPrefixHashFlags < 0 || serv.CHWBLPrefixHashFlags > 255 {
		return errors.New("chwbl_prefix_hash_flags must be within 0..255")
	}
	levelMask := 0x1f
	if serv.CHWBLPrefixHashLevel >= 2 {
		levelMask |= 0x20
	}
	if serv.CHWBLPrefixHashLevel >= 3 {
		levelMask |= 0xc0
	}
	if serv.CHWBLPrefixHashFlags != 0 && serv.CHWBLPrefixHashFlags&^levelMask != 0 {
		return errors.New("chwbl_prefix_hash_flags enables inputs above chwbl_prefix_hash_level")
	}
	if serv.CHWBLMeanLoadFactor < 100 || serv.CHWBLMeanLoadFactor > 300 {
		return errors.New("chwbl_mean_load_factor must be within 100..300")
	}
	if serv.CHWBLReplication < 1 || serv.CHWBLReplication > 1024 {
		return errors.New("chwbl_replication must be within 1..1024")
	}
	if serv.CHWBLEnableCacheSalt && serv.CHWBLPrefixHashFlags != 0 &&
		serv.CHWBLPrefixHashFlags&0x08 == 0 {
		return errors.New("chwbl_enable_cache_salt requires cache_salt flag bit 3 when flags are explicit")
	}
	if serv.Sel == cmn.LbSelWRRHash {
		positive := 0
		for i := range eps {
			if eps[i].weight > 0 && !eps[i].inActiveEP {
				positive++
			}
		}
		if positive == 0 {
			return errors.New("sel=wrr-hash(10) requires at least one positive-weight endpoint")
		}
		if serv.CHWBLReplication < positive {
			return fmt.Errorf("chwbl_replication must be >= positive-weight endpoint count (%d) for sel=10", positive)
		}
	}
	return nil
}

type chwblRuleSnapshot struct {
	level       int
	flags       int
	mean        int
	replication int
	cacheSalt   bool
}

func snapshotCHWBLRule(r *ruleEnt) chwblRuleSnapshot {
	return chwblRuleSnapshot{
		level: r.chwblPrefixHashLevel, flags: r.chwblPrefixHashFlags,
		mean: r.chwblMeanLoadFactor, replication: r.chwblReplication,
		cacheSalt: r.chwblEnableCacheSalt,
	}
}

func (s chwblRuleSnapshot) restore(r *ruleEnt) {
	r.chwblPrefixHashLevel = s.level
	r.chwblPrefixHashFlags = s.flags
	r.chwblMeanLoadFactor = s.mean
	r.chwblReplication = s.replication
	r.chwblEnableCacheSalt = s.cacheSalt
}
