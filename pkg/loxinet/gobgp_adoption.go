package loxinet

import (
	"context"
	"errors"
	tk "github.com/loxilb-io/loxilib"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/proto"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

func (na *NetAPIStruct) NetBGPAdoptionWarnings() (map[string][]string, error) {
	if mh.bgp == nil {
		return nil, nil
	}
	return mh.bgp.adoptionWarnings()
}
func (h *GoBgpH) adoptionWarnings() (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(bgpOperationContext(), 5*time.Second)
	defer cancel()
	stream, err := h.client.ListPeer(ctx, &api.ListPeerRequest{})
	if err != nil {
		return nil, errors.New("BGP adoption inspection unavailable")
	}
	warnings := make(map[string][]string)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			return warnings, nil
		}
		if err != nil {
			return nil, errors.New("BGP adoption inspection incomplete")
		}
		p := r.GetPeer()
		peer := net.ParseIP(p.GetConf().GetNeighborAddress())
		if peer == nil {
			continue
		} // Only validated IP identifiers enter warnings.
		if names := bgpDroppedPeerAttributes(p); len(names) > 0 {
			warnings[peer.String()] = names
		}
	}
}

// GoBGP v3.35.0 config/oc/default.go defines connect/hold/idle timers as
// 120/90/30 seconds; default keepalive is hold/3. Do not import its file
// watcher/config-loader dependencies just to use these defaults.
// Compare configuration, never negotiated/session state, with the defaults
// produced by BGPNeighMod + GoBGP. Return names only, including auth presence.
func bgpDroppedPeerAttributes(p *api.Peer) []string {
	names := map[string]bool{}
	add := func(name string, changed bool) {
		if changed {
			names[name] = true
		}
	}
	c := p.GetConf()
	add("auth_password", c.GetAuthPassword() != "")
	timers := p.GetTimers().GetConfig()
	if timers != nil {
		add("timers.connect_retry", timers.ConnectRetry != 120)
		add("timers.hold_time", timers.HoldTime != 90)
		add("timers.keepalive_interval", timers.KeepaliveInterval != 90/3)
		add("timers.idle_hold_time_after_reset", timers.IdleHoldTimeAfterReset != 30)
		add("timers.minimum_advertisement_interval", timers.MinimumAdvertisementInterval != 0)
	}
	gr := p.GetGracefulRestart()
	add("graceful_restart", gr.GetEnabled() || gr.GetHelperOnly() || gr.GetLonglivedEnabled() || gr.GetNotificationEnabled() || gr.GetRestartTime() != 0 || gr.GetDeferralTime() != 0 || gr.GetStaleRoutesTime() != 0)
	afi := api.Family_AFI_IP
	if net.ParseIP(c.GetNeighborAddress()).To4() == nil {
		afi = api.Family_AFI_IP6
	}
	families := p.GetAfiSafis()
	add("afi_safis", len(families) > 1)
	for _, f := range families {
		cfg := f.GetConfig()
		family := cfg.GetFamily()
		add("afi_safis", family.GetAfi() != afi || family.GetSafi() != api.Family_SAFI_UNICAST || !cfg.GetEnabled())
		add("afi_safis.graceful_restart", f.GetMpGracefulRestart().GetConfig().GetEnabled() || proto.Size(f.GetLongLivedGracefulRestart().GetConfig()) != 0)
		add("afi_safis.add_paths", proto.Size(f.GetAddPaths().GetConfig()) != 0)
		add("afi_safis.prefix_limits", proto.Size(f.GetPrefixLimits()) != 0)
		add("afi_safis.route_selection", proto.Size(f.GetRouteSelectionOptions().GetConfig()) != 0)
		add("afi_safis.multiple_paths", proto.Size(f.GetUseMultiplePaths().GetConfig()) != 0)
		policy := f.GetApplyPolicy()
		add("afi_safis.apply_policy", len(policy.GetImportPolicy().GetPolicies()) > 0 || len(policy.GetExportPolicy().GetPolicies()) > 0 || policy.GetImportPolicy().GetDefaultAction() == api.RouteAction_REJECT || policy.GetExportPolicy().GetDefaultAction() == api.RouteAction_REJECT)
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (na *NetAPIStruct) NetBGPAdoptionWarn(peer string, attributes []string) {
	if peer == "" {
		tk.LogIt(tk.LogWarning, "BGP adoption attribute inspection incomplete; dropped_attributes=unknown\n")
		return
	}
	tk.LogIt(tk.LogWarning, "BGP adoption peer=%s dropped_attributes=%s\n", peer, strings.Join(attributes, ","))
}
