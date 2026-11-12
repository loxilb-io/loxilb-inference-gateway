package snapshot

import (
	"sort"
)

// Warnings contain peer identifiers and attribute NAMES only. Never retain a
// raw peer or authentication value in the snapshot layer, metric or log.
type bgpAdoptionCheck struct {
	hooks      Hooks
	attributes map[string][]string
	err        error
	checked    bool
}

func checkBGPAdoption(h Hooks) bgpAdoptionCheck {
	if BGPIntentAdopted() {
		return bgpAdoptionCheck{}
	}
	// Only a static-file adoption can discard YAML-only configuration. An
	// API-only first global POST may still have an unstarted speaker; avoid
	// its unnecessary ListPeer inspection, WARN and gauge write entirely.
	static, ok := h.(interface{ NetBGPStaticConfigPresent() bool })
	if !ok || !static.NetBGPStaticConfigPresent() {
		return bgpAdoptionCheck{}
	}
	hook, ok := h.(interface {
		NetBGPAdoptionWarnings() (map[string][]string, error)
	})
	if !ok {
		return bgpAdoptionCheck{}
	}
	attributes, err := hook.NetBGPAdoptionWarnings()
	return bgpAdoptionCheck{hooks: h, attributes: attributes, err: err, checked: true}
}
func (c bgpAdoptionCheck) record() {
	if !c.checked {
		return
	}
	if c.err != nil {
		// The hook returns a fixed safe error; raw gRPC errors/peer payloads are
		// deliberately omitted. An incomplete inspection must not block adoption.
		bgpAdoptionDroppedAttributes.Set(-1)
		c.warn("", nil)
		return
	}
	count := 0
	peers := make([]string, 0, len(c.attributes))
	for peer := range c.attributes {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	for _, peer := range peers {
		names := c.attributes[peer]
		sort.Strings(names)
		count += len(names)
		if len(names) > 0 {
			c.warn(peer, names)
		}
	}
	bgpAdoptionDroppedAttributes.Set(float64(count))
}

func (c bgpAdoptionCheck) warn(peer string, attributes []string) {
	if logger, ok := c.hooks.(interface{ NetBGPAdoptionWarn(string, []string) }); ok {
		logger.NetBGPAdoptionWarn(peer, attributes)
	}
}
