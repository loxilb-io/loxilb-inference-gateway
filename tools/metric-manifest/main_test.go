package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFixture lays out a one-package tree and returns its root.
func writeFixture(t *testing.T, src string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "api", "prometheus")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func collect(t *testing.T, src string) map[string]Def {
	t.Helper()
	defs, err := collectDefs(writeFixture(t, src))
	if err != nil {
		t.Fatalf("collectDefs: %v", err)
	}
	out := map[string]Def{}
	for _, d := range defs {
		out[d.Name] = d
	}
	return out
}

// The ordinary inline case, which everything else must not disturb.
func TestInlineConstructorStillResolves(t *testing.T) {
	got := collect(t, `package prometheus

const MetricFoo = "loxilb_foo_total"

var foo = promauto.NewCounterVec(
	prometheus.CounterOpts{Name: MetricFoo, Help: "h"},
	[]string{"service"},
)
`)
	d, ok := got["loxilb_foo_total"]
	if !ok {
		t.Fatalf("inline family not found, got %v", keys(got))
	}
	if d.Type != "counter" || len(d.Labels) != 1 || d.Labels[0] != "service" {
		t.Errorf("wrong shape: %+v", d)
	}
	if d.Unresolved {
		t.Error("inline family should not be unresolved")
	}
}

// A helper that registers on its caller's behalf: the names live at the call
// sites, and reading only the constructor site would report one unresolved
// definition and miss both families.
func TestHelperParameterNamesResolveAtCallSites(t *testing.T) {
	got := collect(t, `package prometheus

const (
	LegacyMetricA = "legacy_a"
	MetricA       = "loxilb_a_total"
	MetricB       = "loxilb_b_total"
)

type dual struct{ legacy, canonical prometheus.Counter }

func newDual(legacyName, canonicalName, help string) *dual {
	d := &dual{}
	if canonicalName == "" {
		d.legacy = promauto.NewCounter(prometheus.CounterOpts{Name: legacyName, Help: help})
		return d
	}
	d.legacy = promauto.NewCounter(prometheus.CounterOpts{Name: legacyName, Help: help})
	d.canonical = promauto.NewCounter(prometheus.CounterOpts{Name: canonicalName, Help: help})
	return d
}

var (
	a = newDual(LegacyMetricA, MetricA, "h")
	b = newDual(MetricB, "", "h")
)
`)
	for _, want := range []string{"legacy_a", "loxilb_a_total", "loxilb_b_total"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %q from a helper call site, got %v", want, keys(got))
		}
	}
	// The second call passes "" for the canonical name, so that half registers
	// nothing. An empty-named family must not be invented for it.
	if _, bad := got[""]; bad {
		t.Error("an empty canonical name produced a family")
	}
	if len(got) != 3 {
		t.Errorf("expected exactly 3 families, got %d: %v", len(got), keys(got))
	}
	for n, d := range got {
		if d.Unresolved {
			t.Errorf("%s still unresolved after expansion", n)
		}
	}
}

// Labels are parameterised the same way and must ride along, or a vector
// family would compare as label-less against upstream and read as divergent.
func TestHelperParameterLabelsResolve(t *testing.T) {
	got := collect(t, `package prometheus

const MetricC = "loxilb_c_total"

func newVec(name string, labels []string) *prometheus.CounterVec {
	return promauto.NewCounterVec(prometheus.CounterOpts{Name: name}, labels)
}

var c = newVec(MetricC, []string{"service", "dip"})
`)
	d, ok := got["loxilb_c_total"]
	if !ok {
		t.Fatalf("family not found: %v", keys(got))
	}
	if len(d.Labels) != 2 {
		t.Errorf("labels did not survive the call site: %+v", d.Labels)
	}
}

// The other indirection: the name arrives through a field on the receiver.
func TestReceiverFieldNamesResolveAtLiterals(t *testing.T) {
	got := collect(t, `package prometheus

const MetricD = "loxilb_d_percent"

type lazyGauge struct {
	name string
	help string
	g    prometheus.Gauge
}

func (l *lazyGauge) Set(v float64) {
	l.g = promauto.With(reg).NewGauge(prometheus.GaugeOpts{Name: l.name, Help: l.help})
	l.g.Set(v)
}

var d = &lazyGauge{name: MetricD, help: "h"}
`)
	got1, ok := got["loxilb_d_percent"]
	if !ok {
		t.Fatalf("receiver-field family not found: %v", keys(got))
	}
	if got1.Type != "gauge" || got1.Unresolved {
		t.Errorf("wrong shape: %+v", got1)
	}
	// promauto.With(reg).NewGauge is still promauto registration.
	if got1.Mechanism != "promauto" {
		t.Errorf("mechanism = %q, want promauto", got1.Mechanism)
	}
}

// The documented limit. Expansion is one hop; a helper calling a helper is not
// followed. What matters is that it stays UNRESOLVED rather than silently
// disappearing -- the manifest generator and the parity generator both refuse
// to ship an unresolved definition, and that refusal is the safety net.
func TestTwoHopWrapperStaysUnresolvedRatherThanVanishing(t *testing.T) {
	defs, err := collectDefs(writeFixture(t, `package prometheus

const MetricE = "loxilb_e_total"

func inner(name string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{Name: name})
}

func outer(name string) prometheus.Counter { return inner(name) }

var e = outer(MetricE)
`))
	if err != nil {
		t.Fatal(err)
	}
	var unresolved int
	for _, d := range defs {
		if d.Unresolved {
			unresolved++
		}
		if d.Name == "loxilb_e_total" {
			t.Error("two-hop indirection resolved; if that is now intended, " +
				"update this test and the comment on expandWrapperDefs")
		}
	}
	if unresolved == 0 {
		t.Fatal("a two-hop registration vanished silently instead of being " +
			"reported unresolved -- the generators would ship a hole")
	}
}

func keys(m map[string]Def) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A helper whose call sites are in another package must not take its family
// down with it. Expansion is per-package, so an uncalled-here template is
// reported unresolved rather than dropped -- the generators then refuse to
// ship, instead of silently reporting the family absent upstream.
func TestUncalledHelperIsReportedNotDropped(t *testing.T) {
	defs, err := collectDefs(writeFixture(t, `package prometheus

func NewNamed(name string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{Name: name})
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) == 0 {
		t.Fatal("a helper with no call site in this package vanished; a caller " +
			"in another package would leave the family missing and unreported")
	}
	if !defs[0].Unresolved {
		t.Errorf("expected the template to be reported unresolved, got %+v", defs[0])
	}
}

// A helper's optional second name is often "" at EVERY call site -- upstream's
// legacy-only gauges are declared exactly this way. That template emits nothing
// and is nonetheless fully understood, so it must not be reported unresolved.
// The distinction is whether a call site was evaluated, not whether a row came
// out of it.
func TestOptionalNameEmptyAtEveryCallSiteIsNotAPhantom(t *testing.T) {
	defs, err := collectDefs(writeFixture(t, `package prometheus

const LegacyOnly = "legacy_only"

type dual struct{ legacy, canonical prometheus.Gauge }

func newDual(legacyName, canonicalName, help string) *dual {
	d := &dual{}
	if canonicalName == "" {
		d.legacy = promauto.NewGauge(prometheus.GaugeOpts{Name: legacyName, Help: help})
		return d
	}
	d.legacy = promauto.NewGauge(prometheus.GaugeOpts{Name: legacyName, Help: help})
	d.canonical = promauto.NewGauge(prometheus.GaugeOpts{Name: canonicalName, Help: help})
	return d
}

var only = newDual(LegacyOnly, "", "h")
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range defs {
		if d.Unresolved {
			t.Errorf("a canonical registration opted out at every call site was "+
				"reported unresolved: %+v", d)
		}
	}
	if len(defs) != 1 || defs[0].Name != "legacy_only" {
		t.Errorf("expected exactly the legacy family, got %+v", defs)
	}
}
