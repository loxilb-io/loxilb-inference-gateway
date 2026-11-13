package prometheus

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLBConnCountCorrectionsReadsZeroWithoutSource(t *testing.T) {
	lbConnCountCorrectionsSource.Store(nil)
	want := `
# HELP loxilb_lb_conn_count_corrections_total ` + lbConnCountCorrectionsHelp + `
# TYPE loxilb_lb_conn_count_corrections_total counter
loxilb_lb_conn_count_corrections_total 0
`
	if err := testutil.CollectAndCompare(lbConnCountCorrectionsCollector{}, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}

func TestLBConnCountCorrectionsReadsItsSourceAtScrape(t *testing.T) {
	n := uint64(1)
	SetLBConnCountCorrectionsSource(func() uint64 {
		n += 2
		return n
	})
	defer lbConnCountCorrectionsSource.Store(nil)
	want := `
# HELP loxilb_lb_conn_count_corrections_total ` + lbConnCountCorrectionsHelp + `
# TYPE loxilb_lb_conn_count_corrections_total counter
loxilb_lb_conn_count_corrections_total 3
`
	if err := testutil.CollectAndCompare(lbConnCountCorrectionsCollector{}, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}
