// Package metrics exposes the small set of in-process counters/gauges that
// the sequencer surfaces over /metrics in Prometheus text exposition format
// (https://prometheus.io/docs/instrumenting/exposition_formats/).
//
// We deliberately avoid pulling in the full prometheus/client_golang
// dependency tree: the sequencer's metric surface is tiny (under a dozen
// numbers), the format is trivially generated from atomic counters, and
// keeping the dep graph minimal matters for a service whose binary is
// shipped on a distroless image.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync/atomic"
)

// Counter is a monotonically-increasing 64-bit counter. Safe for concurrent
// use; the zero value is ready to use.
type Counter struct {
	v atomic.Uint64
}

// Inc bumps the counter by 1.
func (c *Counter) Inc() { c.v.Add(1) }

// Add bumps the counter by n.
func (c *Counter) Add(n uint64) { c.v.Add(n) }

// Value returns the current counter value. Reads are atomic.
func (c *Counter) Value() uint64 { return c.v.Load() }

// Gauge is a 64-bit value that can go up or down. Safe for concurrent use.
type Gauge struct {
	v atomic.Int64
}

// Set replaces the gauge's value.
func (g *Gauge) Set(n int64) { g.v.Store(n) }

// Add adjusts the gauge by delta (which may be negative).
func (g *Gauge) Add(delta int64) { g.v.Add(delta) }

// Value returns the current gauge value.
func (g *Gauge) Value() int64 { return g.v.Load() }

// Registry holds the H-2 two-phase-commit counters defined by the spec
// plus a gauge for the live size of the prepared-transaction LRU.
//
// All metric names are stable and form part of the operator-facing
// contract: dashboards and alerts key off them. Do not rename without
// adding an alias.
type Registry struct {
	// PreparedPending is the number of two-phase-commit transactions
	// currently in flight from the Go sequencer's point of view (issued
	// PrepareUpdate, not yet committed/aborted/failed). Maintained as a
	// gauge because it can go up and down. Mirrors the Rust LRU's `len()`
	// modulo any in-flight Commit/Abort RPCs.
	PreparedPending Gauge

	// CommitsAfterDBSuccess increments each time the Go sequencer
	// successfully calls CommitPreparedUpdate after the matching Postgres
	// COMMIT returned OK. This is the "happy path" counter for H-2.
	CommitsAfterDBSuccess Counter

	// AbortsAfterDBFailure increments each time the Go sequencer calls
	// AbortPreparedUpdate because the Postgres COMMIT (or any pre-commit
	// step after PrepareUpdate succeeded) failed. A non-zero rate here is
	// the operator-visible signal that the two-phase rollback is doing
	// its job.
	AbortsAfterDBFailure Counter

	// labels is an optional set of constant label key/values rendered on
	// every metric line. Empty by default.
	labels map[string]string
}

// New returns a Registry with all counters/gauges zero-initialised.
func New() *Registry { return &Registry{} }

// WithConstLabels returns the registry with constant labels set on every
// metric. Returns the same registry receiver, so usage is fluent.
func (r *Registry) WithConstLabels(labels map[string]string) *Registry {
	if len(labels) == 0 {
		r.labels = nil
		return r
	}
	cp := make(map[string]string, len(labels))
	for k, v := range labels {
		cp[k] = v
	}
	r.labels = cp
	return r
}

// Handler returns an http.Handler that serves the registry's metrics in
// Prometheus text exposition format. The handler is concurrency-safe.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.WriteTo(w)
	})
}

// WriteTo writes the current metrics in Prometheus text format to w. Used
// directly by the HTTP handler and by tests that need to inspect the
// rendered output without spinning up a server.
func (r *Registry) WriteTo(w io.Writer) {
	type metric struct {
		name string
		help string
		typ  string
		val  float64
	}
	mets := []metric{
		{
			name: "olympus_sequencer_prepared_pending",
			help: "Number of two-phase-commit transactions in flight (PrepareUpdate issued, not yet committed/aborted) — H-2.",
			typ:  "gauge",
			val:  float64(r.PreparedPending.Value()),
		},
		{
			name: "olympus_sequencer_commits_after_db_success_total",
			help: "Total number of CommitPreparedUpdate RPCs the Go sequencer issued after the matching Postgres COMMIT succeeded (H-2 happy path).",
			typ:  "counter",
			val:  float64(r.CommitsAfterDBSuccess.Value()),
		},
		{
			name: "olympus_sequencer_aborts_after_db_failure_total",
			help: "Total number of AbortPreparedUpdate RPCs the Go sequencer issued because a Postgres COMMIT (or other post-prepare step) failed (H-2 rollback path).",
			typ:  "counter",
			val:  float64(r.AbortsAfterDBFailure.Value()),
		},
	}
	for _, m := range mets {
		fmt.Fprintf(w, "# HELP %s %s\n", m.name, m.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", m.name, m.typ)
		fmt.Fprintf(w, "%s%s %s\n", m.name, r.renderLabels(), formatFloat(m.val))
	}
}

// renderLabels returns the constant-label suffix (`{k="v",...}`) or "" when
// no labels are set. Sorted by key for deterministic test output.
func (r *Registry) renderLabels() string {
	if len(r.labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(r.labels))
	for k := range r.labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := "{"
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%s=%q", k, r.labels[k])
	}
	out += "}"
	return out
}

// formatFloat formats v with the smallest integer representation when
// possible (matching Prometheus convention for whole-valued counters/gauges).
func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
