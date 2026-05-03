package metrics

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestRegistry_RendersPrometheusFormat(t *testing.T) {
	r := New()
	r.PreparedPending.Set(7)
	r.CommitsAfterDBSuccess.Add(42)
	r.AbortsAfterDBFailure.Inc()

	var buf bytes.Buffer
	r.Render(&buf)
	body := buf.String()

	for _, want := range []string{
		"# HELP olympus_sequencer_prepared_pending",
		"# TYPE olympus_sequencer_prepared_pending gauge",
		"olympus_sequencer_prepared_pending 7",
		"# TYPE olympus_sequencer_commits_after_db_success_total counter",
		"olympus_sequencer_commits_after_db_success_total 42",
		"# TYPE olympus_sequencer_aborts_after_db_failure_total counter",
		"olympus_sequencer_aborts_after_db_failure_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestRegistry_ConstLabels(t *testing.T) {
	r := New().WithConstLabels(map[string]string{
		"service":  "sequencer",
		"instance": "test-1",
	})
	r.PreparedPending.Set(3)

	var buf bytes.Buffer
	r.Render(&buf)
	body := buf.String()

	// Labels are sorted by key for deterministic output.
	if !strings.Contains(body, `olympus_sequencer_prepared_pending{instance="test-1",service="sequencer"} 3`) {
		t.Errorf("labels not rendered correctly:\n%s", body)
	}

	// Empty labels collapses to no suffix.
	r2 := New().WithConstLabels(nil)
	r2.PreparedPending.Set(0)
	var buf2 bytes.Buffer
	r2.Render(&buf2)
	if strings.Contains(buf2.String(), "{") {
		t.Errorf("empty labels should not render braces:\n%s", buf2.String())
	}
}

func TestCounter_ConcurrentInc(t *testing.T) {
	var c Counter
	var wg sync.WaitGroup
	const N = 1000
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Inc()
		}()
	}
	wg.Wait()
	if c.Value() != N {
		t.Fatalf("counter race: want %d, got %d", N, c.Value())
	}
}

func TestGauge_AddAndSet(t *testing.T) {
	var g Gauge
	g.Set(10)
	g.Add(-3)
	g.Add(2)
	if g.Value() != 9 {
		t.Fatalf("gauge: want 9, got %d", g.Value())
	}
}

func TestHandler_ContentType(t *testing.T) {
	r := New()
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, req)

	got := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type: want text/plain..., got %q", got)
	}
}
