use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use olympus_matcher::core::CoreMatcher;

fn build_matcher_single() -> CoreMatcher {
    let mut m = CoreMatcher::new();
    // A naive catastrophic pattern for PCRE — DFA handles it in linear time.
    m.add_raw_pattern("redos_probe", r"(a+)+b").unwrap();
    m
}

fn build_matcher_multi() -> CoreMatcher {
    let mut m = CoreMatcher::new();
    m.add_raw_pattern("digits", r"\d+").unwrap();
    m.add_raw_pattern("words", r"[A-Za-z]+").unwrap();
    m.add_raw_pattern("email", r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}")
        .unwrap();
    m.add_raw_pattern("url", r"https?://[^\s]+").unwrap();
    m.add_raw_pattern("hash_hex", r"[0-9a-f]{64}").unwrap();
    m.add_raw_pattern("iso_date", r"\d{4}-\d{2}-\d{2}").unwrap();
    m.add_raw_pattern("redacted", r"\[REDACTED\]").unwrap();
    m.add_raw_pattern(
        "uuid",
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    )
    .unwrap();
    m.add_raw_pattern("ipv4", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        .unwrap();
    m.add_raw_pattern("ssn", r"\d{3}-\d{2}-\d{4}").unwrap();
    m
}

/// Benchmark `match_first` against a 10k-char adversarial input
/// (ReDoS probe — `a` repeated 10k times).
fn bench_match_first_redos(c: &mut Criterion) {
    let matcher = build_matcher_single();
    let input = "a".repeat(10_000);

    c.bench_function("match_first_redos_10k", |b| {
        b.iter(|| {
            let _ = matcher.match_first(black_box(&input));
        })
    });
}

/// Size-scaling benchmark: run the ReDoS probe at 1k, 10k, and 100k input
/// sizes.  Comparing wall-clock numbers across these sizes exposes non-linear
/// scaling — a true DFA will show ~linear growth, while catastrophic
/// backtracking would show exponential blowup.
fn bench_redos_scaling(c: &mut Criterion) {
    let matcher = build_matcher_single();
    let mut group = c.benchmark_group("redos_scaling");
    for &size in &[1_000usize, 10_000, 100_000] {
        let input = "a".repeat(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &input, |b, inp| {
            b.iter(|| {
                let _ = matcher.match_first(black_box(inp));
            });
        });
    }
    group.finish();
}

/// Benchmark `match_all` across 10 patterns on a 1k-char realistic fragment.
fn bench_match_all_realistic(c: &mut Criterion) {
    let matcher = build_matcher_multi();
    let input = concat!(
        "From: alice@example.com\n",
        "Date: 2024-03-15\n",
        "Subject: Re: FOIA request 2024-1234\n",
        "Reference: https://olympus.example.gov/docs/abc123\n",
        "Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
        "SSN: [REDACTED] (192.168.1.42)\n",
        "Content: The requested document contains 42 pages and references ",
        "document.pdf along with supplemental.docx files.\n",
        "UUID: 550e8400-e29b-41d4-a716-446655440000\n",
        "Status: FULFILLED\n",
    );
    // Pad to ~1k chars
    let padded = format!("{:width$}", input, width = 1024);

    c.bench_function("match_all_10_patterns_1k", |b| {
        b.iter(|| {
            let _ = matcher.match_all(black_box(&padded));
        })
    });
}

criterion_group!(
    benches,
    bench_match_first_redos,
    bench_redos_scaling,
    bench_match_all_realistic
);
criterion_main!(benches);
