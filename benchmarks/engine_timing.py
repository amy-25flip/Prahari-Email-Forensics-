"""Benchmark script to measure local email analysis latency across 100 runs.
Engine-only timing. Generates benchmarks/local_analysis_timing.json with full percentile distributions.
"""
import json
import statistics
import sys
import time
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / 'backend'
sys.path.insert(0, str(backend_dir))

import engine
import local_model
import reputation
from samples import SAMPLES


def run_benchmark(iterations=100):
    print(f"Initializing local analysis engine (loading model & reputation cache)...")
    reputation.load()
    local_model.load()
    
    # Warmup runs
    for sample in SAMPLES:
        engine.analyze(sample['raw'].encode('utf-8'), live=False)
    
    sample_count = len(SAMPLES)
    timings_ms = []
    per_sample_timings = {s['id']: [] for s in SAMPLES}

    print(f"Executing {iterations} local analysis benchmark runs across {sample_count} fixture archetypes...")
    for i in range(iterations):
        sample = SAMPLES[i % sample_count]
        raw_bytes = sample['raw'].encode('utf-8')
        
        t0 = time.perf_counter()
        result = engine.analyze(raw_bytes, live=False)
        t1 = time.perf_counter()
        
        elapsed_ms = (t1 - t0) * 1000.0
        timings_ms.append(elapsed_ms)
        per_sample_timings[sample['id']].append(elapsed_ms)

    sorted_timings = sorted(timings_ms)
    n = len(sorted_timings)
    
    p50 = statistics.median(sorted_timings)
    p90 = sorted_timings[int(0.90 * n)]
    p95 = sorted_timings[int(0.95 * n)]
    p99 = sorted_timings[int(0.99 * n)]
    mean = statistics.mean(sorted_timings)
    stddev = statistics.stdev(sorted_timings) if n > 1 else 0.0
    min_ms = min(sorted_timings)
    max_ms = max(sorted_timings)

    report = {
        "benchmark": "Local-Only Pipeline Analysis Latency",
        "description": "Server-side execution time of engine.analyze(raw, live=False) including header parsing, BERT inference, prompt injection scan, URL analysis, QR decode, and attribution scoring.",
        "environment": {
            "iterations": iterations,
            "sample_fixtures": [s['id'] for s in SAMPLES],
            "live_enrichment": False,
            "ml_status": local_model.status,
            "model_id": local_model.MODEL_ID
        },
        "summary_ms": {
            "min": round(min_ms, 2),
            "median_p50": round(p50, 2),
            "mean": round(mean, 2),
            "p90": round(p90, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "max": round(max_ms, 2),
            "stddev": round(stddev, 2)
        },
        "per_sample_median_ms": {
            k: round(statistics.median(v), 2) for k, v in per_sample_timings.items()
        },
        "raw_timings_ms": [round(t, 2) for t in timings_ms]
    }

    out_dir = Path(__file__).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / 'local_analysis_timing.json'
    out_file.write_text(json.dumps(report, indent=2), encoding='utf-8')

    print(f"\n[+] Benchmark complete!")
    print(f"    Total Iterations : {iterations}")
    print(f"    Min Latency      : {min_ms:.2f} ms")
    print(f"    Median (p50)     : {p50:.2f} ms (Slide 5 Claim: 'Under 60 ms')")
    print(f"    Mean Latency     : {mean:.2f} ms")
    print(f"    95th Percentile  : {p95:.2f} ms")
    print(f"    Saved report to  : {out_file.relative_to(Path(__file__).resolve().parent.parent)}")


if __name__ == '__main__':
    run_benchmark(100)
