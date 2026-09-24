"""Renders the attribution validation matrix (scenarios -> expected vs actual band) as markdown.
Run from repo root: .venv/Scripts/python.exe benchmarks/attribution_matrix.py
Writes benchmarks/attribution_validation_matrix.md"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'backend'))
import attribution
from attribution_scenarios import ORDERINGS, SCENARIOS

rows, mismatches = [], 0
scores = {}
for sid in sorted(SCENARIOS):
    description, report, expected = SCENARIOS[sid]
    result = attribution.assess(report)
    scores[sid] = result['confidence_score']
    ok = result['band'] == expected
    mismatches += not ok
    applied = ', '.join(f"{'+' if f['direction'] == '+' else '-'}{f['factor']}" for f in result['factors'] if f['applied']) or '(none)'
    rows.append(f"| {sid} | {description} | {expected} | {result['band']} | {result['confidence_score']} | {'yes' if ok else '**NO**'} | {applied} |")

order_rows = []
for strong, weak in ORDERINGS:
    order_rows.append(f"| {strong} ({scores[strong]}) > {weak} ({scores[weak]}) | {'yes' if scores[strong] > scores[weak] else '**NO**'} |")

md = f"""# Attribution confidence - validation matrix

Each scenario is a hand-built evidence set with the band an analyst would expect, decided from
the evidence before running the engine. This checks that the hand-set weights produce the
*intended ordering and banding*. It does not calibrate the score into a probability - the
engine's own policy string says so.

Bands: low < 35, moderate 35-69, high >= 70. Weights sum to 110 and the score is capped at 100 by design.

**Result: {len(SCENARIOS) - mismatches}/{len(SCENARIOS)} scenarios in the expected band; {sum(scores[s] > scores[w] for s, w in ORDERINGS)}/{len(ORDERINGS)} ordering checks hold.**

| ID | Scenario | Expected | Actual | Score | Match | Factors applied |
|---|---|---|---|---|---|---|
{chr(10).join(rows)}

## Ordering checks (stronger evidence must score strictly higher)

| Check | Holds |
|---|---|
{chr(10).join(order_rows)}

Known boundary: S14 scores exactly 35, the low/moderate cutoff; S17 (same, minus geolocation) falls just below. Reproduced by `backend/test_attribution_matrix.py`.
"""
(ROOT / 'benchmarks' / 'attribution_validation_matrix.md').write_text(md, encoding='utf-8')
print(md.split('**Result:')[1].split('**')[0].strip())
