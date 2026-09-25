"""Independent evaluation on public labelled corpora that were NOT used to train the project's model.

Sources (checked 2026-09-25):
  * Apache SpamAssassin public corpus, 20030228_easy_ham and 20030228_hard_ham (legitimate mail, 2003)
    https://spamassassin.apache.org/old/publiccorpus/
  * Jose Nazario's phishing corpus, phishing-2025 mailbox (phishing, hand-classified, CC-BY-4.0)
    https://www.monkey.org/~jose/phishing/  (attribution required: Jose Nazario)
Usage: python evaluation/run_external_eval.py --download   (fetch into evaluation/data, git-ignored)
       python evaluation/run_external_eval.py [--per-corpus 150]
Writes benchmarks/external_evaluation.json and .md. Fixed random seed; nothing is tuned on these sets.
"""
import argparse
import json
import mailbox
import random
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'evaluation' / 'data'
sys.path.insert(0, str(ROOT / 'backend'))
FILES = {
    'phishing-2025': 'https://www.monkey.org/~jose/phishing/phishing-2025',
    '20030228_easy_ham.tar.bz2': 'https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2',
    '20030228_hard_ham.tar.bz2': 'https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2',
}
MAX_BYTES = 1_000_000


def download():
    DATA.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        target = DATA / name
        if not target.exists():
            urllib.request.urlretrieve(url, target)


def tar_messages(name):
    with tarfile.open(DATA / name, 'r:bz2') as archive:       # members are read in memory, never extracted to disk
        for member in archive:
            if member.isfile() and not member.name.endswith('cmds') and 0 < member.size <= MAX_BYTES:
                data = archive.extractfile(member).read()
                if 0 < len(data) <= MAX_BYTES: yield data


def mbox_messages(name):
    for message in mailbox.mbox(str(DATA / name)):
        data = message.as_bytes()
        if 0 < len(data) <= MAX_BYTES: yield data


CORPORA = {
    'phishing-2025 (Nazario)': ('phishing', lambda: mbox_messages('phishing-2025')),
    'spamassassin easy_ham 2003': ('legitimate', lambda: tar_messages('20030228_easy_ham.tar.bz2')),
    'spamassassin hard_ham 2003': ('legitimate', lambda: tar_messages('20030228_hard_ham.tar.bz2')),
}
RULES = {
    'model_label_phishing': lambda r: str(r['ml'].get('label', '')).lower() == 'phishing',
    'evidence_score_ge_25': lambda r: r['score'] >= 25,
    'evidence_score_ge_45': lambda r: r['score'] >= 45,
    'evidence_score_ge_60_gateway_hold': lambda r: r['score'] >= 60 or r['triage']['priority'] == 'urgent',
    'primary_class_threat': lambda r: r['classification']['primary'] in ('phishing', 'fraud_related', 'impersonated'),
    'primary_or_suspicious': lambda r: r['classification']['primary'] not in ('legitimate', 'undetermined'),
}


def run(per_corpus, seed=20260925):
    import engine
    import local_model
    local_model.load()
    rng = random.Random(seed)
    counts = {name: {rule: 0 for rule in RULES} for name in CORPORA}
    sizes, unavailable = {}, 0
    for name, (label, reader) in CORPORA.items():
        messages = list(reader())
        rng.shuffle(messages)
        sample = messages[:per_corpus]
        sizes[name] = {'label': label, 'available': len(messages), 'evaluated': len(sample)}
        for raw in sample:
            try: result = engine.analyze(raw, source='external-eval')
            except ValueError:
                sizes[name]['evaluated'] -= 1
                continue
            if result['ml'].get('status') != 'ready': unavailable += 1
            for rule, fn in RULES.items():
                counts[name][rule] += int(fn(result))
    return counts, sizes, unavailable


def metrics(counts, sizes):
    out = {}
    for rule in RULES:
        tp = sum(counts[n][rule] for n in counts if sizes[n]['label'] == 'phishing')
        fn = sum(sizes[n]['evaluated'] - counts[n][rule] for n in counts if sizes[n]['label'] == 'phishing')
        fp = sum(counts[n][rule] for n in counts if sizes[n]['label'] == 'legitimate')
        tn = sum(sizes[n]['evaluated'] - counts[n][rule] for n in counts if sizes[n]['label'] == 'legitimate')
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        out[rule] = {'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn, 'precision': round(precision, 4), 'recall': round(recall, 4),
                     'f1': round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0,
                     'false_positive_rate': round(fp / (fp + tn), 4) if fp + tn else 0,
                     'per_corpus_flagged': {n: f"{counts[n][rule]}/{sizes[n]['evaluated']}" for n in counts}}
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--per-corpus', type=int, default=150)
    args = parser.parse_args()
    if args.download: download()
    if not all((DATA / n).exists() for n in FILES): sys.exit('Corpora missing: run with --download first.')
    counts, sizes, unavailable = run(args.per_corpus)
    report = {'seed': 20260925, 'per_corpus_cap': args.per_corpus, 'corpora': sizes, 'model_unavailable_messages': unavailable, 'rules': metrics(counts, sizes),
              'caveats': ['Legitimate mail is 2003-era public mailing-list/personal mail; phishing is one person\'s 2025 inbox, hand-classified. The two classes differ in era, '
                          'header style and source, so class separation may partly reflect that, and absolute numbers do not transfer to a modern mailbox.',
                          'No training-set overlap check was possible: the training corpus is not stored in this repository.',
                          'Sample sizes are small; treat rates as rough. Nothing was tuned on these sets.']}
    (ROOT / 'benchmarks').mkdir(exist_ok=True)
    (ROOT / 'benchmarks' / 'external_evaluation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
