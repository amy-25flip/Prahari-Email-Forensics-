"""Runs the five-class decision table over the synthetic fixtures and prints per-class recall/precision."""
import collections
import engine
import five_class_fixtures as fx

CLASSES = ['legitimate', 'suspicious', 'impersonated', 'phishing', 'fraud_related']


def run():
    import local_model
    local_model.load()
    conf, misses = collections.Counter(), []
    for cls, *mail in fx.CASES:
        got = engine.analyze(fx.build(*mail))
        primary = got['classification']['primary']
        conf[(cls, primary)] += 1
        if cls != primary: misses.append((cls, primary, mail[1], mail[2], got['score'], [f['title'] for f in got['findings']]))
    return conf, misses


def per_class(conf):
    out = {}
    for c in CLASSES:
        tp = conf[(c, c)]
        total = sum(v for (a, _), v in conf.items() if a == c)
        pred = sum(v for (_, b), v in conf.items() if b == c)
        out[c] = {'recall': tp / total if total else 0, 'precision': tp / pred if pred else 0, 'n': total}
    out['accuracy'] = sum(v for (a, b), v in conf.items() if a == b) / sum(conf.values())
    return out


if __name__ == '__main__':
    conf, misses = run()
    for m in misses: print('MISS', m)
    for k, v in per_class(conf).items(): print(k, v)
