"""Local-only inference. Never silently substitute rules for a trained model."""
import json
import logging
import os
import threading
import traceback
from pathlib import Path

logger = logging.getLogger('local_model')

os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

MODEL_ID = os.getenv('MODEL_ID', 'ealvaradob/bert-finetuned-phishing')
# Must match whatever the loaded model was actually trained/fine-tuned at -- a
# train/inference mismatch here silently degrades accuracy without erroring.
MAX_LENGTH = int(os.getenv('MODEL_MAX_LENGTH', '256'))
lock = threading.Lock()
model = tokenizer = None
phishing_index = None
status = 'loading'
detail = 'Loading locally cached model'


def _phishing_label_index(id2label):
    """Find the single label that means "phishing", not merely one
    containing that substring. A common negative-class naming convention --
    id2label={0:'not_phishing', 1:'phishing'} -- means 'not_phishing' also
    contains "phishing" as a substring; naive first-match substring search
    would silently pick the LEGITIMATE class as "phishing", inverting every
    verdict. Raises ValueError on anything ambiguous rather than guessing,
    matching this module's own "never silently substitute" principle."""
    labels = {int(k): str(v).lower().replace('-', '_') for k, v in id2label.items()}
    exact = [i for i, name in labels.items() if name in ('phishing', 'phish')]
    if len(exact) == 1:
        return exact[0]
    negated = ('not_phish', 'non_phish', 'no_phish', 'nonphish')
    candidates = [i for i, name in labels.items() if 'phish' in name and not any(n in name for n in negated)]
    if len(candidates) == 1:
        return candidates[0]
    raise ValueError(f'Could not unambiguously identify the phishing class from label mapping: {id2label}')


def load():
    global model, tokenizer, phishing_index, status, detail
    if os.getenv('DISABLE_ML') == '1':
        status, detail = 'unavailable', 'Model disabled by configuration'
        return
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        torch.set_num_threads(min(4, os.cpu_count() or 1))
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, local_files_only=True, trust_remote_code=False)
        candidate = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, local_files_only=True, low_cpu_mem_usage=True)
        # Resolved once here (not per-classify() call): also means a bad/
        # ambiguous label mapping fails loudly at load time via the except
        # below (status='unavailable') instead of silently guessing wrong,
        # or re-deriving the same fragile lookup on every request.
        resolved_phishing_index = _phishing_label_index(candidate.config.id2label)
        model = candidate.eval()
        phishing_index = resolved_phishing_index
        status = 'ready'
        if MODEL_ID == 'ealvaradob/bert-finetuned-phishing':
            detail = 'Local CPU inference; pretrained model, not team-retrained'
        else:
            # Don't just trust a non-default MODEL_ID to mean "team-trained" -- that overclaims
            # for anyone pointing this at some other random public checkpoint. Only claim
            # team provenance when the training script's own report is actually sitting next
            # to the weights, and cite the real held-out test metrics from it.
            report_path = Path(MODEL_ID) / 'training_report.json'
            try:
                metrics = json.loads(report_path.read_text())['test_metrics']
                detail = (f'Local CPU inference; fine-tuned by this team on our own curated dataset '
                           f'(held-out test accuracy {metrics["test_accuracy"] * 100:.1f}%, '
                           f'F1 {metrics["test_f1"] * 100:.1f}%; see {report_path})')
            except (OSError, ValueError, KeyError):
                detail = f'Local CPU inference; custom model source ({MODEL_ID}); provenance not verified, evaluation pending'
    except Exception as exc:
        status, detail = 'unavailable', f'Model not loaded ({type(exc).__name__}); no AI prediction available'
        # The health-check detail stays short and user-facing on purpose; the actual
        # exception was previously swallowed entirely with no trace anywhere, making a
        # real load failure (bad cache, permissions, wrong MODEL_ID, OOM-adjacent errors
        # surfacing as OSError) undiagnosable from deployment logs alone.
        logger.error('Model load failed for MODEL_ID=%s: %s', MODEL_ID, exc)
        logger.error(traceback.format_exc())


def classify(text):
    if status != 'ready':
        return {'status': status, 'model': MODEL_ID, 'label': 'Unavailable', 'confidence': None, 'detail': detail}
    import torch
    with lock, torch.inference_mode():
        inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=MAX_LENGTH)
        scores = torch.softmax(model(**inputs).logits, dim=-1)[0]
        index = int(scores.argmax())
        return {'status': 'ready', 'model': MODEL_ID, 'label': model.config.id2label[index],
                'confidence': round(float(scores[index]) * 100, 1),
                'phishing_probability': round(float(scores[phishing_index]) * 100, 1),
                'detail': f'Uncalibrated model probability; first {MAX_LENGTH} tokens; independent evaluation pending'}
