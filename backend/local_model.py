"""Local-only inference. Never silently substitute rules for a trained model."""
import os
import threading

os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

MODEL_ID = os.getenv('MODEL_ID', 'ealvaradob/bert-finetuned-phishing')
# Must match whatever the loaded model was actually trained/fine-tuned at -- a
# train/inference mismatch here silently degrades accuracy without erroring.
MAX_LENGTH = int(os.getenv('MODEL_MAX_LENGTH', '256'))
lock = threading.Lock()
model = tokenizer = None
status = 'loading'
detail = 'Loading locally cached model'


def load():
    global model, tokenizer, status, detail
    if os.getenv('DISABLE_ML') == '1':
        status, detail = 'unavailable', 'Model disabled by configuration'
        return
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        torch.set_num_threads(min(4, os.cpu_count() or 1))
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, local_files_only=True, trust_remote_code=False)
        candidate = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, local_files_only=True, low_cpu_mem_usage=True)
        labels = {str(v).lower(): int(k) for k, v in candidate.config.id2label.items()}
        if not any('phish' in label for label in labels):
            raise ValueError('Model label mapping must identify phishing explicitly')
        model = candidate.eval()
        status, detail = 'ready', 'Local CPU inference; pretrained model, not team-retrained'
    except Exception as exc:
        status, detail = 'unavailable', f'Model not loaded ({type(exc).__name__}); no AI prediction available'


def classify(text):
    if status != 'ready':
        return {'status': status, 'model': MODEL_ID, 'label': 'Unavailable', 'confidence': None, 'detail': detail}
    import torch
    with lock, torch.inference_mode():
        inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=MAX_LENGTH)
        scores = torch.softmax(model(**inputs).logits, dim=-1)[0]
        index = int(scores.argmax())
        phishing_index = next(int(k) for k, v in model.config.id2label.items() if 'phish' in v.lower())
        return {'status': 'ready', 'model': MODEL_ID, 'label': model.config.id2label[index],
                'confidence': round(float(scores[index]) * 100, 1),
                'phishing_probability': round(float(scores[phishing_index]) * 100, 1),
                'detail': f'Uncalibrated model probability; first {MAX_LENGTH} tokens; independent evaluation pending'}
