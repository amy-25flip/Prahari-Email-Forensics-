FROM node:22-bookworm-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu && pip install --no-cache-dir -r requirements.txt
ENV HF_HOME=/opt/model-cache HF_HUB_DISABLE_PROGRESS_BARS=1
# This repo ships weights as pytorch_model.bin, not .safetensors (confirmed via
# HfApi().list_repo_files() -- do not assume a HF repo has safetensors available).
# Missing '*.bin' here silently downloaded everything except the actual model
# weights and only surfaced as a runtime OSError on first real deployment.
RUN python -c "from huggingface_hub import snapshot_download; snapshot_download('ealvaradob/bert-finetuned-phishing', allow_patterns=['*.json','*.txt','*.safetensors','*.bin'])"
COPY backend/ ./
COPY --from=frontend /app/frontend/dist /app/frontend/dist
RUN useradd --uid 1000 --create-home appuser && mkdir /data && chown appuser /data && chmod -R a+rX /opt/model-cache
ENV DATA_DIR=/data COOKIE_SECURE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 PORT=8000
USER appuser
EXPOSE 8000
# /api/ready (not /api/health) -- /api/health always reports status:ready
# regardless of whether the BERT model has actually finished loading, so
# using it here would let this HEALTHCHECK pass before the model is usable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT','8000') + '/api/ready', timeout=3)"
CMD ["python", "serve.py"]
