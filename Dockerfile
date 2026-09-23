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
# Ship the TEAM'S OWN fine-tuned checkpoint (99.32% held-out test accuracy --
# see training_report.json alongside the weights), not a generic pretrained
# public model. An earlier version of this Dockerfile instead downloaded
# ealvaradob/bert-finetuned-phishing from the Hugging Face Hub and never set
# MODEL_ID, so a built image silently served that pretrained model in place
# of the real one this project trains and reports metrics for.
COPY training/output/phishing-bert-v1/final/ /opt/model/phishing-bert-v1/
COPY backend/ ./
COPY --from=frontend /app/frontend/dist /app/frontend/dist
RUN useradd --uid 1000 --create-home appuser && mkdir /data && chown appuser /data && chmod -R a+rX /opt/model
ENV DATA_DIR=/data COOKIE_SECURE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 PORT=8000 MODEL_ID=/opt/model/phishing-bert-v1
USER appuser
EXPOSE 8000
# /api/ready (not /api/health) -- /api/health always reports status:ready
# regardless of whether the BERT model has actually finished loading, so
# using it here would let this HEALTHCHECK pass before the model is usable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT','8000') + '/api/ready', timeout=3)"
CMD ["python", "serve.py"]
