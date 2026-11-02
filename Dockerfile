FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_ENV=production \
    DATABASE_PATH=/var/data/eip.sqlite3 UPLOAD_DIR=/var/data/uploads EMBEDDING_CACHE_DIR=/app/models
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5', cache_dir='/app/models')"
COPY backend backend
COPY frontend frontend
COPY docs docs
# Run as an unprivileged user
RUN useradd --create-home --uid 10001 eip && mkdir -p /var/data && chown -R eip:eip /var/data /app/models
USER eip
WORKDIR /app/backend
EXPOSE 5000
CMD gunicorn wsgi:app --bind 0.0.0.0:${PORT:-5000} --workers 1 --threads 8 --timeout 300 --forwarded-allow-ips="*"
