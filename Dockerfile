FROM python:3.13-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/browsers \
    SUBTOOLS_DATA_DIR=/app/data SUBTOOLS_HOST=0.0.0.0 SUBTOOLS_PORT=8787
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends xvfb xauth tini gosu fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 subtools
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/browsers \
    && rm -rf /var/lib/apt/lists/*
COPY *.py ./
COPY web ./web
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /app/data && chown subtools:subtools /app/data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=3)"
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["python", "run_web.py"]
