FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /app
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt && groupadd --gid 10001 phishintel && useradd --uid 10001 --gid 10001 --no-create-home phishintel
COPY phishintel ./phishintel
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=2).close()"]
CMD ["uvicorn", "phishintel.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--limit-concurrency", "16", "--timeout-keep-alive", "5"]
