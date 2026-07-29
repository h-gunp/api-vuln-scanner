FROM golang:1.23-bookworm AS katana-builder

RUN GOBIN=/out go install github.com/projectdiscovery/katana/cmd/katana@v1.1.2

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY scanner ./scanner
COPY --from=katana-builder /out/katana /usr/local/bin/katana
RUN pip install --upgrade pip && pip install .

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8001
CMD ["uvicorn", "scanner.api:app", "--host", "0.0.0.0", "--port", "8001"]
