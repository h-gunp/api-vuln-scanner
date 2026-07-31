FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY scanner ./scanner
COPY llm ./llm
RUN pip install --upgrade pip && pip install .

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8002
CMD ["uvicorn", "llm.api:app", "--host", "0.0.0.0", "--port", "8002"]
