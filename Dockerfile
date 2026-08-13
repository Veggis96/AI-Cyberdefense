FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY cyberdefense_agent ./cyberdefense_agent
COPY samples ./samples

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/data /app/reports \
    && chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["cyberdefense-agent"]
CMD ["--events", "samples/events.jsonl"]
