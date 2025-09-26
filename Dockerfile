# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN useradd -m -u 10001 botuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

# Create non-root writable volume for state
RUN mkdir -p /state && chown -R botuser:botuser /state
ENV DB_PATH=/state/bot_state.sqlite3

USER botuser
CMD ["python", "main.py"]
