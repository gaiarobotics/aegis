FROM python:3.12-slim

WORKDIR /app

# Install aegis-shield from source first (aegis-monitor depends on it)
COPY pyproject.toml README.md /app/
COPY aegis/ /app/aegis/
RUN pip install --no-cache-dir .

# Install aegis-monitor from source
COPY aegis-monitor/ /app/aegis-monitor/
RUN pip install --no-cache-dir /app/aegis-monitor/

EXPOSE 8080

CMD ["uvicorn", "monitor.app:app", "--host", "0.0.0.0", "--port", "8080"]
