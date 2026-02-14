FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install vijil-dome from local wheel (includes instrument_dome for Darwin telemetry)
COPY vijil_dome-*.whl /tmp/
RUN pip install --no-cache-dir /tmp/vijil_dome-*.whl \
    opentelemetry-instrumentation-asyncio \
    opentelemetry-instrumentation-threading \
    opentelemetry-instrumentation-logging \
    && rm /tmp/vijil_dome-*.whl

# Copy application
COPY . .

# Expose A2A port
EXPOSE 9000

# Run agent
CMD ["python", "agent.py"]
