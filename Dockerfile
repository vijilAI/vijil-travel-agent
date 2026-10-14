FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vijil_dome-*.whl /tmp/
RUN pip install --no-cache-dir /tmp/vijil_dome-*.whl \
    opentelemetry-instrumentation-asyncio \
    opentelemetry-instrumentation-threading \
    opentelemetry-instrumentation-logging \
    && rm /tmp/vijil_dome-*.whl

COPY . .

EXPOSE 9000

CMD ["python", "agent.py"]
