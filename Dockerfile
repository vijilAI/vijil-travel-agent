FROM python:3.12-slim

WORKDIR /app

# Install dependencies. requirements.txt is the only install source for vijil-dome
# (exact pin); do not add a later pip step that installs a different vijil-dome.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose A2A port
EXPOSE 9000

# Run agent
CMD ["python", "agent.py"]
