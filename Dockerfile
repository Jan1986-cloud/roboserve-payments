# Force rebuild

FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN echo "Cache-buster: $(date +%s)"
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
