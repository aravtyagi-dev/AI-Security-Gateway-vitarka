FROM python:3.11-slim

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy gateway source code and documents
COPY . .

# Pre-train classifier model
RUN python eval/train_injection.py

EXPOSE 8000 8501 8502

CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
