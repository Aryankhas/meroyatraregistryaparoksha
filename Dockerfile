FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for Pillow (if needed later)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg-dev zlib1g-dev libpng-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY frontend/ ./frontend/

EXPOSE 8000

CMD ["python", "main.py"]