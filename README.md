# Public API Service

A simple FastAPI web service with basic authentication.

## Credentials
- **Username:** `aparoksha`
- **Password:** `aparoksha123`

## Endpoints

| Endpoint | Auth Required | Description |
|----------|---------------|-------------|
| `GET /` | No | Welcome message |
| `GET /public` | No | Public endpoint |
| `GET /protected` | **Yes** | Protected endpoint (requires auth) |
| `GET /health` | No | Health check |

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python main.py
```

The server will start on `http://0.0.0.0:8000` (accessible from any IP).

## Testing

```bash
# Public endpoints (no auth)
curl http://localhost:8000/
curl http://localhost:8000/public
curl http://localhost:8000/health

# Protected endpoint (with auth)
curl -u aparoksha:aparoksha123 http://localhost:8000/protected
```

## Docker (optional)

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
EXPOSE 8000
CMD ["python", "main.py"]
```

Build and run:
```bash
docker build -t public-api .
docker run -p 8000:8000 public-api
```