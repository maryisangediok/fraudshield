# FraudShield Deployment Guide

## Local Development

### Quick Start

```bash
# Clone and setup
git clone <repo-url>
cd fraudshield
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your OPENAI_API_KEY

# Run
uvicorn fraudshield.api.server:app --reload
```

### Development Environment

```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini
DATABASE_URL=sqlite:///./fraudshield.db
ENVIRONMENT=dev
DEBUG=true
API_TOKEN=dev-token
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
CORS_ORIGINS=*
```

---

## Production Deployment

### Environment Variables

```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini
DATABASE_URL=postgresql://user:pass@host:5432/fraudshield
ENVIRONMENT=prod
DEBUG=false
API_TOKEN=<generate-strong-token>
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW=60
CORS_ORIGINS=https://your-app.com,https://admin.your-app.com
```

Generate a secure API token:
```bash
openssl rand -hex 32
```

---

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home appuser
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run server
CMD ["uvicorn", "fraudshield.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - OPENAI_MODEL=gpt-4o-mini
      - DATABASE_URL=postgresql://fraudshield:password@db:5432/fraudshield
      - ENVIRONMENT=prod
      - DEBUG=false
      - API_TOKEN=${API_TOKEN}
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=fraudshield
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=fraudshield
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    # For future caching implementation

volumes:
  postgres_data:
```

### Build and Run

```bash
# Build
docker-compose build

# Run
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop
docker-compose down
```

---

## Cloud Deployment

### AWS (ECS/Fargate)

1. **ECR**: Push Docker image
2. **ECS**: Create task definition and service
3. **ALB**: Load balancer with HTTPS
4. **RDS**: PostgreSQL database
5. **Secrets Manager**: Store API keys

### Google Cloud Run

```bash
# Build and push
gcloud builds submit --tag gcr.io/PROJECT_ID/fraudshield

# Deploy
gcloud run deploy fraudshield \
  --image gcr.io/PROJECT_ID/fraudshield \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars "OPENAI_API_KEY=sk-..." \
  --set-env-vars "ENVIRONMENT=prod"
```

### Heroku

```bash
# Create app
heroku create fraudshield-api

# Set config
heroku config:set OPENAI_API_KEY=sk-...
heroku config:set ENVIRONMENT=prod
heroku config:set API_TOKEN=$(openssl rand -hex 32)

# Deploy
git push heroku main
```

---

## Reverse Proxy (nginx)

```nginx
upstream fraudshield {
    server 127.0.0.1:8000;
}

server {
    listen 443 ssl http2;
    server_name api.fraudshield.com;

    ssl_certificate /etc/letsencrypt/live/api.fraudshield.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.fraudshield.com/privkey.pem;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    location / {
        proxy_pass http://fraudshield;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for long-running analysis
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }

    # File upload limits
    client_max_body_size 50M;
}
```

---

## Monitoring

### Logging Setup

Production logs are JSON-formatted. Configure log aggregation:

**CloudWatch (AWS):**
```yaml
# cloudwatch-agent-config.json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [{
          "file_path": "/app/logs/fraudshield.log",
          "log_group_name": "fraudshield",
          "log_stream_name": "{instance_id}"
        }]
      }
    }
  }
}
```

**Datadog:**
```yaml
# datadog.yaml
logs:
  - type: file
    path: /app/logs/fraudshield.log
    service: fraudshield
    source: python
```

### Health Checks

```bash
# Basic health
curl https://api.fraudshield.com/health

# Detailed status
curl -H "X-API-Key: $API_TOKEN" https://api.fraudshield.com/status

# Metrics
curl -H "X-API-Key: $API_TOKEN" https://api.fraudshield.com/admin/metrics
```

### Alerting

Set up alerts for:
- Error rate > 5%
- P95 latency > 2s
- HIGH risk detections spike
- LLM unavailable for > 5 min
- Rate limit hits > 100/hour

---

## Scaling

### Horizontal Scaling

```yaml
# docker-compose with replicas
services:
  api:
    deploy:
      replicas: 3
```

### Considerations

1. **Database**: Use PostgreSQL with connection pooling
2. **Caching**: Add Redis for distributed caching
3. **Rate Limiting**: Move to Redis for shared state
4. **Sessions**: Stateless design (no session state)

---

## Security Checklist

- [ ] `ENVIRONMENT=prod` set
- [ ] `DEBUG=false` set
- [ ] Strong `API_TOKEN` generated
- [ ] `CORS_ORIGINS` restricted
- [ ] HTTPS enabled (via reverse proxy)
- [ ] Database credentials secured
- [ ] OpenAI API key in secrets manager
- [ ] Rate limiting configured
- [ ] Firewall rules in place
- [ ] Log aggregation configured
- [ ] Alerting configured

---

## Backup & Recovery

### Database Backup

```bash
# PostgreSQL backup
pg_dump -h localhost -U fraudshield -d fraudshield > backup.sql

# Restore
psql -h localhost -U fraudshield -d fraudshield < backup.sql
```

### Application State

Blacklist/whitelist and A/B experiments are currently in-memory. For production:
1. Persist to database
2. Or load from config file on startup

---

## Troubleshooting

### Common Issues

**LLM Rate Limits:**
```
openai.RateLimitError: Rate limit exceeded
```
→ Reduce concurrent requests or upgrade OpenAI tier

**Database Connection:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
→ Check DATABASE_URL and network connectivity

**Memory Issues (Video Processing):**
```
MemoryError: Unable to allocate
```
→ Increase container memory or process smaller chunks

### Debug Mode

Set `DEBUG=true` to:
- Enable `/docs` endpoint
- See detailed error messages
- Enable verbose logging


