# Environment Configuration

Copy these variables to a `.env` file in the project root.

---

## Required Variables

```env
# OpenAI API key (get from https://platform.openai.com/api-keys)
OPENAI_API_KEY=sk-your-api-key-here
```

---

## All Configuration Options

### Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `dev` | Environment mode: `dev` or `prod` |
| `DEBUG` | `true` | Enable debug mode (shows /docs) |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./fraudshield.db` | Database connection string |

### OpenAI

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | (required) | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model for text/URL analysis |
| `OPENAI_VISION_MODEL` | `gpt-4o-mini` | Model for image analysis |
| `OPENAI_TRANSCRIPTION_MODEL` | `gpt-4o-mini-transcribe` | Model for audio transcription |
| `OPENAI_MAX_TOKENS` | `1000` | Max tokens for LLM responses |

### API Security

| Variable | Default | Description |
|----------|---------|-------------|
| `API_TOKEN` | (empty) | API authentication token |
| `API_TOKEN_HEADER` | `X-API-Key` | Header name for API token |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_REQUESTS` | `60` | Max requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Window in seconds |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | `*` | Allowed origins (comma-separated) |

### Risk Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `HIGH_RISK_THRESHOLD` | `7.0` | Score >= this = HIGH |
| `MEDIUM_RISK_THRESHOLD` | `4.0` | Score >= this = MEDIUM |

### Indicator Overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `CRITICAL_INDICATORS` | (see below) | Force HIGH risk (comma-separated) |
| `ELEVATED_INDICATORS` | (see below) | Bump LOW to MEDIUM (comma-separated) |

**Default Critical Indicators:**
```
credential_theft,identity_theft,brand_impersonation_paypal,
brand_impersonation,wire_transfer_request,gift_card_scam,
malware_distribution,known_phishing_url,blacklisted_content,
blacklisted_domains
```

**Default Elevated Indicators:**
```
urgency_language,suspicious_keywords,crypto_reference,
url_shortener_used,phishing_path_keywords,sensitive_query_parameters,
velocity_duplicate_content,velocity_high_ip_rate
```

### Velocity Checking

| Variable | Default | Description |
|----------|---------|-------------|
| `VELOCITY_CONTENT_WINDOW` | `300` | Seconds to track duplicate content |
| `VELOCITY_CONTENT_MAX_DUPLICATES` | `3` | Max same content before flagging |
| `VELOCITY_IP_WINDOW` | `60` | Seconds for IP rate tracking |
| `VELOCITY_IP_MAX_REQUESTS` | `30` | Max requests per IP in window |

### Caching

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_CAPACITY` | `128` | Max cached items |
| `CACHE_TTL` | `3600` | Cache TTL in seconds (1 hour) |

### Feedback

| Variable | Default | Description |
|----------|---------|-------------|
| `WHITELIST_SUGGESTION_THRESHOLD` | `3` | False positives before suggesting whitelist |

---

## Development Configuration

```env
OPENAI_API_KEY=sk-your-key
OPENAI_MODEL=gpt-4o-mini
DATABASE_URL=sqlite:///./fraudshield.db
ENVIRONMENT=dev
DEBUG=true
CORS_ORIGINS=*
```

---

## Production Configuration

```env
# OpenAI
OPENAI_API_KEY=sk-prod-key
OPENAI_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini
OPENAI_TRANSCRIPTION_MODEL=gpt-4o-mini-transcribe
OPENAI_MAX_TOKENS=1000

# Database
DATABASE_URL=postgresql://user:pass@db.example.com:5432/fraudshield

# Environment
ENVIRONMENT=prod
DEBUG=false

# Security
API_TOKEN=<generate-with-openssl-rand-hex-32>
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW=60
CORS_ORIGINS=https://app.example.com,https://admin.example.com

# Risk Thresholds
HIGH_RISK_THRESHOLD=7.0
MEDIUM_RISK_THRESHOLD=4.0

# Velocity
VELOCITY_CONTENT_WINDOW=300
VELOCITY_CONTENT_MAX_DUPLICATES=3
VELOCITY_IP_WINDOW=60
VELOCITY_IP_MAX_REQUESTS=30

# Caching
CACHE_CAPACITY=500
CACHE_TTL=3600
```

---

## Generate Secure API Token

```bash
# Linux/Mac
openssl rand -hex 32

# Windows PowerShell
-join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
```

---

## Custom Indicator Lists

Add custom indicators to force specific risk levels:

```env
# Add custom critical indicators (force HIGH)
CRITICAL_INDICATORS=credential_theft,my_custom_scam_pattern,internal_threat

# Add custom elevated indicators (bump LOW to MEDIUM)
ELEVATED_INDICATORS=urgency_language,my_warning_pattern
```

