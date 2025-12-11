# FraudShield 🛡️

**Multi-modal AI-powered fraud detection system** that analyzes text, URLs, audio, images, emails, PDFs, and videos to identify scams, phishing attempts, and social engineering attacks.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

### Multi-Modal Analysis

| Type | Input | Description |
|------|-------|-------------|
| `text` | Message text | Scam patterns, urgency language, suspicious keywords |
| `url` / `link` | URL string | Phishing detection, brand impersonation, suspicious TLDs |
| `audio` | `.wav`, `.mp3` | Transcription + text analysis for voice scams |
| `image` | `.png`, `.jpg` | GPT-4o vision for fake screenshots, phishing pages |
| `email` | `.eml` | Full email parsing with text + URL + attachment analysis |
| `pdf` / `document` | PDF file | Text extraction, URL detection, invoice fraud |
| `video` | `.mp4` | Frame + audio extraction with multi-modal fusion |
| `multi` | Any combination | Weighted fusion across all modalities |

### Industry-Standard Features

| Feature | Description |
|---------|-------------|
| **Blacklist/Whitelist** | Known bad/good patterns for instant classification |
| **Velocity Checks** | Detect rapid duplicate submissions and rate abuse |
| **A/B Testing** | Compare model versions and prompts |
| **Explainability** | Feature importance breakdown with recommendations |
| **Feedback Loop** | Report false positives/negatives to improve accuracy |
| **Structured Logging** | JSON logs for production monitoring |
| **Configurable Thresholds** | Per-client risk level customization |

### Analysis Response

```json
{
  "risk_level": "HIGH",
  "overall_score": 8.5,
  "confidence": 0.92,
  "modality_scores": {"text": 7.5, "url": 9.5},
  "indicators": ["urgency_language", "brand_impersonation_paypal"],
  "explanation": "Combined analysis detected...",
  "recommendations": [
    "⚠️ HIGH RISK: Do not proceed without verification",
    "🔗 Verify the URL by typing it directly in your browser"
  ],
  "explainability": {
    "summary": "Risk based primarily on: brand_impersonation_paypal, urgency_language",
    "feature_breakdown": [
      {"feature": "brand_impersonation_paypal", "contribution": 4.5, "weight": 1.0}
    ]
  }
}
```

---

## 🚀 Quickstart

### 1. Clone and Install

```bash
git clone <repo-url>
cd fraudshield
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac
pip install -r requirements.txt
```

### 2. Configure Environment

Create `.env` in the project root:

```env
# OpenAI
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini

# Database
DATABASE_URL=sqlite:///./fraudshield.db

# Environment (dev or prod)
ENVIRONMENT=dev
DEBUG=true

# Security (required in production)
API_TOKEN=your-secret-token-here
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW=60
CORS_ORIGINS=http://localhost:3000,http://localhost:8501
```

### 3. Run the Server

```bash
uvicorn fraudshield.api.server:app --reload
```

### 4. Open API Docs

Navigate to: http://127.0.0.1:8000/docs

### 5. (Optional) Run Streamlit UI

```bash
streamlit run app.py
```

Navigate to: http://localhost:8501

---

## 📖 API Reference

### Core Endpoints

#### `POST /analyze`

Analyze content for fraud risk.

```bash
# Text analysis
curl -X POST http://127.0.0.1:8000/analyze \
  -H "X-API-Key: your-token" \
  -F "type=text" \
  -F "text=URGENT: Your account has been compromised!"

# URL analysis
curl -X POST http://127.0.0.1:8000/analyze \
  -H "X-API-Key: your-token" \
  -F "type=url" \
  -F "url=http://bit.ly/paypal-verify"

# Image analysis
curl -X POST http://127.0.0.1:8000/analyze \
  -H "X-API-Key: your-token" \
  -F "type=image" \
  -F "file=@screenshot.png"

# Multi-modal analysis
curl -X POST http://127.0.0.1:8000/analyze \
  -H "X-API-Key: your-token" \
  -F "type=multi" \
  -F "text=Click here for your prize" \
  -F "url=http://free-prizes.xyz" \
  -F "file=@screenshot.png" \
  -F "source_hint=image"
```

#### `POST /feedback`

Submit feedback to improve accuracy.

```bash
curl -X POST http://127.0.0.1:8000/feedback \
  -H "X-API-Key: your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "The original message",
    "modality": "text",
    "predicted_risk_level": "HIGH",
    "predicted_score": 8.5,
    "feedback_type": "false_positive",
    "actual_risk_level": "LOW",
    "comment": "This was a legitimate email"
  }'
```

#### `GET /feedback/stats`

Get accuracy statistics from user feedback.

```bash
curl http://127.0.0.1:8000/feedback/stats?days=30 \
  -H "X-API-Key: your-token"
```

### Admin Endpoints

All admin endpoints require API authentication.

#### Blacklist/Whitelist Management

```bash
# Add to blacklist
curl -X POST http://127.0.0.1:8000/admin/blacklist \
  -H "X-API-Key: your-token" \
  -H "Content-Type: application/json" \
  -d '{"value": "scam-domain.com", "category": "domains"}'

# Add regex pattern
curl -X POST http://127.0.0.1:8000/admin/blacklist \
  -H "X-API-Key: your-token" \
  -H "Content-Type: application/json" \
  -d '{"value": "paypal.*verify.*\\.com", "category": "phishing", "is_regex": true}'

# Add to whitelist
curl -X POST http://127.0.0.1:8000/admin/whitelist \
  -H "X-API-Key: your-token" \
  -H "Content-Type: application/json" \
  -d '{"value": "mycompany.com", "category": "domains"}'

# Check a URL
curl "http://127.0.0.1:8000/admin/lists/check?value=https://paypa1.com&check_type=url" \
  -H "X-API-Key: your-token"

# Get list stats
curl http://127.0.0.1:8000/admin/lists/stats \
  -H "X-API-Key: your-token"
```

#### A/B Testing

```bash
# Create experiment
curl -X POST http://127.0.0.1:8000/admin/experiments \
  -H "X-API-Key: your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "prompt_v2_test",
    "name": "New Prompt Testing",
    "variants": {
      "control": {"weight": 1.0, "config": {"prompt_version": "v1"}},
      "treatment": {"weight": 1.0, "config": {"prompt_version": "v2"}}
    },
    "traffic_percentage": 50.0
  }'

# Start experiment
curl -X POST http://127.0.0.1:8000/admin/experiments/prompt_v2_test/start \
  -H "X-API-Key: your-token"

# Get results
curl http://127.0.0.1:8000/admin/experiments/prompt_v2_test \
  -H "X-API-Key: your-token"

# Complete experiment
curl -X POST http://127.0.0.1:8000/admin/experiments/prompt_v2_test/complete \
  -H "X-API-Key: your-token"
```

#### Metrics & Monitoring

```bash
# Get application metrics
curl http://127.0.0.1:8000/admin/metrics \
  -H "X-API-Key: your-token"

# Get velocity tracker stats
curl http://127.0.0.1:8000/admin/velocity/stats \
  -H "X-API-Key: your-token"
```

---

## 🏗️ Project Structure

```
fraudshield/
├── api/
│   ├── server.py           # FastAPI application & routes
│   ├── admin.py             # Admin endpoints (lists, A/B, metrics)
│   └── security.py          # Authentication & rate limiting
├── pipelines/
│   ├── text_pipeline.py     # Text analysis (heuristics + LLM)
│   ├── url_pipeline.py      # URL analysis (heuristics + LLM)
│   ├── audio_pipeline.py    # Audio transcription + analysis
│   ├── vision_pipeline.py   # Image analysis with GPT-4o
│   ├── email_pipeline.py    # Email parsing + multi-signal
│   ├── pdf_pipeline.py      # PDF extraction + analysis
│   ├── video_pipeline.py    # Video frame + audio analysis
│   └── fusion_engine.py     # Multi-modal score fusion
├── services/
│   ├── llm_client.py        # OpenAI API wrapper
│   ├── text_service.py      # Text heuristics
│   ├── risk_service.py      # URL heuristics + scoring
│   ├── audio_service.py     # Audio transcription
│   ├── vision_service.py    # Vision analysis
│   ├── email_service.py     # Email parsing (.eml)
│   ├── pdf_service.py       # PDF text extraction
│   ├── video_service.py     # Video processing
│   ├── cache_service.py     # Analysis caching
│   ├── velocity_service.py  # Rate/duplicate detection
│   ├── lists_service.py     # Blacklist/whitelist
│   ├── feedback_service.py  # User feedback tracking
│   └── ab_testing.py        # A/B testing framework
├── utils/
│   ├── confidence.py        # Confidence calibration
│   ├── risk_levels.py       # Risk level calculation
│   ├── explainability.py    # Feature importance
│   └── logging_config.py    # Structured logging & metrics
├── models/
│   ├── analysis.py          # Analysis log model
│   └── feedback.py          # Feedback model
├── schemas/
│   └── analyze_schemas.py   # Pydantic models
├── tests/                    # Test suite
├── config.py                 # Settings from .env
├── database.py               # Database connection
└── app.py                    # Streamlit UI
```

---

## 🧪 Development

### Install Dev Dependencies

```bash
pip install -r dev-requirements.txt
```

### Run Tests

```bash
pytest fraudshield/tests/ -v
```

### Run with Coverage

```bash
pytest fraudshield/tests/ -v --cov=fraudshield --cov-report=term-missing
```

### Test Categories

| Test File | Coverage |
|-----------|----------|
| `test_api.py` | Core API endpoints |
| `test_heuristics.py` | Text & URL heuristics |
| `test_confidence.py` | Confidence calibration |
| `test_fusion.py` | Multi-modal fusion |
| `test_velocity.py` | Rate limiting & duplicates |
| `test_lists.py` | Blacklist/whitelist |
| `test_explainability.py` | Feature importance |
| `test_feedback.py` | Feedback system |
| `test_risk_levels.py` | Risk calculation |

---

## ⚙️ Configuration

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | (required) | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model for text/URL analysis |
| `OPENAI_VISION_MODEL` | `gpt-4o-mini` | Model for image analysis |
| `OPENAI_TRANSCRIPTION_MODEL` | `gpt-4o-mini-transcribe` | Model for audio |
| `OPENAI_MAX_TOKENS` | `1000` | Max tokens for LLM responses |
| `DATABASE_URL` | `sqlite:///./fraudshield.db` | Database connection |
| `ENVIRONMENT` | `dev` | `dev` or `prod` |
| `DEBUG` | `true` | Enable debug mode |

### Security & Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `API_TOKEN` | (empty) | API authentication token |
| `RATE_LIMIT_REQUESTS` | `60` | Max requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Window in seconds |
| `CORS_ORIGINS` | `*` | Allowed origins (comma-separated) |

### Risk Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `HIGH_RISK_THRESHOLD` | `7.0` | Score >= this = HIGH |
| `MEDIUM_RISK_THRESHOLD` | `4.0` | Score >= this = MEDIUM |
| `CRITICAL_INDICATORS` | (see docs) | Force HIGH (comma-separated) |
| `ELEVATED_INDICATORS` | (see docs) | Bump to MEDIUM (comma-separated) |

### Velocity & Caching

| Variable | Default | Description |
|----------|---------|-------------|
| `VELOCITY_CONTENT_WINDOW` | `300` | Seconds for duplicate tracking |
| `VELOCITY_CONTENT_MAX_DUPLICATES` | `3` | Max duplicates before flag |
| `VELOCITY_IP_WINDOW` | `60` | Seconds for IP rate tracking |
| `VELOCITY_IP_MAX_REQUESTS` | `30` | Max requests per IP |
| `CACHE_CAPACITY` | `128` | Max cached items |
| `CACHE_TTL` | `3600` | Cache TTL in seconds |

See [docs/ENV_EXAMPLE.md](docs/ENV_EXAMPLE.md) for full configuration reference.

### Risk Level Logic

```
Score 0-3.9  → LOW
Score 4-6.9  → MEDIUM  
Score 7-10   → HIGH

Overrides:
- Critical indicators (credential_theft, brand_impersonation) → Force HIGH
- Elevated indicators (urgency_language, url_shortener) → Bump LOW to MEDIUM
```

---

## 🔒 Security

### API Authentication

```bash
# Set strong token in production
export API_TOKEN=$(openssl rand -hex 32)

# Include in requests
curl -H "X-API-Key: $API_TOKEN" ...
```

### Rate Limiting

- Default: 60 requests/minute per IP
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`
- Exceeded: `429 Too Many Requests`

### Production Checklist

- [ ] Set `ENVIRONMENT=prod`
- [ ] Set `DEBUG=false` (disables /docs)
- [ ] Generate strong `API_TOKEN`
- [ ] Configure specific `CORS_ORIGINS`
- [ ] Use HTTPS (reverse proxy)
- [ ] Set up log aggregation
- [ ] Configure alerting on HIGH risk spikes

---

## 📊 Monitoring

### Structured Logging

Production logs are JSON-formatted for easy parsing:

```json
{
  "timestamp": "2024-12-11T10:30:00.000Z",
  "level": "INFO",
  "logger": "fraudshield.api",
  "message": "Analysis completed",
  "data": {
    "modality": "text",
    "risk_level": "HIGH",
    "duration_ms": 125
  },
  "environment": "prod"
}
```

### Metrics

Access via `/admin/metrics`:

```json
{
  "uptime_seconds": 3600,
  "counters": {
    "analysis.text.total": 150,
    "analysis.text.risk.high": 12
  },
  "timings": {
    "analysis.text.latency": {
      "avg": 0.125,
      "p95": 0.250
    }
  }
}
```

---

## 📦 Dependencies

**Core:**
- FastAPI, Uvicorn, Pydantic
- OpenAI SDK (LLM + Vision + Audio)
- SQLAlchemy (database)

**Document Processing:**
- `pypdf` - PDF extraction
- `moviepy` - Video processing
- `Pillow` - Image processing

**UI:**
- `streamlit` - Demo interface
- `requests` - HTTP client

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
