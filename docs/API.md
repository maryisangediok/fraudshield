# FraudShield API Reference

Complete API documentation for FraudShield.

---

## Authentication

All endpoints require an API key in production. Pass it via the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-token-here" http://localhost:8000/analyze
```

In development (`ENVIRONMENT=dev`), authentication is optional.

---

## Core Endpoints

### `GET /health`

Health check endpoint.

**Response:**
```json
{"status": "ok"}
```

---

### `GET /status`

Get server status and configuration.

**Response:**
```json
{
  "status": "ok",
  "environment": "dev",
  "debug": true,
  "openai_model": "gpt-4o-mini",
  "rate_limit": {
    "requests": 60,
    "window_seconds": 60
  }
}
```

---

### `POST /analyze`

Analyze content for fraud risk.

**Request (multipart/form-data):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | One of: `text`, `url`, `audio`, `image`, `email`, `pdf`, `video`, `multi` |
| `text` | string | For text/multi | Message content to analyze |
| `url` | string | For url/multi | URL to analyze |
| `file` | file | For audio/image/email/pdf/video | File to analyze |
| `source_hint` | string | For multi | Hint for file type: `audio` or `image` |

**Response:**
```json
{
  "risk_level": "HIGH",
  "overall_score": 8.5,
  "confidence": 0.92,
  "modality_scores": {
    "text": 7.5,
    "url": 9.5
  },
  "indicators": [
    "urgency_language",
    "brand_impersonation_paypal",
    "phishing_path_keywords"
  ],
  "explanation": "Combined heuristic and LLM analysis...",
  "recommendations": [
    "⚠️ HIGH RISK: Do not proceed without verification",
    "🔗 Verify the URL by typing it directly in your browser"
  ],
  "explainability": {
    "summary": "Risk based primarily on: brand_impersonation_paypal",
    "feature_breakdown": [
      {
        "feature": "brand_impersonation_paypal",
        "contribution": 4.5,
        "weight": 1.0,
        "description": "URL appears to impersonate PayPal",
        "category": "url"
      }
    ],
    "category_scores": {
      "url": 4.5,
      "text": 3.0
    }
  }
}
```

**Risk Levels:**
- `LOW`: Score 0-3.9, no critical indicators
- `MEDIUM`: Score 4-6.9, or LOW with elevated indicators
- `HIGH`: Score 7-10, or any critical indicator present

---

### `POST /feedback`

Submit feedback on an analysis result.

**Request (JSON):**
```json
{
  "content": "The original analyzed content",
  "modality": "text",
  "predicted_risk_level": "HIGH",
  "predicted_score": 8.5,
  "feedback_type": "false_positive",
  "actual_risk_level": "LOW",
  "analysis_id": 123,
  "comment": "This was a legitimate marketing email"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | Yes | Original content that was analyzed |
| `modality` | string | Yes | Type of analysis (text, url, etc.) |
| `predicted_risk_level` | string | Yes | What the system predicted |
| `predicted_score` | float | Yes | Score the system gave |
| `feedback_type` | string | Yes | `false_positive`, `false_negative`, or `correct` |
| `actual_risk_level` | string | No | What risk level it should have been |
| `analysis_id` | int | No | Link to original analysis record |
| `comment` | string | No | User explanation |

**Response:**
```json
{
  "id": 42,
  "message": "Feedback submitted successfully. Thank you!",
  "feedback_type": "false_positive"
}
```

---

### `GET /feedback/stats`

Get feedback statistics.

**Query Parameters:**
- `days` (int, default 30): Time period for statistics

**Response:**
```json
{
  "period_days": 30,
  "total_feedback": 150,
  "false_positives": 12,
  "false_negatives": 5,
  "correct": 133,
  "false_positive_rate": 0.08,
  "false_negative_rate": 0.033,
  "accuracy": 0.887
}
```

---

## Admin Endpoints

All admin endpoints are under `/admin` prefix.

### Blacklist/Whitelist

#### `POST /admin/blacklist`

Add a pattern to the blacklist.

**Request:**
```json
{
  "value": "scam-domain.com",
  "category": "domains",
  "is_regex": false
}
```

#### `DELETE /admin/blacklist`

Remove a pattern from the blacklist.

**Request:**
```json
{
  "value": "scam-domain.com",
  "category": "domains"
}
```

#### `POST /admin/whitelist`

Add a pattern to the whitelist.

#### `DELETE /admin/whitelist`

Remove a pattern from the whitelist.

#### `GET /admin/lists/stats`

Get blacklist/whitelist statistics.

**Response:**
```json
{
  "blacklist_domains": 15,
  "blacklist_urls": 3,
  "blacklist_patterns": 8,
  "whitelist_domains": 50,
  "whitelist_urls": 0
}
```

#### `GET /admin/lists/check`

Check if a value matches any list.

**Query Parameters:**
- `value` (string): URL or content to check
- `check_type` (string): `url` or `content`

**Response:**
```json
{
  "value": "https://paypa1.com/login",
  "matched": true,
  "list_type": "blacklist",
  "pattern": "paypa1.com",
  "category": "domains",
  "risk_override": "HIGH"
}
```

---

### A/B Testing

#### `POST /admin/experiments`

Create a new experiment.

**Request:**
```json
{
  "id": "model_comparison",
  "name": "GPT-4o-mini vs GPT-4o",
  "description": "Compare accuracy between models",
  "variants": {
    "control": {
      "weight": 1.0,
      "config": {"model": "gpt-4o-mini"}
    },
    "treatment": {
      "weight": 0.1,
      "config": {"model": "gpt-4o"}
    }
  },
  "traffic_percentage": 10.0
}
```

#### `GET /admin/experiments`

List all experiments.

#### `GET /admin/experiments/{id}`

Get experiment details and results.

**Response:**
```json
{
  "experiment_id": "model_comparison",
  "name": "GPT-4o-mini vs GPT-4o",
  "status": "running",
  "started_at": "2024-12-01T10:00:00Z",
  "variants": {
    "control": {
      "impressions": 900,
      "conversions": 850,
      "conversion_rate": 0.944,
      "avg_score": 5.2
    },
    "treatment": {
      "impressions": 100,
      "conversions": 98,
      "conversion_rate": 0.980,
      "avg_score": 5.5
    }
  },
  "winner": null
}
```

#### `POST /admin/experiments/{id}/start`

Start an experiment.

#### `POST /admin/experiments/{id}/pause`

Pause an experiment.

#### `POST /admin/experiments/{id}/complete`

Complete an experiment and determine winner.

#### `DELETE /admin/experiments/{id}`

Delete an experiment.

---

### Metrics

#### `GET /admin/metrics`

Get application metrics.

**Response:**
```json
{
  "uptime_seconds": 86400,
  "counters": {
    "analysis.text.total": 1500,
    "analysis.text.risk.low": 1200,
    "analysis.text.risk.medium": 250,
    "analysis.text.risk.high": 50,
    "analysis.url.total": 800
  },
  "gauges": {},
  "timings": {
    "analysis.text.latency": {
      "count": 1500,
      "min": 0.05,
      "max": 2.5,
      "avg": 0.125,
      "p50": 0.100,
      "p95": 0.250,
      "p99": 0.500
    }
  }
}
```

#### `GET /admin/velocity/stats`

Get velocity tracker statistics.

**Response:**
```json
{
  "tracked_content_hashes": 150,
  "tracked_ips": 45,
  "tracked_clients": 10
}
```

#### `POST /admin/metrics/reset`

Reset all metrics.

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message here"
}
```

**Status Codes:**
- `400 Bad Request`: Invalid input
- `401 Unauthorized`: Missing or invalid API key
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

---

## Rate Limiting

**Headers:**
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in window

**When exceeded (429):**
```json
{
  "detail": "Rate limit exceeded. Try again in 45 seconds."
}
```


