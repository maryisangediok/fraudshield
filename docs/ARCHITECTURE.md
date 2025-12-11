# FraudShield Architecture

## Overview

FraudShield is a multi-modal fraud detection system that combines rule-based heuristics with LLM-powered analysis. The architecture is designed for:

- **Modularity**: Each modality has its own pipeline
- **Extensibility**: Easy to add new analysis types
- **Reliability**: Graceful fallbacks when LLM unavailable
- **Performance**: Caching and early exits for known patterns

---

## System Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                           API Request                                │
│                    POST /analyze (text, url, file)                  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Security Layer                               │
│              API Authentication + Rate Limiting                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Pre-Processing Layer                            │
│                                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────────┐ │
│  │  Blacklist/ │  │   Velocity   │  │         Cache               │ │
│  │  Whitelist  │  │    Check     │  │   (skip if cached)          │ │
│  │   Check     │  │              │  │                             │ │
│  └─────────────┘  └──────────────┘  └─────────────────────────────┘ │
│         │                │                        │                  │
│         ▼                ▼                        ▼                  │
│    [Instant]       [Risk Boost]            [Return cached]          │
│    HIGH/LOW        Added                                             │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Analysis Pipelines                             │
│                                                                      │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │  Text   │ │   URL   │ │  Audio  │ │  Image  │ │  Video  │       │
│  │Pipeline │ │Pipeline │ │Pipeline │ │Pipeline │ │Pipeline │       │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘       │
│       │           │           │           │           │             │
│       ▼           ▼           ▼           ▼           ▼             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Fusion Engine                             │   │
│  │           (Weighted combination for multi-modal)             │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Post-Processing Layer                           │
│                                                                      │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────┐ │
│  │   Risk Level    │  │  Confidence      │  │   Explainability   │ │
│  │   Calculation   │  │  Calibration     │  │      Report        │ │
│  └─────────────────┘  └──────────────────┘  └────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           Response                                   │
│        risk_level, score, confidence, indicators, explanation        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Analysis Pipelines

Each pipeline follows the same pattern:

```python
def analyze_X_with_llm(input) -> Dict[str, Any]:
    # 1. Check blacklist/whitelist (instant override)
    # 2. Check velocity (add risk boost)
    # 3. Run heuristics (fast, rule-based)
    # 4. Run LLM analysis (slow, AI-powered)
    # 5. Combine scores
    # 6. Calculate risk level
    # 7. Generate explainability report
    return result
```

#### Text Pipeline
- **Heuristics**: Keyword matching, urgency detection, crypto references
- **LLM**: Full message analysis with context understanding

#### URL Pipeline
- **Heuristics**: IP detection, TLD checking, brand impersonation
- **LLM**: URL structure analysis, phishing pattern recognition

#### Audio Pipeline
- **Transcription**: OpenAI Whisper API
- **Analysis**: Text pipeline on transcript

#### Image Pipeline
- **Vision**: GPT-4o vision for screenshot analysis
- **Detection**: Fake login pages, scam invoices, phishing emails

#### Video Pipeline
- **Extraction**: Key frames + audio track
- **Analysis**: Image + audio pipelines fused together

---

### 2. Scoring System

#### Score Scale: 0-10

| Score Range | Risk Level |
|-------------|------------|
| 0.0 - 3.9 | LOW |
| 4.0 - 6.9 | MEDIUM |
| 7.0 - 10.0 | HIGH |

#### Score Combination

```python
# Simple average of heuristic and LLM scores
combined_score = (heuristic_score + llm_score) / 2.0

# Add velocity risk boost
combined_score = min(10.0, combined_score + velocity.risk_boost)
```

#### Risk Level Overrides

1. **Critical indicators** → Force HIGH
   - `credential_theft`
   - `identity_theft`
   - `brand_impersonation_paypal`
   - `malware_distribution`

2. **Elevated indicators** → Bump LOW to MEDIUM
   - `urgency_language`
   - `crypto_reference`
   - `url_shortener_used`

---

### 3. Confidence Calibration

LLM confidence is adjusted based on agreement with heuristics:

```python
if heuristic_risk == llm_risk:
    # Strong agreement: boost confidence
    calibrated = min(1.0, llm_confidence + 0.2)
elif abs(heuristic_level - llm_level) == 1:
    # Moderate agreement: keep as-is
    calibrated = llm_confidence
else:
    # Conflict: reduce confidence
    calibrated = max(0.0, llm_confidence - 0.3)
```

---

### 4. Multi-Modal Fusion

When analyzing multiple modalities, scores are weighted:

```python
weights = {
    "text": 1.0,
    "url": 1.1,   # URLs are slightly more reliable
    "audio": 1.3, # Audio scams are high-confidence
    "image": 1.2, # Visual evidence is strong
}

overall_score = sum(score * weight) / sum(weights)
```

The final risk level is the **maximum** of:
- Score-derived level
- Maximum individual modality level

---

### 5. Blacklist/Whitelist

Provides instant classification for known patterns:

```
Request arrives
      │
      ▼
┌─────────────────┐
│ Check Whitelist │──Yes──▶ Return LOW (skip analysis)
└────────┬────────┘
         │ No
         ▼
┌─────────────────┐
│ Check Blacklist │──Yes──▶ Return HIGH (skip analysis)
└────────┬────────┘
         │ No
         ▼
    Continue to
    full analysis
```

---

### 6. Velocity Checks

Detects suspicious patterns:

| Pattern | Risk Boost | Indicator |
|---------|------------|-----------|
| Same content 3+ times in 5 min | +1.5 | `velocity_duplicate_content` |
| IP at 80%+ of rate limit | +0.5 | `velocity_high_ip_rate` |
| IP exceeds rate limit | +2.0 | `velocity_ip_limit_exceeded` |

---

## Database Schema

### Analysis Table

```sql
CREATE TABLE analysis (
    id INTEGER PRIMARY KEY,
    user_hash TEXT,
    modality TEXT,
    risk_level TEXT,
    overall_score TEXT,
    modality_scores JSON,
    indicators JSON,
    source_hint TEXT,
    created_at TIMESTAMP
);
```

### Feedback Table

```sql
CREATE TABLE feedback (
    id INTEGER PRIMARY KEY,
    content_hash TEXT,
    modality TEXT,
    predicted_risk_level TEXT,
    predicted_score REAL,
    feedback_type TEXT,
    actual_risk_level TEXT,
    analysis_id INTEGER,
    client_id TEXT,
    user_comment TEXT,
    created_at TIMESTAMP
);
```

---

## Configuration

All configuration via environment variables:

```
┌─────────────────────────────────────────────┐
│                 config.py                    │
│                                             │
│  Settings (BaseSettings)                    │
│  ├── openai_api_key                         │
│  ├── openai_model                           │
│  ├── openai_vision_model                    │
│  ├── database_url                           │
│  ├── environment (dev/prod)                 │
│  ├── api_token                              │
│  ├── rate_limit_requests                    │
│  ├── rate_limit_window                      │
│  ├── cors_origins                           │
│  ├── low_risk_threshold (4.0)               │
│  ├── medium_risk_threshold (7.0)            │
│  ├── critical_indicators [...]              │
│  └── elevated_indicators [...]              │
└─────────────────────────────────────────────┘
```

---

## Error Handling

### LLM Fallback

When OpenAI API fails, return neutral score:

```python
try:
    llm_result = llm.score_text(text)
except OpenAIError:
    llm_result = {
        "risk_level": "LOW",
        "overall_score": 0.0,
        "confidence": 0.0,
        "indicators": ["llm_unavailable"],
    }
```

### Graceful Degradation

```
Full Analysis (LLM + Heuristics)
         │
         │ LLM fails
         ▼
Heuristics Only (rule-based)
         │
         │ Heuristics fail
         ▼
Return LOW with error indicator
```

---

## Performance Considerations

1. **Caching**: Identical content returns cached result
2. **Early exits**: Blacklist/whitelist skip full analysis
3. **Async**: Audio/image processing is async
4. **Rate limiting**: Prevents abuse
5. **Connection pooling**: Database and OpenAI client reuse


