# Changelog

All notable changes to FraudShield are documented here.

---

## [0.3.0] - 2024-12-11

### Added

#### Industry-Standard Features
- **Blacklist/Whitelist System** - Instant classification for known patterns
  - Domain and URL blacklisting
  - Regex pattern support
  - Content hash matching
  - Admin API endpoints for management

- **Velocity Checks** - Detect suspicious request patterns
  - Duplicate content detection
  - IP rate monitoring
  - Risk boost for suspicious patterns

- **A/B Testing Framework** - Compare model versions
  - Create and manage experiments
  - Consistent user assignment
  - Conversion and score tracking
  - Admin API for experiment management

- **Explainability** - Feature importance breakdown
  - Per-feature contribution scores
  - Category-based aggregation
  - Actionable recommendations
  - Human-readable summaries

- **Feedback System** - Improve accuracy over time
  - Submit false positive/negative reports
  - Track accuracy statistics
  - Identify candidates for whitelisting

- **Structured Logging** - Production-ready monitoring
  - JSON-formatted logs
  - Metrics collection (counters, gauges, timings)
  - Request tracking with correlation IDs

#### Admin Endpoints
- `POST/DELETE /admin/blacklist` - Manage blacklist
- `POST/DELETE /admin/whitelist` - Manage whitelist
- `GET /admin/lists/stats` - List statistics
- `GET /admin/lists/check` - Check value against lists
- `POST /admin/experiments` - Create A/B experiment
- `GET /admin/experiments` - List experiments
- `POST /admin/experiments/{id}/start` - Start experiment
- `POST /admin/experiments/{id}/complete` - Complete experiment
- `GET /admin/metrics` - Application metrics
- `GET /admin/velocity/stats` - Velocity tracker stats

### Changed
- Pipelines now check blacklist/whitelist before analysis
- Velocity risk boost added to combined scores
- Explainability data included in analysis response
- Recommendations added to response

### Tests
- `test_velocity.py` - Velocity checking tests
- `test_lists.py` - Blacklist/whitelist tests
- `test_explainability.py` - Feature importance tests
- `test_feedback.py` - Feedback system tests
- `test_risk_levels.py` - Risk calculation tests

---

## [0.2.0] - 2024-12-10

### Added

#### Multi-Modal Analysis
- **Email Analysis** (`type=email`)
  - Parse .eml files
  - Extract text, URLs, attachments
  - Multi-signal fusion

- **PDF Analysis** (`type=pdf`)
  - Extract text content
  - Detect embedded URLs
  - Invoice/document fraud detection

- **Video Analysis** (`type=video`)
  - Extract key frames
  - Extract audio track
  - Fuse image + audio analysis

#### API Security
- API token authentication (`X-API-Key` header)
- Rate limiting (configurable requests/window)
- Security headers (HSTS, XSS, etc.)
- CORS configuration

#### Confidence Scoring
- LLM confidence in responses
- Calibration based on heuristic agreement
- Agreement indicators

### Changed
- Standardized score scale to 0-10
- Risk level calculation with indicator overrides
- Environment names: `dev`/`prod` (was `development`/`production`)

---

## [0.1.0] - 2024-12-09

### Added

#### Core Analysis
- **Text Analysis** - Message and chat content
  - Heuristic scoring (keywords, urgency, crypto)
  - LLM-powered analysis
  - Combined scoring

- **URL Analysis** - Link checking
  - IP address detection
  - URL shortener detection
  - Brand impersonation (PayPal, etc.)
  - High-risk TLD detection
  - LLM pattern recognition

- **Audio Analysis** - Voice recordings
  - OpenAI Whisper transcription
  - Text pipeline on transcript

- **Image Analysis** - Screenshots
  - GPT-4o vision analysis
  - Fake login page detection
  - Scam invoice detection

- **Multi-Modal Fusion**
  - Weighted score combination
  - Cross-modality indicator aggregation

#### Infrastructure
- FastAPI application
- SQLAlchemy database
- Pydantic schemas
- Streamlit demo UI
- Basic test suite

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.3.0 | 2024-12-11 | Industry features: blacklists, A/B, explainability |
| 0.2.0 | 2024-12-10 | Email, PDF, Video; API security |
| 0.1.0 | 2024-12-09 | Initial release: text, URL, audio, image |


