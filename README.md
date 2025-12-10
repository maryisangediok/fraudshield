# FraudShield

FraudShield is a multimodal AI safety system for detecting fraud across **text**, **URLs**, **audio**, and **video**.

This repository currently includes:
- A FastAPI backend with a unified `/analyze` endpoint
- A pluggable service layer for each modality
- A simple risk fusion service
- SQLAlchemy model for anonymized analysis logs
- Utilities and pipelines scaffolding for future models

## Features (MVP)
- `/health` endpoint to verify service status
- `/analyze` endpoint supporting:
  - `type=text`  + `text=...`
  - `type=link`  + `url=...`
  - `type=audio` + `file=<upload>`
  - `type=video` + `file=<upload>`
- Returns:
  - `risk_level`: LOW / MEDIUM / HIGH
  - `overall_score`: float
  - `modality_scores`: per-modality score
  - `indicators`: list of reason codes
  - `explanation`: human-readable summary

> NOTE: All modality services are currently stubbed with placeholder logic. This is intentional so you can plug in real models incrementally.

## Quickstart

```bash
pip install -r requirements.txt
uvicorn fraudshield.api.server:app --reload
```

Then open: http://127.0.0.1:8000/docs
