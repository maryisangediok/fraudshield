# fraudshield/eval/run_eval.py
"""
Industry-standard evaluation script for FraudShield.

Features:
- ROC-AUC and PR-AUC metrics
- Per-modality breakdown (URL, SMS, Email)
- Latency tracking (p50, p95, p99)
- Progress bar with tqdm
- Results export (JSON + CSV)
- Threshold analysis
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import numpy as np
import requests
from tqdm import tqdm

try:
    from sklearn.metrics import (
        roc_auc_score,
        precision_recall_curve,
        auc,
        confusion_matrix,
        classification_report,
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[WARN] scikit-learn not installed. Some metrics will be unavailable.")

from fraudshield.config import settings
from fraudshield.eval.dataset_loader import iter_all_samples, get_dataset_stats


@dataclass
class EvalResult:
    """Result from a single API call."""
    id: str
    modality: str
    label: str
    predicted_risk: str
    overall_score: float
    indicators: List[str]
    latency_ms: float
    success: bool
    error: Optional[str] = None


@dataclass
class EvalMetrics:
    """Comprehensive evaluation metrics."""
    # Basic counts
    total: int = 0
    successful: int = 0
    failed: int = 0
    
    # Confusion matrix
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    
    # Classification metrics
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    
    # AUC metrics (require sklearn)
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    
    # Latency metrics (ms)
    latency_p50: Optional[float] = None
    latency_p95: Optional[float] = None
    latency_p99: Optional[float] = None
    latency_mean: Optional[float] = None
    latency_min: Optional[float] = None
    latency_max: Optional[float] = None
    
    # Per-modality breakdown
    by_modality: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Threshold analysis
    threshold_analysis: Dict[str, Dict[str, float]] = field(default_factory=dict)


def call_analyze(
    base_url: str,
    sample: Dict,
    api_key: Optional[str] = None,
    timeout: int = 30,
) -> EvalResult:
    """
    Call the FraudShield /analyze endpoint for a single sample.

    - URL samples  -> type='url',   url=<content>
    - Text samples -> type='text',  text=<content>
    """
    modality = sample["modality"]
    content = sample["content"]
    label = sample["label"]
    sample_id = str(sample["id"])

    # Determine payload type
    if modality == "url":
        data = {
            "type": "url",
            "text": "",
            "url": content,
            "source_hint": f"eval_{modality}",
        }
    else:
        data = {
            "type": "text",
            "text": content,
            "url": "",
            "source_hint": f"eval_{modality}",
        }
    
    files = {"file": (None, "")}
    headers = {"accept": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    start_time = time.perf_counter()
    
    try:
        resp = requests.post(
            f"{base_url.rstrip('/')}/analyze",
            data=data,
            files=files,
            headers=headers,
            timeout=timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        return EvalResult(
            id=sample_id,
            modality=modality,
            label=label,
            predicted_risk=body.get("risk_level", "UNKNOWN"),
            overall_score=float(body.get("overall_score", 0.0)),
            indicators=body.get("indicators", []),
            latency_ms=latency_ms,
            success=True,
            error=None,
        )
    except Exception as e:
        latency_ms = (time.perf_counter() - start_time) * 1000
        return EvalResult(
            id=sample_id,
            modality=modality,
            label=label,
            predicted_risk="ERROR",
            overall_score=0.0,
            indicators=[],
            latency_ms=latency_ms,
            success=False,
            error=str(e),
        )


def is_positive_label(label: str) -> bool:
    """Check if label indicates a positive (fraud/phishing) case."""
    label = (label or "").lower()
    return label in {"phishing", "scam", "fraud", "malicious", "spam"}


def is_positive_prediction(risk: str) -> bool:
    """Check if risk level indicates a positive prediction."""
    risk = (risk or "").upper()
    return risk in {"MEDIUM", "HIGH"}


def risk_to_score(risk: str) -> float:
    """Convert risk level to numeric score for AUC calculations."""
    risk = (risk or "").upper()
    mapping = {"LOW": 0.2, "MEDIUM": 0.6, "HIGH": 0.9, "UNKNOWN": 0.5, "ERROR": 0.5}
    return mapping.get(risk, 0.5)


def compute_metrics(results: List[EvalResult]) -> EvalMetrics:
    """Compute comprehensive evaluation metrics."""
    metrics = EvalMetrics()
    
    # Filter successful results
    successful_results = [r for r in results if r.success]
    failed_results = [r for r in results if not r.success]
    
    metrics.total = len(results)
    metrics.successful = len(successful_results)
    metrics.failed = len(failed_results)
    
    if not successful_results:
        return metrics
    
    # Compute confusion matrix components
    y_true = []
    y_pred = []
    y_scores = []
    
    for r in successful_results:
        gt_pos = is_positive_label(r.label)
        pred_pos = is_positive_prediction(r.predicted_risk)
        
        y_true.append(1 if gt_pos else 0)
        y_pred.append(1 if pred_pos else 0)
        y_scores.append(r.overall_score)
        
        if gt_pos and pred_pos:
            metrics.tp += 1
        elif not gt_pos and pred_pos:
            metrics.fp += 1
        elif not gt_pos and not pred_pos:
            metrics.tn += 1
        elif gt_pos and not pred_pos:
            metrics.fn += 1
    
    # Classification metrics
    total = metrics.tp + metrics.fp + metrics.tn + metrics.fn
    if total > 0:
        metrics.accuracy = (metrics.tp + metrics.tn) / total
    
    if metrics.tp + metrics.fp > 0:
        metrics.precision = metrics.tp / (metrics.tp + metrics.fp)
    
    if metrics.tp + metrics.fn > 0:
        metrics.recall = metrics.tp / (metrics.tp + metrics.fn)
    
    if metrics.precision and metrics.recall and (metrics.precision + metrics.recall) > 0:
        metrics.f1_score = 2 * (metrics.precision * metrics.recall) / (metrics.precision + metrics.recall)
    
    # AUC metrics (require sklearn and both classes present)
    if SKLEARN_AVAILABLE and len(set(y_true)) > 1:
        try:
            metrics.roc_auc = roc_auc_score(y_true, y_scores)
            precision_vals, recall_vals, _ = precision_recall_curve(y_true, y_scores)
            metrics.pr_auc = auc(recall_vals, precision_vals)
        except Exception:
            pass
    
    # Latency metrics
    latencies = [r.latency_ms for r in successful_results]
    if latencies:
        latencies_arr = np.array(latencies)
        metrics.latency_p50 = float(np.percentile(latencies_arr, 50))
        metrics.latency_p95 = float(np.percentile(latencies_arr, 95))
        metrics.latency_p99 = float(np.percentile(latencies_arr, 99))
        metrics.latency_mean = float(np.mean(latencies_arr))
        metrics.latency_min = float(np.min(latencies_arr))
        metrics.latency_max = float(np.max(latencies_arr))
    
    # Per-modality breakdown
    modalities = set(r.modality for r in successful_results)
    for modality in modalities:
        mod_results = [r for r in successful_results if r.modality == modality]
        mod_tp = sum(1 for r in mod_results if is_positive_label(r.label) and is_positive_prediction(r.predicted_risk))
        mod_fp = sum(1 for r in mod_results if not is_positive_label(r.label) and is_positive_prediction(r.predicted_risk))
        mod_tn = sum(1 for r in mod_results if not is_positive_label(r.label) and not is_positive_prediction(r.predicted_risk))
        mod_fn = sum(1 for r in mod_results if is_positive_label(r.label) and not is_positive_prediction(r.predicted_risk))
        
        mod_total = mod_tp + mod_fp + mod_tn + mod_fn
        mod_accuracy = (mod_tp + mod_tn) / mod_total if mod_total > 0 else None
        mod_precision = mod_tp / (mod_tp + mod_fp) if (mod_tp + mod_fp) > 0 else None
        mod_recall = mod_tp / (mod_tp + mod_fn) if (mod_tp + mod_fn) > 0 else None
        
        mod_latencies = [r.latency_ms for r in mod_results]
        
        metrics.by_modality[modality] = {
            "total": len(mod_results),
            "tp": mod_tp,
            "fp": mod_fp,
            "tn": mod_tn,
            "fn": mod_fn,
            "accuracy": mod_accuracy,
            "precision": mod_precision,
            "recall": mod_recall,
            "latency_p50": float(np.percentile(mod_latencies, 50)) if mod_latencies else None,
        }
    
    # Threshold analysis
    for threshold_name, threshold_val in [("strict", 0.7), ("balanced", 0.5), ("lenient", 0.3)]:
        t_tp = sum(1 for r, s in zip(successful_results, y_scores) if is_positive_label(r.label) and s >= threshold_val)
        t_fp = sum(1 for r, s in zip(successful_results, y_scores) if not is_positive_label(r.label) and s >= threshold_val)
        t_tn = sum(1 for r, s in zip(successful_results, y_scores) if not is_positive_label(r.label) and s < threshold_val)
        t_fn = sum(1 for r, s in zip(successful_results, y_scores) if is_positive_label(r.label) and s < threshold_val)
        
        t_total = t_tp + t_fp + t_tn + t_fn
        metrics.threshold_analysis[threshold_name] = {
            "threshold": threshold_val,
            "accuracy": (t_tp + t_tn) / t_total if t_total > 0 else 0,
            "precision": t_tp / (t_tp + t_fp) if (t_tp + t_fp) > 0 else 0,
            "recall": t_tp / (t_tp + t_fn) if (t_tp + t_fn) > 0 else 0,
        }
    
    return metrics


def save_results(
    results: List[EvalResult],
    metrics: EvalMetrics,
    output_dir: Path,
    run_name: str,
) -> Dict[str, Path]:
    """Save results to JSON and CSV files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{run_name}_{timestamp}"
    
    paths = {}
    
    # Save detailed results as JSON
    results_json_path = output_dir / f"{base_name}_results.json"
    with open(results_json_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    paths["results_json"] = results_json_path
    
    # Save metrics summary as JSON
    metrics_json_path = output_dir / f"{base_name}_metrics.json"
    with open(metrics_json_path, "w", encoding="utf-8") as f:
        json.dump(asdict(metrics), f, indent=2)
    paths["metrics_json"] = metrics_json_path
    
    # Save results as CSV
    results_csv_path = output_dir / f"{base_name}_results.csv"
    with open(results_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "id", "modality", "label", "predicted_risk", "overall_score",
            "latency_ms", "success", "error", "indicators"
        ])
        for r in results:
            writer.writerow([
                r.id, r.modality, r.label, r.predicted_risk, r.overall_score,
                r.latency_ms, r.success, r.error or "", "|".join(r.indicators)
            ])
    paths["results_csv"] = results_csv_path
    
    # Save metrics summary as CSV
    metrics_csv_path = output_dir / f"{base_name}_metrics.csv"
    with open(metrics_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["total", metrics.total])
        writer.writerow(["successful", metrics.successful])
        writer.writerow(["failed", metrics.failed])
        writer.writerow(["tp", metrics.tp])
        writer.writerow(["fp", metrics.fp])
        writer.writerow(["tn", metrics.tn])
        writer.writerow(["fn", metrics.fn])
        writer.writerow(["accuracy", metrics.accuracy])
        writer.writerow(["precision", metrics.precision])
        writer.writerow(["recall", metrics.recall])
        writer.writerow(["f1_score", metrics.f1_score])
        writer.writerow(["roc_auc", metrics.roc_auc])
        writer.writerow(["pr_auc", metrics.pr_auc])
        writer.writerow(["latency_p50_ms", metrics.latency_p50])
        writer.writerow(["latency_p95_ms", metrics.latency_p95])
        writer.writerow(["latency_p99_ms", metrics.latency_p99])
    paths["metrics_csv"] = metrics_csv_path
    
    return paths


def print_report(metrics: EvalMetrics, dataset_stats: Dict[str, Any]) -> None:
    """Print a comprehensive evaluation report."""
    print("\n" + "=" * 60)
    print("           FRAUDSHIELD EVALUATION REPORT")
    print("=" * 60)
    
    # Dataset info
    print("\n📊 DATASET STATISTICS")
    print("-" * 40)
    print(f"  Total samples:      {dataset_stats.get('total', 'N/A')}")
    for label, count in dataset_stats.get("by_label", {}).items():
        print(f"    - {label}: {count}")
    for modality, count in dataset_stats.get("by_modality", {}).items():
        print(f"    - {modality}: {count}")
    
    # Overall metrics
    print("\n📈 OVERALL METRICS")
    print("-" * 40)
    print(f"  Samples evaluated:  {metrics.total}")
    print(f"  Successful:         {metrics.successful}")
    print(f"  Failed:             {metrics.failed}")
    print()
    print(f"  TP: {metrics.tp:>5}  |  FP: {metrics.fp:>5}")
    print(f"  FN: {metrics.fn:>5}  |  TN: {metrics.tn:>5}")
    print()
    
    if metrics.accuracy is not None:
        print(f"  Accuracy:           {metrics.accuracy * 100:.2f}%")
    if metrics.precision is not None:
        print(f"  Precision:          {metrics.precision * 100:.2f}%")
    if metrics.recall is not None:
        print(f"  Recall:             {metrics.recall * 100:.2f}%")
    if metrics.f1_score is not None:
        print(f"  F1-Score:           {metrics.f1_score * 100:.2f}%")
    
    # AUC metrics
    if metrics.roc_auc is not None or metrics.pr_auc is not None:
        print("\n🎯 AUC METRICS")
        print("-" * 40)
        if metrics.roc_auc is not None:
            print(f"  ROC-AUC:            {metrics.roc_auc:.4f}")
        if metrics.pr_auc is not None:
            print(f"  PR-AUC:             {metrics.pr_auc:.4f}")
    
    # Latency metrics
    if metrics.latency_p50 is not None:
        print("\n⏱️  LATENCY METRICS")
        print("-" * 40)
        print(f"  p50 (median):       {metrics.latency_p50:.1f} ms")
        print(f"  p95:                {metrics.latency_p95:.1f} ms")
        print(f"  p99:                {metrics.latency_p99:.1f} ms")
        print(f"  Mean:               {metrics.latency_mean:.1f} ms")
        print(f"  Min:                {metrics.latency_min:.1f} ms")
        print(f"  Max:                {metrics.latency_max:.1f} ms")
    
    # Per-modality breakdown
    if metrics.by_modality:
        print("\n📋 PER-MODALITY BREAKDOWN")
        print("-" * 40)
        for modality, stats in metrics.by_modality.items():
            acc_str = f"{stats['accuracy'] * 100:.1f}%" if stats['accuracy'] is not None else "N/A"
            prec_str = f"{stats['precision'] * 100:.1f}%" if stats['precision'] is not None else "N/A"
            rec_str = f"{stats['recall'] * 100:.1f}%" if stats['recall'] is not None else "N/A"
            lat_str = f"{stats['latency_p50']:.0f}ms" if stats['latency_p50'] is not None else "N/A"
            
            print(f"  {modality.upper():>8}: n={stats['total']:>4} | "
                  f"Acc={acc_str:>6} | Prec={prec_str:>6} | Rec={rec_str:>6} | p50={lat_str}")
    
    # Threshold analysis
    if metrics.threshold_analysis:
        print("\n🎚️  THRESHOLD ANALYSIS")
        print("-" * 40)
        for name, stats in metrics.threshold_analysis.items():
            print(f"  {name.capitalize():>10} (≥{stats['threshold']:.1f}): "
                  f"Acc={stats['accuracy'] * 100:.1f}% | "
                  f"Prec={stats['precision'] * 100:.1f}% | "
                  f"Rec={stats['recall'] * 100:.1f}%")
    
    print("\n" + "=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Run industry-standard evaluation of FraudShield /analyze endpoint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic evaluation (uses settings from .env)
  python -m fraudshield.eval.run_eval

  # With custom dataset
  python -m fraudshield.eval.run_eval --dataset-dir datasets/fraudshield_dataset_large
    
  # Only phishing samples (no benign)
  python -m fraudshield.eval.run_eval --no-benign
        """,
    )
    parser.add_argument(
        "--dataset-dir",
        type=str,
        default=None,
        help=f"Path to dataset directory (default: from .env or {settings.eval_dataset_dir}).",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default="http://127.0.0.1:8000",
        help="Base URL of FraudShield API (default: http://127.0.0.1:8000).",
    )
    parser.add_argument(
        "--api-key-env",
        type=str,
        default="FRAUDSHIELD_API_KEY",
        help="Environment variable containing API key (default: FRAUDSHIELD_API_KEY).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help=f"Directory to save results (default: from .env or {settings.eval_output_dir}).",
    )
    parser.add_argument(
        "--run-name",
        type=str,
        default="eval",
        help="Name for this evaluation run (default: eval).",
    )
    parser.add_argument(
        "--no-benign",
        action="store_true",
        help="Exclude benign samples from evaluation.",
    )
    parser.add_argument(
        "--modalities",
        type=str,
        nargs="+",
        choices=["url", "sms", "email"],
        help="Modalities to evaluate (default: all).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum number of samples to evaluate (default: all).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress bar and verbose output.",
    )

    args = parser.parse_args()

    # Use settings as defaults
    dataset_dir_str = args.dataset_dir or settings.eval_dataset_dir
    output_dir_str = args.output_dir or settings.eval_output_dir
    
    # Validate dataset directory
    dataset_dir = Path(dataset_dir_str).expanduser().resolve()
    if not dataset_dir.exists():
        raise SystemExit(f"❌ Dataset directory does not exist: {dataset_dir}")

    # Get API key from settings or env
    api_key = settings.openai_api_key or os.getenv(args.api_key_env) or None

    # Print configuration
    if not args.quiet:
        print("\n🔧 CONFIGURATION")
        print("-" * 40)
        print(f"  Dataset:    {dataset_dir}")
        print(f"  API URL:    {args.base_url}")
        print(f"  API Key:    {'✓ Set' if api_key else '✗ Not set (dev mode)'}")
        print(f"  Output:     {output_dir_str}")
        print(f"  Benign:     {'Excluded' if args.no_benign else 'Included'}")
        print(f"  Modalities: {args.modalities or 'All'}")

    # Get dataset stats
    include_benign = not args.no_benign
    dataset_stats = get_dataset_stats(dataset_dir, include_benign)
    
    if dataset_stats["total"] == 0:
        raise SystemExit("❌ No samples found in dataset.")

    # Collect samples
    samples = list(iter_all_samples(dataset_dir, include_benign, args.modalities))
    
    if args.max_samples:
        samples = samples[:args.max_samples]

    if not args.quiet:
        print(f"\n📂 Loading {len(samples)} samples...")

    # Run evaluation
    results: List[EvalResult] = []
    
    iterator = samples
    if not args.quiet:
        iterator = tqdm(samples, desc="Evaluating", unit="sample")
    
    for sample in iterator:
        result = call_analyze(
            base_url=args.base_url,
            sample=sample,
            api_key=api_key,
            timeout=args.timeout,
        )
        results.append(result)

    # Compute metrics
    metrics = compute_metrics(results)

    # Print report
    print_report(metrics, dataset_stats)

    # Save results
    output_dir = Path(output_dir_str)
    saved_paths = save_results(results, metrics, output_dir, args.run_name)
    
    print("💾 RESULTS SAVED")
    print("-" * 40)
    for name, path in saved_paths.items():
        print(f"  {name}: {path}")
    print()


if __name__ == "__main__":
    main()
