# fraudshield/eval/train_calibrator.py
"""
Train score calibrator on evaluation results.

Usage:
    # Uses dataset from .env (EVAL_DATASET_DIR)
    python -m fraudshield.eval.train_calibrator
    
    # Or specify explicitly
    python -m fraudshield.eval.train_calibrator \
        --dataset-dir datasets/fraudshield_dataset_large
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from tqdm import tqdm

from fraudshield.config import settings
from fraudshield.services.calibration_service import ScoreCalibrator


def train_from_dataset(
    dataset_dir: Path,
    base_url: str = "http://127.0.0.1:8000",
    output_path: Path = None,
) -> ScoreCalibrator:
    """Train calibrator by running evaluation on dataset."""
    from fraudshield.eval.dataset_loader import iter_all_samples
    from fraudshield.eval.run_eval import call_analyze, is_positive_label
    
    if output_path is None:
        output_path = Path(settings.calibration_file)
    
    print(f"📊 Loading samples from {dataset_dir}...")
    samples = list(iter_all_samples(dataset_dir, include_benign=settings.eval_include_benign))
    
    print(f"🔄 Evaluating {len(samples)} samples...")
    y_true = []
    y_scores = []
    
    for sample in tqdm(samples, desc="  Collecting scores"):
        result = call_analyze(base_url, sample)
        if result.success:
            y_true.append(1 if is_positive_label(result.label) else 0)
            y_scores.append(result.overall_score)
    
    print(f"\n📈 Training calibrator on {len(y_true)} samples...")
    calibrator = ScoreCalibrator()
    calibrator.fit(np.array(y_true), np.array(y_scores), method="platt")
    
    # Save
    output_path.parent.mkdir(parents=True, exist_ok=True)
    calibrator.save(output_path)
    
    # Print diagnostics
    diag = calibrator.get_diagnostics()
    print(f"\n✅ Calibrator trained and saved to {output_path}")
    print(f"   Method: {diag['method']}")
    print(f"   ECE before: {diag['ece_before']:.4f}")
    print(f"   ECE after:  {diag['ece_after']:.4f}")
    print(f"   Improvement: {diag['improvement']*100:.1f}%")
    
    return calibrator


def main():
    parser = argparse.ArgumentParser(description="Train score calibrator")
    parser.add_argument("--dataset-dir", type=str, default=None,
                        help=f"Dataset directory (default: from .env)")
    parser.add_argument("--base-url", type=str, default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=str, default=None,
                        help=f"Output file (default: {settings.calibration_file})")
    parser.add_argument("--method", type=str, default="platt", choices=["platt", "isotonic"])
    
    args = parser.parse_args()
    
    # Use settings as defaults
    dataset_dir = args.dataset_dir or settings.eval_dataset_dir
    output_path = args.output or settings.calibration_file
    
    train_from_dataset(
        Path(dataset_dir),
        args.base_url,
        Path(output_path),
    )


if __name__ == "__main__":
    main()

