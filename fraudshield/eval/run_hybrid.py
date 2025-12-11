# fraudshield/eval/run_hybrid.py
"""
CLI entry point for hybrid evaluation.

Usage:
    python -m fraudshield.eval.run_hybrid --dataset-dir datasets/fraudshield_dataset_large

    # Full evaluation with all features
    python -m fraudshield.eval.run_hybrid \
        --dataset-dir datasets/fraudshield_dataset_large \
        --enable-judge \
        --enable-adversarial \
        --output-dir eval_results \
        --run-name production_eval

    # Quick evaluation (metrics only)
    python -m fraudshield.eval.run_hybrid \
        --dataset-dir datasets/fraudshield_dataset_large \
        --no-judge \
        --no-adversarial
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from fraudshield.config import settings
from fraudshield.eval.hybrid_eval import HybridEvalConfig, HybridEvaluator


def main():
    parser = argparse.ArgumentParser(
        description="Run industry-standard hybrid evaluation of FraudShield.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic evaluation (uses settings from .env)
  python -m fraudshield.eval.run_hybrid

  # Quick metrics only (no LLM judge or adversarial)
  python -m fraudshield.eval.run_hybrid --no-judge --no-adversarial

  # Custom configuration
  python -m fraudshield.eval.run_hybrid \\
    --dataset-dir datasets/fraudshield_dataset_large \\
    --judge-sample-rate 0.2
        """,
    )
    
    # Dataset (now optional - uses settings)
    parser.add_argument(
        "--dataset-dir",
        type=str,
        default=None,
        help=f"Dataset directory (default: from .env or {settings.eval_dataset_dir}).",
    )
    
    # API configuration
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
        help="Environment variable containing API key.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30).",
    )
    
    # Dataset options
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
        "--max-samples",
        type=int,
        default=None,
        help="Maximum number of samples to evaluate.",
    )
    
    # Judge options
    parser.add_argument(
        "--enable-judge",
        action="store_true",
        default=True,
        help="Enable LLM-as-a-Judge evaluation (default: enabled).",
    )
    parser.add_argument(
        "--no-judge",
        action="store_true",
        help="Disable LLM-as-a-Judge evaluation.",
    )
    parser.add_argument(
        "--judge-model",
        type=str,
        default="gpt-4o-mini",
        help="OpenAI model for judge (default: gpt-4o-mini).",
    )
    parser.add_argument(
        "--judge-sample-rate",
        type=float,
        default=0.1,
        help="Fraction of samples to judge (default: 0.1 = 10%%).",
    )
    parser.add_argument(
        "--no-judge-errors",
        action="store_true",
        help="Don't automatically judge all FP/FN errors.",
    )
    
    # Adversarial options
    parser.add_argument(
        "--enable-adversarial",
        action="store_true",
        default=True,
        help="Enable adversarial testing (default: enabled).",
    )
    parser.add_argument(
        "--no-adversarial",
        action="store_true",
        help="Disable adversarial testing.",
    )
    parser.add_argument(
        "--adversarial-techniques",
        type=str,
        nargs="+",
        help="Specific adversarial techniques to test.",
    )
    parser.add_argument(
        "--adversarial-samples",
        type=int,
        default=5,
        help="Samples per adversarial technique (default: 5).",
    )
    
    # Output options
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help=f"Directory to save results (default: from .env or {settings.eval_output_dir}).",
    )
    parser.add_argument(
        "--run-name",
        type=str,
        default="hybrid_eval",
        help="Name for this evaluation run (default: hybrid_eval).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output.",
    )
    
    args = parser.parse_args()
    
    # Use settings as defaults
    dataset_dir_str = args.dataset_dir or settings.eval_dataset_dir
    output_dir_str = args.output_dir or settings.eval_output_dir
    include_benign = not args.no_benign and settings.eval_include_benign
    enable_judge = args.enable_judge and not args.no_judge and settings.eval_run_judge
    enable_adversarial = args.enable_adversarial and not args.no_adversarial and settings.eval_run_adversarial
    
    # Validate dataset directory
    dataset_dir = Path(dataset_dir_str).expanduser().resolve()
    if not dataset_dir.exists():
        raise SystemExit(f"❌ Dataset directory does not exist: {dataset_dir}")
    
    # Get API key from settings or env
    api_key = settings.openai_api_key or os.getenv(args.api_key_env) or None
    
    # Build configuration
    config = HybridEvalConfig(
        dataset_dir=dataset_dir,
        include_benign=include_benign,
        modalities=args.modalities,
        max_samples=args.max_samples,
        base_url=args.base_url,
        api_key=api_key,
        timeout=args.timeout,
        enable_judge=enable_judge,
        judge_model=args.judge_model,
        judge_sample_rate=args.judge_sample_rate,
        judge_all_errors=not args.no_judge_errors,
        enable_adversarial=enable_adversarial,
        adversarial_techniques=args.adversarial_techniques,
        adversarial_samples_per_technique=args.adversarial_samples,
        output_dir=Path(output_dir_str),
        run_name=args.run_name,
        quiet=args.quiet,
    )
    
    # Run evaluation
    evaluator = HybridEvaluator(config)
    report = evaluator.run()
    
    # Exit with appropriate code
    if report.overall_score >= 0.8:
        exit(0)  # Good
    elif report.overall_score >= 0.6:
        exit(0)  # Acceptable
    else:
        exit(1)  # Needs improvement


if __name__ == "__main__":
    main()

