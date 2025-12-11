# fraudshield/eval/run_comprehensive.py
"""
Comprehensive evaluation CLI with ALL metrics.

This is the ultimate evaluation script that includes:
- Traditional metrics (P/R/F1/AUC)
- LLM-as-a-Judge (explanation quality)
- Adversarial testing (robustness)
- Advanced metrics (calibration, cost-sensitive, CI)
- Business impact (dollar values, ROI)
- Temporal analysis (drift detection)

Usage:
    python -m fraudshield.eval.run_comprehensive \\
        --dataset-dir datasets/fraudshield_dataset_large
"""

from __future__ import annotations

import argparse
import json
import os
import time

from fraudshield.config import settings
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import numpy as np
import requests
from tqdm import tqdm

from fraudshield.eval.dataset_loader import iter_all_samples, get_dataset_stats
from fraudshield.eval.run_eval import (
    EvalResult,
    call_analyze,
    compute_metrics,
    is_positive_label,
    is_positive_prediction,
)
from fraudshield.eval.advanced_metrics import (
    compute_all_advanced_metrics,
    AdvancedMetricsReport,
)
from fraudshield.eval.business_metrics import (
    FraudValueConfig,
    compute_business_impact,
    print_business_report,
    BusinessReport,
)
from fraudshield.eval.temporal_metrics import (
    TemporalAnalyzer,
    print_temporal_report,
    TemporalReport,
)

# Optional imports
try:
    from fraudshield.eval.llm_judge import LLMJudge, aggregate_judge_results, JudgeReport
    LLM_JUDGE_AVAILABLE = True
except ImportError:
    LLM_JUDGE_AVAILABLE = False

try:
    from fraudshield.eval.adversarial import (
        AdversarialGenerator,
        AdversarialTestResult,
        aggregate_adversarial_results,
        AdversarialReport,
    )
    ADVERSARIAL_AVAILABLE = True
except ImportError:
    ADVERSARIAL_AVAILABLE = False


@dataclass
class ComprehensiveConfig:
    """Configuration for comprehensive evaluation."""
    
    # Dataset
    dataset_dir: Path = None
    include_benign: bool = True
    modalities: Optional[List[str]] = None
    max_samples: Optional[int] = None
    
    # API
    base_url: str = "http://127.0.0.1:8000"
    api_key: Optional[str] = None
    timeout: int = 30
    
    # Components to run
    run_traditional: bool = True
    run_advanced: bool = True
    run_business: bool = True
    run_temporal: bool = True
    run_judge: bool = True
    run_adversarial: bool = True
    
    # LLM Judge config
    judge_model: str = "gpt-4o-mini"
    judge_sample_rate: float = 0.1
    
    # Adversarial config
    adversarial_samples_per_technique: int = 5
    
    # Business config
    avg_fraud_amount: float = 500.0
    fn_cost: float = 100.0
    fp_cost: float = 10.0
    
    # Output
    output_dir: Path = Path("eval_results")
    run_name: str = "comprehensive"
    quiet: bool = False


@dataclass
class ComprehensiveReport:
    """Complete evaluation report with all metrics."""
    
    # Metadata
    run_name: str = ""
    timestamp: str = ""
    duration_seconds: float = 0.0
    
    # Dataset stats
    dataset_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Traditional metrics
    traditional_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Advanced metrics
    advanced_metrics: Optional[AdvancedMetricsReport] = None
    
    # Business impact
    business_report: Optional[BusinessReport] = None
    
    # Temporal analysis
    temporal_report: Optional[TemporalReport] = None
    
    # LLM Judge (if enabled)
    judge_report: Optional[JudgeReport] = None
    
    # Adversarial (if enabled)
    adversarial_report: Optional[AdversarialReport] = None
    
    # Overall scores (0-100)
    scores: Dict[str, float] = field(default_factory=dict)
    
    # Key recommendations
    recommendations: List[str] = field(default_factory=list)


def run_comprehensive_eval(config: ComprehensiveConfig) -> ComprehensiveReport:
    """Run comprehensive evaluation with all metrics."""
    
    start_time = time.time()
    report = ComprehensiveReport(
        run_name=config.run_name,
        timestamp=datetime.now().isoformat(),
    )
    
    # Print header
    if not config.quiet:
        print("\n" + "=" * 70)
        print("         COMPREHENSIVE FRAUDSHIELD EVALUATION")
        print("=" * 70)
        print(f"\n  Dataset: {config.dataset_dir}")
        print(f"  API: {config.base_url}")
    
    # Get dataset stats
    report.dataset_stats = get_dataset_stats(config.dataset_dir, config.include_benign)
    
    if not config.quiet:
        print(f"  Samples: {report.dataset_stats.get('total', 0)}")
        print()
    
    # Phase 1: Run traditional evaluation
    if not config.quiet:
        print("📊 Phase 1: Traditional Metrics")
        print("-" * 50)
    
    results, y_true, y_pred, y_scores = _run_api_evaluation(config)
    
    if config.run_traditional:
        traditional = compute_metrics(results)
        report.traditional_metrics = asdict(traditional)
        
        if not config.quiet:
            _print_traditional_summary(traditional)
    
    # Phase 2: Advanced metrics
    if config.run_advanced and len(y_true) > 0:
        if not config.quiet:
            print("\n🔬 Phase 2: Advanced Metrics")
            print("-" * 50)
        
        report.advanced_metrics = compute_all_advanced_metrics(
            y_true=np.array(y_true),
            y_scores=np.array(y_scores),
            y_pred=np.array(y_pred),
            fn_cost=config.fn_cost,
            fp_cost=config.fp_cost,
        )
        
        if not config.quiet:
            _print_advanced_summary(report.advanced_metrics)
    
    # Phase 3: Business impact
    if config.run_business and len(y_true) > 0:
        if not config.quiet:
            print("\n💰 Phase 3: Business Impact")
            print("-" * 50)
        
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        
        business_config = FraudValueConfig(
            avg_fraud_amount=config.avg_fraud_amount,
        )
        
        report.business_report = compute_business_impact(
            tp=tp, fp=fp, tn=tn, fn=fn,
            config=business_config,
            avg_latency_ms=report.traditional_metrics.get("latency_mean", 100),
        )
        
        if not config.quiet:
            _print_business_summary(report.business_report)
    
    # Phase 4: Temporal analysis
    if config.run_temporal and len(y_true) > 10:
        if not config.quiet:
            print("\n📈 Phase 4: Temporal Analysis")
            print("-" * 50)
        
        analyzer = TemporalAnalyzer()
        report.temporal_report = analyzer.analyze(
            y_true=np.array(y_true),
            y_pred=np.array(y_pred),
            y_scores=np.array(y_scores),
            n_windows=min(10, len(y_true) // 50),
        )
        
        if not config.quiet:
            _print_temporal_summary(report.temporal_report)
    
    # Phase 5: LLM Judge (optional)
    if config.run_judge and LLM_JUDGE_AVAILABLE:
        if not config.quiet:
            print("\n🧑‍⚖️ Phase 5: LLM Judge")
            print("-" * 50)
        
        try:
            # Use API key from settings (loaded from .env via pydantic-settings)
            api_key = settings.openai_api_key or os.getenv("OPENAI_API_KEY")
            judge = LLMJudge(model=config.judge_model, api_key=api_key)
            report.judge_report = _run_judge_evaluation(
                judge, results, config.judge_sample_rate, config.quiet
            )
            
            if not config.quiet and report.judge_report:
                _print_judge_summary(report.judge_report)
        except Exception as e:
            if not config.quiet:
                print(f"  ⚠️ Judge evaluation failed: {e}")
    
    # Phase 6: Adversarial testing (optional)
    if config.run_adversarial and ADVERSARIAL_AVAILABLE:
        if not config.quiet:
            print("\n⚔️ Phase 6: Adversarial Testing")
            print("-" * 50)
        
        try:
            report.adversarial_report = _run_adversarial_evaluation(
                config, results, config.quiet
            )
            
            if not config.quiet and report.adversarial_report:
                _print_adversarial_summary(report.adversarial_report)
        except Exception as e:
            if not config.quiet:
                print(f"  ⚠️ Adversarial evaluation failed: {e}")
    
    # Calculate overall scores
    report.scores = _calculate_overall_scores(report)
    
    # Generate recommendations
    report.recommendations = _generate_recommendations(report)
    
    # Record duration
    report.duration_seconds = time.time() - start_time
    
    # Save report
    output_path = _save_comprehensive_report(report, config)
    
    # Print final summary
    if not config.quiet:
        _print_final_summary(report, output_path)
    
    return report


def _run_api_evaluation(config: ComprehensiveConfig):
    """Run API evaluation and collect results."""
    samples = list(iter_all_samples(
        config.dataset_dir,
        config.include_benign,
        config.modalities,
    ))
    
    if config.max_samples:
        samples = samples[:config.max_samples]
    
    results = []
    y_true = []
    y_pred = []
    y_scores = []
    
    iterator = samples
    if not config.quiet:
        iterator = tqdm(samples, desc="  Evaluating", unit="sample")
    
    for sample in iterator:
        result = call_analyze(
            base_url=config.base_url,
            sample=sample,
            api_key=config.api_key,
            timeout=config.timeout,
        )
        result._content = sample.get("content", "")
        results.append(result)
        
        if result.success:
            y_true.append(1 if is_positive_label(result.label) else 0)
            y_pred.append(1 if is_positive_prediction(result.predicted_risk) else 0)
            y_scores.append(result.overall_score)
    
    return results, y_true, y_pred, y_scores


def _run_judge_evaluation(judge, results, sample_rate, quiet):
    """Run LLM judge evaluation."""
    import random
    
    # Sample results
    successful = [r for r in results if r.success]
    sample_size = int(len(successful) * sample_rate)
    sampled = random.sample(successful, min(sample_size, len(successful)))
    
    quality_scores = []
    error_analyses = []
    
    iterator = sampled
    if not quiet:
        iterator = tqdm(sampled, desc="  Judging", unit="sample")
    
    for result in iterator:
        content = getattr(result, '_content', f"Sample {result.id}")
        gt_pos = is_positive_label(result.label)
        pred_pos = is_positive_prediction(result.predicted_risk)
        is_correct = gt_pos == pred_pos
        
        score = judge.evaluate_quality(
            sample_id=result.id,
            content=content,
            content_type=result.modality,
            risk_level=result.predicted_risk,
            score=result.overall_score,
            indicators=result.indicators,
            ground_truth=result.label,
            is_correct=is_correct,
        )
        quality_scores.append(score)
    
    return aggregate_judge_results(quality_scores, error_analyses)


def _run_adversarial_evaluation(config, results, quiet):
    """Run adversarial testing."""
    generator = AdversarialGenerator(use_llm=False)  # Start without LLM
    
    # Get phishing samples
    phishing_samples = [
        {"id": r.id, "content": getattr(r, '_content', ''), "modality": r.modality}
        for r in results
        if is_positive_label(r.label) and r.success
    ][:30]
    
    if not phishing_samples:
        return None
    
    # Generate adversarial samples
    adv_samples = generator.generate_batch(
        samples=phishing_samples,
        techniques=["homoglyph_substitution", "zero_width_injection", "url_encoding"],
        samples_per_technique=config.adversarial_samples_per_technique,
    )
    
    # Test them
    test_results = []
    
    iterator = adv_samples
    if not quiet:
        iterator = tqdm(adv_samples, desc="  Testing", unit="sample")
    
    for adv_sample in iterator:
        sample = {
            "id": f"adv_{adv_sample.original_id}",
            "modality": adv_sample.modality,
            "content": adv_sample.adversarial_content,
            "label": "phishing",
        }
        
        try:
            result = call_analyze(
                base_url=config.base_url,
                sample=sample,
                api_key=config.api_key,
                timeout=config.timeout,
            )
            
            detected = is_positive_prediction(result.predicted_risk)
            
            test_results.append(AdversarialTestResult(
                sample=adv_sample,
                detected=detected,
                risk_level=result.predicted_risk,
                score=result.overall_score,
                indicators=result.indicators,
                evasion_successful=not detected,
            ))
        except:
            pass
    
    return aggregate_adversarial_results(test_results)


def _calculate_overall_scores(report: ComprehensiveReport) -> Dict[str, float]:
    """Calculate overall scores (0-100 scale)."""
    scores = {}
    
    # Detection score (from traditional metrics)
    if report.traditional_metrics:
        f1 = report.traditional_metrics.get("f1_score") or 0
        auc = report.traditional_metrics.get("roc_auc") or f1  # Use F1 as fallback if no AUC
        recall = report.traditional_metrics.get("recall") or 0
        
        # Weight recall heavily for fraud detection (values are 0-1, convert to 0-100)
        scores["detection"] = min(100, (f1 * 0.3 + auc * 0.3 + recall * 0.4) * 100)
    
    # Calibration score
    if report.advanced_metrics:
        ece = report.advanced_metrics.calibration.expected_calibration_error
        scores["calibration"] = max(0, (1 - ece * 5)) * 100  # ECE of 0.2 = 0 score
    
    # Business score (positive ROI = good, cap at 100)
    if report.business_report:
        roi = report.business_report.impact.roi_percentage
        # ROI > 100% = score 100, ROI = 0 = score 50, negative ROI = score < 50
        scores["business"] = min(100, max(0, 50 + min(roi, 100) / 2))
    
    # Quality score (from judge)
    if report.judge_report and report.judge_report.avg_overall_quality > 0:
        scores["quality"] = (report.judge_report.avg_overall_quality / 5) * 100
    
    # Robustness score (from adversarial)
    if report.adversarial_report and report.adversarial_report.total_samples > 0:
        scores["robustness"] = (1 - report.adversarial_report.evasion_rate) * 100
    
    # Stability score (from temporal)
    if report.temporal_report:
        staleness = report.temporal_report.model_staleness_score
        scores["stability"] = (1 - staleness) * 100
    
    # Overall weighted score
    weights = {
        "detection": 0.35,
        "calibration": 0.15,
        "business": 0.20,
        "quality": 0.10,
        "robustness": 0.10,
        "stability": 0.10,
    }
    
    total_weight = sum(weights.get(k, 0) for k in scores.keys())
    if total_weight > 0:
        scores["overall"] = sum(
            scores[k] * weights.get(k, 0) for k in scores.keys()
        ) / total_weight
    
    return scores


def _generate_recommendations(report: ComprehensiveReport) -> List[str]:
    """Generate recommendations from all components."""
    recs = []
    
    # From traditional metrics
    if report.traditional_metrics:
        recall = report.traditional_metrics.get("recall", 0)
        precision = report.traditional_metrics.get("precision", 0)
        
        if recall and recall < 0.9:
            recs.append(f"🔴 Recall is {recall*100:.1f}% - lower threshold to catch more fraud")
        if precision and precision < 0.5:
            recs.append(f"⚠️ Precision is {precision*100:.1f}% - too many false alarms")
    
    # From advanced metrics
    if report.advanced_metrics:
        if report.advanced_metrics.calibration.expected_calibration_error > 0.1:
            recs.append("📊 Poor calibration - consider Platt scaling")
        
        if report.advanced_metrics.threshold_analysis.optimal_f1_threshold != 0.5:
            opt = report.advanced_metrics.threshold_analysis.optimal_f1_threshold
            recs.append(f"🎚️ Optimal threshold is {opt:.2f}, not 0.5")
    
    # From business
    if report.business_report:
        if report.business_report.impact.net_savings < 0:
            recs.append("💰 Negative ROI - system costs more than it saves")
        
        for rec in report.business_report.recommendations[:2]:
            recs.append(rec)
    
    # From temporal
    if report.temporal_report and report.temporal_report.recommended_retrain:
        recs.append("🔄 Model drift detected - consider retraining")
    
    # From adversarial
    if report.adversarial_report and report.adversarial_report.evasion_rate > 0.2:
        recs.append(f"⚔️ {report.adversarial_report.evasion_rate*100:.0f}% evasion rate - improve robustness")
    
    return recs[:10]  # Top 10


def _print_traditional_summary(metrics):
    """Print traditional metrics summary."""
    print(f"  Accuracy:   {metrics.accuracy*100:.1f}%" if metrics.accuracy else "  Accuracy: N/A")
    print(f"  Precision:  {metrics.precision*100:.1f}%" if metrics.precision else "  Precision: N/A")
    print(f"  Recall:     {metrics.recall*100:.1f}%" if metrics.recall else "  Recall: N/A")
    print(f"  F1 Score:   {metrics.f1_score*100:.1f}%" if metrics.f1_score else "  F1: N/A")
    print(f"  ROC-AUC:    {metrics.roc_auc:.4f}" if metrics.roc_auc else "  ROC-AUC: N/A")


def _print_advanced_summary(metrics: AdvancedMetricsReport):
    """Print advanced metrics summary."""
    print(f"  ECE (calibration):     {metrics.calibration.expected_calibration_error:.4f}")
    print(f"  Brier Score:           {metrics.calibration.brier_score:.4f}")
    print(f"  Score Separation:      {metrics.score_distribution.score_separation:.2f}")
    print(f"  Optimal Threshold:     {metrics.threshold_analysis.optimal_f1_threshold:.2f}")
    print(f"  F1 at 95% Recall:      {metrics.threshold_analysis.precision_at_95_recall*100:.1f}% precision")


def _print_business_summary(report: BusinessReport):
    """Print business metrics summary."""
    print(f"  Fraud Blocked:         ${report.impact.fraud_blocked_value:,.0f}")
    print(f"  Fraud Missed:          ${report.impact.fraud_missed_value:,.0f}")
    print(f"  Total FP Cost:         ${report.impact.total_fp_cost:,.0f}")
    print(f"  Net Savings:           ${report.impact.net_savings:,.0f}")
    print(f"  ROI:                   {report.impact.roi_percentage:.1f}%")


def _print_temporal_summary(report: TemporalReport):
    """Print temporal metrics summary."""
    print(f"  Accuracy Trend:        {report.accuracy_trend}")
    print(f"  Recall Trend:          {report.recall_trend}")
    print(f"  Drift Detected:        {'Yes ⚠️' if report.drift_result.drift_detected else 'No ✅'}")
    print(f"  Staleness Score:       {report.model_staleness_score*100:.1f}%")
    print(f"  Retrain Recommended:   {'Yes' if report.recommended_retrain else 'No'}")


def _print_judge_summary(report):
    """Print judge summary."""
    print(f"  Samples Judged:        {report.successful_evaluations}")
    print(f"  Avg Explanation:       {report.avg_explanation_quality:.1f}/5")
    print(f"  Avg Relevance:         {report.avg_indicator_relevance:.1f}/5")
    print(f"  Avg User-Friendly:     {report.avg_user_friendliness:.1f}/5")


def _print_adversarial_summary(report):
    """Print adversarial summary."""
    print(f"  Samples Tested:        {report.total_samples}")
    print(f"  Detection Rate:        {(1-report.evasion_rate)*100:.1f}%")
    print(f"  Evasion Rate:          {report.evasion_rate*100:.1f}%")


def _save_comprehensive_report(report: ComprehensiveReport, config: ComprehensiveConfig) -> Path:
    """Save the comprehensive report."""
    config.output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{config.run_name}_{timestamp}_comprehensive.json"
    output_path = config.output_dir / filename
    
    # Convert to serializable format
    report_dict = {
        "run_name": report.run_name,
        "timestamp": report.timestamp,
        "duration_seconds": report.duration_seconds,
        "dataset_stats": report.dataset_stats,
        "traditional_metrics": report.traditional_metrics,
        "scores": report.scores,
        "recommendations": report.recommendations,
    }
    
    if report.advanced_metrics:
        report_dict["advanced_metrics"] = asdict(report.advanced_metrics)
    
    if report.business_report:
        report_dict["business_metrics"] = asdict(report.business_report.impact)
    
    if report.temporal_report:
        report_dict["temporal_metrics"] = {
            "accuracy_trend": report.temporal_report.accuracy_trend,
            "drift_detected": report.temporal_report.drift_result.drift_detected,
            "staleness_score": report.temporal_report.model_staleness_score,
        }
    
    with open(output_path, "w") as f:
        json.dump(report_dict, f, indent=2, default=str)
    
    return output_path


def _print_final_summary(report: ComprehensiveReport, output_path: Path):
    """Print final summary."""
    print("\n" + "=" * 70)
    print("                    EVALUATION COMPLETE")
    print("=" * 70)
    
    print("\n🏆 OVERALL SCORES (0-100)")
    print("-" * 50)
    
    for name, score in sorted(report.scores.items(), key=lambda x: -x[1] if x[0] != "overall" else 0):
        # Cap score at 100 for display
        display_score = min(100, max(0, score))
        bar_len = int(display_score / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        
        if name == "overall":
            print(f"\n  {'OVERALL':<15} {bar} {display_score:.1f}")
        else:
            print(f"  {name:<15} {bar} {display_score:.1f}")
    
    if report.recommendations:
        print("\n📋 TOP RECOMMENDATIONS")
        print("-" * 50)
        for rec in report.recommendations[:5]:
            print(f"  {rec}")
    
    print(f"\n💾 Report saved to: {output_path}")
    print(f"⏱️  Duration: {report.duration_seconds:.1f} seconds")
    print("\n" + "=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Run comprehensive FraudShield evaluation with ALL metrics.",
    )
    
    # All args now have defaults from settings - can run with no args!
    parser.add_argument("--dataset-dir", type=str, default=None,
                        help=f"Dataset directory (default: from .env or {settings.eval_dataset_dir})")
    parser.add_argument("--base-url", type=str, default="http://127.0.0.1:8000")
    parser.add_argument("--output-dir", type=str, default=None,
                        help=f"Output directory (default: {settings.eval_output_dir})")
    parser.add_argument("--run-name", type=str, default="comprehensive")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Max samples to evaluate (default: all)")
    parser.add_argument("--no-benign", action="store_true",
                        help="Exclude benign samples")
    parser.add_argument("--no-judge", action="store_true",
                        help="Skip LLM judge evaluation")
    parser.add_argument("--no-adversarial", action="store_true",
                        help="Skip adversarial testing")
    parser.add_argument("--avg-fraud-amount", type=float, default=500.0,
                        help="Average fraud amount for business metrics")
    parser.add_argument("--quiet", action="store_true",
                        help="Minimal output")
    
    args = parser.parse_args()
    
    # Use settings as defaults, CLI args override
    dataset_dir = args.dataset_dir or settings.eval_dataset_dir
    output_dir = args.output_dir or settings.eval_output_dir
    max_samples = args.max_samples or (settings.eval_max_samples if settings.eval_max_samples > 0 else None)
    include_benign = not args.no_benign and settings.eval_include_benign
    run_judge = not args.no_judge and settings.eval_run_judge
    run_adversarial = not args.no_adversarial and settings.eval_run_adversarial
    
    config = ComprehensiveConfig(
        dataset_dir=Path(dataset_dir),
        base_url=args.base_url,
        output_dir=Path(output_dir),
        run_name=args.run_name,
        max_samples=max_samples,
        include_benign=include_benign,
        run_judge=run_judge,
        run_adversarial=run_adversarial,
        avg_fraud_amount=args.avg_fraud_amount,
        quiet=args.quiet,
    )
    
    api_key = settings.openai_api_key or os.getenv("OPENAI_API_KEY")
    if api_key:
        config.api_key = api_key
    
    report = run_comprehensive_eval(config)
    
    # Exit code based on overall score
    if report.scores.get("overall", 0) >= 70:
        exit(0)
    else:
        exit(1)


if __name__ == "__main__":
    main()

