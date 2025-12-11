# fraudshield/eval/hybrid_eval.py
"""
Hybrid evaluation combining traditional metrics with LLM-as-a-Judge.

This is the industry-standard approach for fraud detection evaluation:
1. Primary: Traditional classification metrics (precision, recall, AUC)
2. Secondary: LLM judge for explanation quality
3. Tertiary: Adversarial robustness testing
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import requests
from tqdm import tqdm

from fraudshield.eval.dataset_loader import iter_all_samples, get_dataset_stats
from fraudshield.eval.run_eval import (
    EvalResult,
    EvalMetrics,
    call_analyze,
    compute_metrics,
    is_positive_label,
    is_positive_prediction,
)
from fraudshield.eval.llm_judge import (
    LLMJudge,
    JudgeScores,
    FPFNAnalysis,
    JudgeReport,
    aggregate_judge_results,
)
from fraudshield.eval.adversarial import (
    AdversarialGenerator,
    AdversarialSample,
    AdversarialTestResult,
    AdversarialReport,
    aggregate_adversarial_results,
)


@dataclass
class HybridEvalConfig:
    """Configuration for hybrid evaluation."""
    # Dataset
    dataset_dir: Path = None
    include_benign: bool = True
    modalities: Optional[List[str]] = None
    max_samples: Optional[int] = None
    
    # API
    base_url: str = "http://127.0.0.1:8000"
    api_key: Optional[str] = None
    timeout: int = 30
    
    # LLM Judge
    enable_judge: bool = True
    judge_model: str = "gpt-4o-mini"
    judge_sample_rate: float = 0.1  # Judge 10% of samples
    judge_all_errors: bool = True  # Always judge FP/FN
    
    # Adversarial Testing
    enable_adversarial: bool = True
    adversarial_techniques: Optional[List[str]] = None
    adversarial_samples_per_technique: int = 5
    
    # Output
    output_dir: Path = Path("eval_results")
    run_name: str = "hybrid_eval"
    quiet: bool = False


@dataclass
class HybridEvalReport:
    """Complete hybrid evaluation report."""
    # Metadata
    run_name: str = ""
    timestamp: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Dataset stats
    dataset_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Traditional metrics
    metrics: Optional[EvalMetrics] = None
    
    # LLM Judge results
    judge_report: Optional[JudgeReport] = None
    
    # Adversarial testing results
    adversarial_report: Optional[AdversarialReport] = None
    
    # Summary scores
    overall_score: float = 0.0
    detection_score: float = 0.0
    quality_score: float = 0.0
    robustness_score: float = 0.0
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)


class HybridEvaluator:
    """Run comprehensive hybrid evaluation."""
    
    def __init__(self, config: HybridEvalConfig):
        self.config = config
        
        # Initialize components
        self.judge = None
        if config.enable_judge:
            try:
                self.judge = LLMJudge(model=config.judge_model)
            except Exception as e:
                print(f"[WARN] Could not initialize LLM judge: {e}")
        
        self.adversarial_gen = None
        if config.enable_adversarial:
            self.adversarial_gen = AdversarialGenerator(use_llm=self.judge is not None)
    
    def run(self) -> HybridEvalReport:
        """Run the complete hybrid evaluation."""
        report = HybridEvalReport(
            run_name=self.config.run_name,
            timestamp=datetime.now().isoformat(),
            config=asdict(self.config) if hasattr(self.config, '__dataclass_fields__') else {},
        )
        
        # Get dataset stats
        report.dataset_stats = get_dataset_stats(
            self.config.dataset_dir,
            self.config.include_benign,
        )
        
        if not self.config.quiet:
            print("\n" + "=" * 60)
            print("         HYBRID EVALUATION STARTING")
            print("=" * 60)
            print(f"\n📊 Dataset: {report.dataset_stats.get('total', 0)} samples")
        
        # Phase 1: Traditional Evaluation
        if not self.config.quiet:
            print("\n📈 Phase 1: Traditional Metrics")
            print("-" * 40)
        
        results, report.metrics = self._run_traditional_eval()
        
        # Phase 2: LLM Judge Evaluation
        if self.config.enable_judge and self.judge:
            if not self.config.quiet:
                print("\n🧑‍⚖️ Phase 2: LLM Judge Evaluation")
                print("-" * 40)
            
            report.judge_report = self._run_judge_eval(results)
        
        # Phase 3: Adversarial Testing
        if self.config.enable_adversarial and self.adversarial_gen:
            if not self.config.quiet:
                print("\n⚔️ Phase 3: Adversarial Testing")
                print("-" * 40)
            
            # Get some phishing samples for adversarial testing
            phishing_samples = [
                {"id": r.id, "content": self._get_content_for_result(r), "modality": r.modality}
                for r in results
                if is_positive_label(r.label) and r.success
            ][:50]  # Limit to 50 samples
            
            report.adversarial_report = self._run_adversarial_eval(phishing_samples)
        
        # Calculate overall scores
        report = self._calculate_scores(report)
        
        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)
        
        # Save results
        self._save_report(report)
        
        # Print summary
        if not self.config.quiet:
            self._print_summary(report)
        
        return report
    
    def _get_content_for_result(self, result: EvalResult) -> str:
        """Get original content for a result (placeholder - would need to track this)."""
        # In a real implementation, you'd store content with results
        return f"Sample {result.id}"
    
    def _run_traditional_eval(self) -> tuple[List[EvalResult], EvalMetrics]:
        """Run traditional metrics evaluation."""
        samples = list(iter_all_samples(
            self.config.dataset_dir,
            self.config.include_benign,
            self.config.modalities,
        ))
        
        if self.config.max_samples:
            samples = samples[:self.config.max_samples]
        
        results: List[EvalResult] = []
        
        iterator = samples
        if not self.config.quiet:
            iterator = tqdm(samples, desc="Evaluating", unit="sample")
        
        for sample in iterator:
            result = call_analyze(
                base_url=self.config.base_url,
                sample=sample,
                api_key=self.config.api_key,
                timeout=self.config.timeout,
            )
            # Store content for later use
            result._content = sample.get("content", "")
            results.append(result)
        
        metrics = compute_metrics(results)
        
        return results, metrics
    
    def _run_judge_eval(self, results: List[EvalResult]) -> JudgeReport:
        """Run LLM judge evaluation on a sample of results."""
        quality_scores: List[JudgeScores] = []
        error_analyses: List[FPFNAnalysis] = []
        
        # Select samples to judge
        samples_to_judge = []
        
        # Always include errors (FP/FN)
        if self.config.judge_all_errors:
            for r in results:
                if not r.success:
                    continue
                gt_pos = is_positive_label(r.label)
                pred_pos = is_positive_prediction(r.predicted_risk)
                if gt_pos != pred_pos:
                    samples_to_judge.append((r, "error"))
        
        # Add random sample
        import random
        successful = [r for r in results if r.success and r not in [s[0] for s in samples_to_judge]]
        sample_count = int(len(successful) * self.config.judge_sample_rate)
        random_samples = random.sample(successful, min(sample_count, len(successful)))
        samples_to_judge.extend([(r, "random") for r in random_samples])
        
        if not self.config.quiet:
            print(f"  Judging {len(samples_to_judge)} samples ({len([s for s in samples_to_judge if s[1] == 'error'])} errors)")
        
        iterator = samples_to_judge
        if not self.config.quiet:
            iterator = tqdm(samples_to_judge, desc="Judging", unit="sample")
        
        for result, reason in iterator:
            content = getattr(result, '_content', f"Sample {result.id}")
            gt_pos = is_positive_label(result.label)
            pred_pos = is_positive_prediction(result.predicted_risk)
            is_correct = gt_pos == pred_pos
            
            # Quality evaluation
            score = self.judge.evaluate_quality(
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
            
            # Error analysis for FP/FN
            if not is_correct:
                error_type = "FP" if pred_pos and not gt_pos else "FN"
                analysis = self.judge.analyze_error(
                    sample_id=result.id,
                    content=content,
                    content_type=result.modality,
                    risk_level=result.predicted_risk,
                    score=result.overall_score,
                    indicators=result.indicators,
                    ground_truth=result.label,
                    prediction="positive" if pred_pos else "negative",
                    error_type=error_type,
                )
                error_analyses.append(analysis)
        
        return aggregate_judge_results(quality_scores, error_analyses)
    
    def _run_adversarial_eval(self, phishing_samples: List[Dict]) -> AdversarialReport:
        """Run adversarial testing."""
        # Generate adversarial samples
        if not self.config.quiet:
            print(f"  Generating adversarial samples from {len(phishing_samples)} phishing samples")
        
        adversarial_samples = self.adversarial_gen.generate_batch(
            samples=phishing_samples,
            techniques=self.config.adversarial_techniques,
            samples_per_technique=self.config.adversarial_samples_per_technique,
        )
        
        if not self.config.quiet:
            print(f"  Testing {len(adversarial_samples)} adversarial samples")
        
        # Test each adversarial sample
        test_results: List[AdversarialTestResult] = []
        
        iterator = adversarial_samples
        if not self.config.quiet:
            iterator = tqdm(adversarial_samples, desc="Testing", unit="sample")
        
        for adv_sample in iterator:
            # Create a sample dict for the API
            sample = {
                "id": f"adv_{adv_sample.original_id}_{adv_sample.technique}",
                "modality": adv_sample.modality,
                "content": adv_sample.adversarial_content,
                "label": "phishing",  # These are all modified phishing samples
            }
            
            start = time.perf_counter()
            try:
                result = call_analyze(
                    base_url=self.config.base_url,
                    sample=sample,
                    api_key=self.config.api_key,
                    timeout=self.config.timeout,
                )
                latency = (time.perf_counter() - start) * 1000
                
                detected = is_positive_prediction(result.predicted_risk)
                
                test_results.append(AdversarialTestResult(
                    sample=adv_sample,
                    detected=detected,
                    risk_level=result.predicted_risk,
                    score=result.overall_score,
                    indicators=result.indicators,
                    evasion_successful=not detected,  # Evasion successful if not detected
                    latency_ms=latency,
                ))
            except Exception as e:
                test_results.append(AdversarialTestResult(
                    sample=adv_sample,
                    detected=False,
                    risk_level="ERROR",
                    score=0.0,
                    indicators=[],
                    evasion_successful=True,
                    error=str(e),
                ))
        
        return aggregate_adversarial_results(test_results)
    
    def _calculate_scores(self, report: HybridEvalReport) -> HybridEvalReport:
        """Calculate overall scores from component metrics."""
        scores = []
        
        # Detection score (from traditional metrics)
        if report.metrics:
            f1 = report.metrics.f1_score or 0
            auc = report.metrics.roc_auc or 0
            report.detection_score = (f1 + auc) / 2 if auc else f1
            scores.append(report.detection_score)
        
        # Quality score (from judge)
        if report.judge_report and report.judge_report.avg_overall_quality > 0:
            report.quality_score = report.judge_report.avg_overall_quality / 5.0  # Normalize to 0-1
            scores.append(report.quality_score)
        
        # Robustness score (from adversarial)
        if report.adversarial_report and report.adversarial_report.total_samples > 0:
            # Higher detection rate = higher robustness
            detection_rate = 1.0 - report.adversarial_report.evasion_rate
            report.robustness_score = detection_rate
            scores.append(report.robustness_score)
        
        # Overall score (weighted average)
        if scores:
            # Weight: 50% detection, 25% quality, 25% robustness
            weights = [0.5, 0.25, 0.25][:len(scores)]
            total_weight = sum(weights)
            report.overall_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
        
        return report
    
    def _generate_recommendations(self, report: HybridEvalReport) -> List[str]:
        """Generate actionable recommendations based on results."""
        recommendations = []
        
        # Detection recommendations
        if report.metrics:
            if report.metrics.recall and report.metrics.recall < 0.9:
                recommendations.append(
                    f"⚠️ Recall is {report.metrics.recall*100:.1f}% - consider lowering detection threshold to catch more fraud"
                )
            if report.metrics.precision and report.metrics.precision < 0.8:
                recommendations.append(
                    f"⚠️ Precision is {report.metrics.precision*100:.1f}% - high false positive rate may frustrate users"
                )
            if report.metrics.fn > 0:
                recommendations.append(
                    f"🔴 {report.metrics.fn} false negatives detected - review missed fraud patterns"
                )
        
        # Quality recommendations
        if report.judge_report:
            if report.judge_report.avg_explanation_quality < 3.5:
                recommendations.append(
                    "📝 Explanation quality is low - improve indicator descriptions"
                )
            if report.judge_report.avg_user_friendliness < 3.5:
                recommendations.append(
                    "👤 User-friendliness is low - simplify alert messages"
                )
            
            # Add top improvement suggestions
            for sugg in report.judge_report.common_improvement_suggestions[:3]:
                recommendations.append(f"💡 {sugg['suggestion']} (mentioned {sugg['count']}x)")
        
        # Robustness recommendations
        if report.adversarial_report:
            if report.adversarial_report.evasion_rate > 0.1:
                recommendations.append(
                    f"🛡️ {report.adversarial_report.evasion_rate*100:.1f}% of adversarial samples evaded detection"
                )
            
            # Flag problematic techniques
            for tech in report.adversarial_report.most_effective_techniques[:2]:
                if tech["evasion_rate"] > 0.2:
                    recommendations.append(
                        f"⚔️ Vulnerable to {tech['technique']} ({tech['evasion_rate']*100:.0f}% evasion rate)"
                    )
        
        return recommendations
    
    def _save_report(self, report: HybridEvalReport) -> Dict[str, Path]:
        """Save the complete report to files."""
        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{self.config.run_name}_{timestamp}"
        
        # Convert report to dict for JSON serialization
        def to_serializable(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            elif isinstance(obj, Path):
                return str(obj)
            return obj
        
        report_dict = {
            "run_name": report.run_name,
            "timestamp": report.timestamp,
            "dataset_stats": report.dataset_stats,
            "overall_score": report.overall_score,
            "detection_score": report.detection_score,
            "quality_score": report.quality_score,
            "robustness_score": report.robustness_score,
            "recommendations": report.recommendations,
            "metrics": asdict(report.metrics) if report.metrics else None,
            "judge_report": asdict(report.judge_report) if report.judge_report else None,
            "adversarial_report": asdict(report.adversarial_report) if report.adversarial_report else None,
        }
        
        # Save full report
        report_path = output_dir / f"{base_name}_hybrid_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        # Save summary
        summary_path = output_dir / f"{base_name}_summary.json"
        summary = {
            "run_name": report.run_name,
            "timestamp": report.timestamp,
            "scores": {
                "overall": report.overall_score,
                "detection": report.detection_score,
                "quality": report.quality_score,
                "robustness": report.robustness_score,
            },
            "recommendations": report.recommendations,
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        
        if not self.config.quiet:
            print(f"\n💾 Results saved to {output_dir}/")
        
        return {"report": report_path, "summary": summary_path}
    
    def _print_summary(self, report: HybridEvalReport) -> None:
        """Print a summary of the hybrid evaluation."""
        print("\n" + "=" * 60)
        print("           HYBRID EVALUATION COMPLETE")
        print("=" * 60)
        
        # Overall scores
        print("\n🏆 OVERALL SCORES")
        print("-" * 40)
        print(f"  Overall Score:    {report.overall_score * 100:.1f}%")
        print(f"  Detection Score:  {report.detection_score * 100:.1f}%")
        if report.quality_score > 0:
            print(f"  Quality Score:    {report.quality_score * 100:.1f}%")
        if report.robustness_score > 0:
            print(f"  Robustness Score: {report.robustness_score * 100:.1f}%")
        
        # Key metrics
        if report.metrics:
            print("\n📊 KEY METRICS")
            print("-" * 40)
            if report.metrics.accuracy:
                print(f"  Accuracy:   {report.metrics.accuracy * 100:.1f}%")
            if report.metrics.precision:
                print(f"  Precision:  {report.metrics.precision * 100:.1f}%")
            if report.metrics.recall:
                print(f"  Recall:     {report.metrics.recall * 100:.1f}%")
            if report.metrics.roc_auc:
                print(f"  ROC-AUC:    {report.metrics.roc_auc:.4f}")
        
        # Judge summary
        if report.judge_report and report.judge_report.successful_evaluations > 0:
            print("\n🧑‍⚖️ QUALITY ASSESSMENT")
            print("-" * 40)
            print(f"  Samples judged:        {report.judge_report.successful_evaluations}")
            print(f"  Avg Explanation:       {report.judge_report.avg_explanation_quality:.1f}/5")
            print(f"  Avg Indicator Quality: {report.judge_report.avg_indicator_relevance:.1f}/5")
            print(f"  Avg User-Friendliness: {report.judge_report.avg_user_friendliness:.1f}/5")
        
        # Adversarial summary
        if report.adversarial_report and report.adversarial_report.total_samples > 0:
            print("\n⚔️ ADVERSARIAL ROBUSTNESS")
            print("-" * 40)
            print(f"  Samples tested:  {report.adversarial_report.total_samples}")
            print(f"  Detection rate:  {(1 - report.adversarial_report.evasion_rate) * 100:.1f}%")
            print(f"  Evasion rate:    {report.adversarial_report.evasion_rate * 100:.1f}%")
        
        # Recommendations
        if report.recommendations:
            print("\n📋 RECOMMENDATIONS")
            print("-" * 40)
            for rec in report.recommendations[:5]:
                print(f"  {rec}")
        
        print("\n" + "=" * 60 + "\n")


def run_hybrid_eval(
    dataset_dir: str,
    base_url: str = "http://127.0.0.1:8000",
    output_dir: str = "eval_results",
    run_name: str = "hybrid_eval",
    enable_judge: bool = True,
    enable_adversarial: bool = True,
    api_key: Optional[str] = None,
    quiet: bool = False,
) -> HybridEvalReport:
    """Convenience function to run hybrid evaluation.
    
    Args:
        dataset_dir: Path to dataset directory
        base_url: FraudShield API URL
        output_dir: Directory for results
        run_name: Name for this evaluation run
        enable_judge: Whether to run LLM judge evaluation
        enable_adversarial: Whether to run adversarial testing
        api_key: Optional API key for FraudShield
        quiet: Suppress output
        
    Returns:
        HybridEvalReport with complete results
    """
    config = HybridEvalConfig(
        dataset_dir=Path(dataset_dir),
        base_url=base_url,
        output_dir=Path(output_dir),
        run_name=run_name,
        enable_judge=enable_judge,
        enable_adversarial=enable_adversarial,
        api_key=api_key,
        quiet=quiet,
    )
    
    evaluator = HybridEvaluator(config)
    return evaluator.run()

