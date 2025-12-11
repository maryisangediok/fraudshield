# fraudshield/eval/__init__.py
"""
FraudShield Evaluation Suite

Industry-standard evaluation tools for fraud detection systems:

CORE EVALUATION:
- Traditional metrics (precision, recall, F1, AUC)
- Dataset loading (JSONL format)

LLM-AS-A-JUDGE:
- Explanation quality scoring
- Indicator relevance assessment
- FP/FN root cause analysis

ADVERSARIAL TESTING:
- Evasion technique simulation
- Robustness scoring

ADVANCED METRICS:
- Calibration (ECE, Brier score)
- Cost-sensitive metrics
- Confidence intervals
- Threshold optimization
- Fairness metrics

BUSINESS IMPACT:
- Dollar value calculations
- ROI analysis
- Operational efficiency

TEMPORAL ANALYSIS:
- Drift detection
- Performance trends
- Staleness indicators
"""

# Dataset loading
from fraudshield.eval.dataset_loader import (
    load_jsonl,
    load_url_samples,
    load_sms_samples,
    load_email_samples,
    iter_all_samples,
    get_dataset_stats,
)

# Traditional evaluation
from fraudshield.eval.run_eval import (
    EvalResult,
    EvalMetrics,
    call_analyze,
    compute_metrics,
    save_results,
    print_report,
)

# LLM Judge
from fraudshield.eval.llm_judge import (
    LLMJudge,
    JudgeScores,
    FPFNAnalysis,
    JudgeReport,
    aggregate_judge_results,
)

# Adversarial testing
from fraudshield.eval.adversarial import (
    AdversarialGenerator,
    AdversarialSample,
    AdversarialTestResult,
    AdversarialReport,
    aggregate_adversarial_results,
)

# Advanced metrics
from fraudshield.eval.advanced_metrics import (
    CalibrationMetrics,
    CostSensitiveMetrics,
    ScoreDistributionMetrics,
    ThresholdAnalysis,
    ConfidenceIntervals,
    FairnessMetrics,
    AdvancedMetricsReport,
    compute_calibration_metrics,
    compute_cost_sensitive_metrics,
    compute_score_distribution_metrics,
    compute_threshold_analysis,
    compute_confidence_intervals,
    compute_fairness_metrics,
    compute_all_advanced_metrics,
)

# Business metrics
from fraudshield.eval.business_metrics import (
    FraudValueConfig,
    BusinessImpactMetrics,
    OperationalMetrics,
    BusinessReport,
    compute_business_impact,
    print_business_report,
)

# Temporal metrics
from fraudshield.eval.temporal_metrics import (
    TimeWindow,
    DriftDetectionResult,
    TemporalReport,
    TemporalAnalyzer,
    print_temporal_report,
)

# Hybrid evaluation
from fraudshield.eval.hybrid_eval import (
    HybridEvalConfig,
    HybridEvalReport,
    HybridEvaluator,
    run_hybrid_eval,
)

__all__ = [
    # Dataset loading
    "load_jsonl",
    "load_url_samples",
    "load_sms_samples",
    "load_email_samples",
    "iter_all_samples",
    "get_dataset_stats",
    
    # Traditional evaluation
    "EvalResult",
    "EvalMetrics",
    "call_analyze",
    "compute_metrics",
    "save_results",
    "print_report",
    
    # LLM Judge
    "LLMJudge",
    "JudgeScores",
    "FPFNAnalysis",
    "JudgeReport",
    "aggregate_judge_results",
    
    # Adversarial testing
    "AdversarialGenerator",
    "AdversarialSample",
    "AdversarialTestResult",
    "AdversarialReport",
    "aggregate_adversarial_results",
    
    # Advanced metrics
    "CalibrationMetrics",
    "CostSensitiveMetrics",
    "ScoreDistributionMetrics",
    "ThresholdAnalysis",
    "ConfidenceIntervals",
    "FairnessMetrics",
    "AdvancedMetricsReport",
    "compute_calibration_metrics",
    "compute_cost_sensitive_metrics",
    "compute_score_distribution_metrics",
    "compute_threshold_analysis",
    "compute_confidence_intervals",
    "compute_fairness_metrics",
    "compute_all_advanced_metrics",
    
    # Business metrics
    "FraudValueConfig",
    "BusinessImpactMetrics",
    "OperationalMetrics",
    "BusinessReport",
    "compute_business_impact",
    "print_business_report",
    
    # Temporal metrics
    "TimeWindow",
    "DriftDetectionResult",
    "TemporalReport",
    "TemporalAnalyzer",
    "print_temporal_report",
    
    # Hybrid evaluation
    "HybridEvalConfig",
    "HybridEvalReport",
    "HybridEvaluator",
    "run_hybrid_eval",
]
