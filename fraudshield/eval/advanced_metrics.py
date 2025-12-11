# fraudshield/eval/advanced_metrics.py
"""
Advanced evaluation metrics for fraud detection.

Includes:
- Calibration metrics (ECE, Brier Score)
- Cost-sensitive metrics (weighted F1, expected cost)
- Score distribution analysis
- Threshold optimization
- Confidence intervals (bootstrap)
- Statistical significance testing
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import numpy as np

try:
    from scipy import stats
    from scipy.special import rel_entr
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


@dataclass
class CalibrationMetrics:
    """Calibration metrics - are confidence scores meaningful?"""
    
    # Expected Calibration Error (lower is better, 0 = perfect)
    expected_calibration_error: float = 0.0
    
    # Maximum Calibration Error
    max_calibration_error: float = 0.0
    
    # Brier Score (lower is better, 0 = perfect)
    brier_score: float = 0.0
    
    # Reliability diagram data (for plotting)
    reliability_diagram: Dict[str, List[float]] = field(default_factory=dict)
    
    # Calibration assessment
    is_well_calibrated: bool = False
    calibration_advice: str = ""


@dataclass
class CostSensitiveMetrics:
    """Cost-sensitive metrics for business impact."""
    
    # Cost configuration
    fn_cost: float = 100.0  # Cost of missing fraud (default: $100)
    fp_cost: float = 10.0   # Cost of false alarm (default: $10)
    
    # Weighted metrics
    weighted_precision: float = 0.0
    weighted_recall: float = 0.0
    weighted_f1: float = 0.0
    
    # Total costs
    total_fn_cost: float = 0.0
    total_fp_cost: float = 0.0
    total_cost: float = 0.0
    
    # Cost-adjusted scores
    cost_per_sample: float = 0.0
    cost_reduction_vs_baseline: float = 0.0  # vs flagging nothing


@dataclass
class ScoreDistributionMetrics:
    """Analysis of prediction score distributions."""
    
    # Separation between classes
    score_separation: float = 0.0  # Higher is better
    kl_divergence: float = 0.0     # Higher = more separable
    
    # Distribution statistics
    positive_class_mean: float = 0.0
    positive_class_std: float = 0.0
    negative_class_mean: float = 0.0
    negative_class_std: float = 0.0
    
    # Overlap
    distribution_overlap: float = 0.0  # Lower is better
    
    # Histogram data (for plotting)
    positive_histogram: Dict[str, List[float]] = field(default_factory=dict)
    negative_histogram: Dict[str, List[float]] = field(default_factory=dict)


@dataclass
class ThresholdAnalysis:
    """Optimal threshold analysis."""
    
    # Optimal thresholds for different objectives
    optimal_f1_threshold: float = 0.5
    optimal_f1_score: float = 0.0
    
    optimal_cost_threshold: float = 0.5
    optimal_cost_value: float = 0.0
    
    # Threshold at specific recall levels
    threshold_at_90_recall: float = 0.0
    threshold_at_95_recall: float = 0.0
    threshold_at_99_recall: float = 0.0
    
    # Precision at those recall levels
    precision_at_90_recall: float = 0.0
    precision_at_95_recall: float = 0.0
    precision_at_99_recall: float = 0.0
    
    # Threshold stability (how sensitive is performance to threshold?)
    threshold_sensitivity: float = 0.0  # Lower is more stable
    
    # PR curve data
    precision_recall_curve: Dict[str, List[float]] = field(default_factory=dict)


@dataclass
class ConfidenceIntervals:
    """Bootstrap confidence intervals for metrics."""
    
    confidence_level: float = 0.95
    n_bootstrap: int = 1000
    
    # Metric CIs (lower, point estimate, upper)
    accuracy_ci: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    precision_ci: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    recall_ci: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    f1_ci: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    roc_auc_ci: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    
    # Statistical significance
    is_significantly_better_than_random: bool = False
    p_value_vs_random: float = 1.0


@dataclass
class FairnessMetrics:
    """Fairness and bias metrics."""
    
    # Overall fairness assessment
    is_fair: bool = True
    fairness_warnings: List[str] = field(default_factory=list)
    
    # By-group metrics (if group info available)
    # Maps group_name -> metrics dict
    by_group: Dict[str, Dict[str, float]] = field(default_factory=dict)
    
    # Parity metrics
    demographic_parity_difference: float = 0.0  # Max diff in positive rate
    equalized_odds_difference: float = 0.0      # Max diff in TPR/FPR
    
    # Disparate impact ratio (should be 0.8-1.25 for legal compliance)
    disparate_impact_ratio: float = 1.0


@dataclass
class AdvancedMetricsReport:
    """Complete advanced metrics report."""
    
    calibration: CalibrationMetrics = field(default_factory=CalibrationMetrics)
    cost_sensitive: CostSensitiveMetrics = field(default_factory=CostSensitiveMetrics)
    score_distribution: ScoreDistributionMetrics = field(default_factory=ScoreDistributionMetrics)
    threshold_analysis: ThresholdAnalysis = field(default_factory=ThresholdAnalysis)
    confidence_intervals: ConfidenceIntervals = field(default_factory=ConfidenceIntervals)
    fairness: FairnessMetrics = field(default_factory=FairnessMetrics)


def compute_calibration_metrics(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    n_bins: int = 10,
) -> CalibrationMetrics:
    """
    Compute calibration metrics.
    
    Args:
        y_true: Ground truth labels (0 or 1)
        y_scores: Predicted probabilities/scores (0 to 1)
        n_bins: Number of bins for calibration
        
    Returns:
        CalibrationMetrics with ECE, Brier score, etc.
    """
    metrics = CalibrationMetrics()
    
    y_true = np.asarray(y_true)
    y_scores = np.asarray(y_scores)
    
    # Clip scores to valid probability range
    y_scores = np.clip(y_scores, 0, 1)
    
    # Brier Score
    metrics.brier_score = float(np.mean((y_scores - y_true) ** 2))
    
    # Expected Calibration Error (ECE)
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    bin_indices = np.digitize(y_scores, bin_boundaries[1:-1])
    
    ece = 0.0
    mce = 0.0
    
    bin_accuracies = []
    bin_confidences = []
    bin_counts = []
    
    for bin_idx in range(n_bins):
        mask = bin_indices == bin_idx
        if np.sum(mask) > 0:
            bin_accuracy = np.mean(y_true[mask])
            bin_confidence = np.mean(y_scores[mask])
            bin_count = np.sum(mask)
            
            bin_accuracies.append(float(bin_accuracy))
            bin_confidences.append(float(bin_confidence))
            bin_counts.append(int(bin_count))
            
            bin_error = abs(bin_accuracy - bin_confidence)
            ece += (bin_count / len(y_true)) * bin_error
            mce = max(mce, bin_error)
        else:
            bin_accuracies.append(0.0)
            bin_confidences.append(0.0)
            bin_counts.append(0)
    
    metrics.expected_calibration_error = float(ece)
    metrics.max_calibration_error = float(mce)
    
    # Reliability diagram data
    metrics.reliability_diagram = {
        "bin_accuracies": bin_accuracies,
        "bin_confidences": bin_confidences,
        "bin_counts": bin_counts,
        "bin_edges": bin_boundaries.tolist(),
    }
    
    # Calibration assessment
    metrics.is_well_calibrated = ece < 0.1
    
    if ece < 0.05:
        metrics.calibration_advice = "Excellent calibration. Confidence scores are trustworthy."
    elif ece < 0.1:
        metrics.calibration_advice = "Good calibration. Minor adjustments may help."
    elif ece < 0.2:
        metrics.calibration_advice = "Moderate calibration. Consider Platt scaling or isotonic regression."
    else:
        metrics.calibration_advice = "Poor calibration. Confidence scores are unreliable. Recalibration strongly recommended."
    
    return metrics


def compute_cost_sensitive_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    fn_cost: float = 100.0,
    fp_cost: float = 10.0,
) -> CostSensitiveMetrics:
    """
    Compute cost-sensitive metrics.
    
    Args:
        y_true: Ground truth labels
        y_pred: Predicted labels (binary)
        fn_cost: Cost of false negative (missing fraud)
        fp_cost: Cost of false positive (false alarm)
        
    Returns:
        CostSensitiveMetrics with weighted scores and costs
    """
    metrics = CostSensitiveMetrics(fn_cost=fn_cost, fp_cost=fp_cost)
    
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    
    # Confusion matrix components
    tp = np.sum((y_true == 1) & (y_pred == 1))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    
    # Cost calculations
    metrics.total_fn_cost = float(fn * fn_cost)
    metrics.total_fp_cost = float(fp * fp_cost)
    metrics.total_cost = metrics.total_fn_cost + metrics.total_fp_cost
    metrics.cost_per_sample = metrics.total_cost / len(y_true) if len(y_true) > 0 else 0
    
    # Baseline cost (if we flagged nothing)
    total_positives = np.sum(y_true == 1)
    baseline_cost = total_positives * fn_cost
    metrics.cost_reduction_vs_baseline = float(
        (baseline_cost - metrics.total_cost) / baseline_cost if baseline_cost > 0 else 0
    )
    
    # Weighted precision/recall (weight positives by cost ratio)
    cost_ratio = fn_cost / fp_cost if fp_cost > 0 else 10
    
    # Weighted precision
    if tp + fp > 0:
        metrics.weighted_precision = float(tp / (tp + fp))
    
    # Weighted recall (critical - missing fraud is expensive)
    if tp + fn > 0:
        metrics.weighted_recall = float(tp / (tp + fn))
    
    # Cost-weighted F1
    if metrics.weighted_precision + metrics.weighted_recall > 0:
        # Use beta = sqrt(fn_cost/fp_cost) to weight recall more when FN is costly
        beta = np.sqrt(cost_ratio)
        metrics.weighted_f1 = float(
            (1 + beta**2) * (metrics.weighted_precision * metrics.weighted_recall) /
            (beta**2 * metrics.weighted_precision + metrics.weighted_recall)
        )
    
    return metrics


def compute_score_distribution_metrics(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    n_bins: int = 50,
) -> ScoreDistributionMetrics:
    """
    Analyze the distribution of prediction scores.
    
    Args:
        y_true: Ground truth labels
        y_scores: Predicted scores
        n_bins: Number of histogram bins
        
    Returns:
        ScoreDistributionMetrics with separation analysis
    """
    metrics = ScoreDistributionMetrics()
    
    y_true = np.asarray(y_true)
    y_scores = np.asarray(y_scores)
    
    positive_scores = y_scores[y_true == 1]
    negative_scores = y_scores[y_true == 0]
    
    if len(positive_scores) == 0 or len(negative_scores) == 0:
        return metrics
    
    # Distribution statistics
    metrics.positive_class_mean = float(np.mean(positive_scores))
    metrics.positive_class_std = float(np.std(positive_scores))
    metrics.negative_class_mean = float(np.mean(negative_scores))
    metrics.negative_class_std = float(np.std(negative_scores))
    
    # Score separation (Cohen's d)
    pooled_std = np.sqrt(
        (np.var(positive_scores) + np.var(negative_scores)) / 2
    )
    if pooled_std > 0:
        metrics.score_separation = float(
            abs(metrics.positive_class_mean - metrics.negative_class_mean) / pooled_std
        )
    
    # KL Divergence (requires scipy)
    if SCIPY_AVAILABLE:
        # Create histograms
        all_scores = np.concatenate([positive_scores, negative_scores])
        bins = np.linspace(min(all_scores), max(all_scores), n_bins + 1)
        
        pos_hist, _ = np.histogram(positive_scores, bins=bins, density=True)
        neg_hist, _ = np.histogram(negative_scores, bins=bins, density=True)
        
        # Add small epsilon to avoid log(0)
        eps = 1e-10
        pos_hist = pos_hist + eps
        neg_hist = neg_hist + eps
        
        # Normalize
        pos_hist = pos_hist / pos_hist.sum()
        neg_hist = neg_hist / neg_hist.sum()
        
        # KL divergence (symmetric)
        kl_pn = np.sum(rel_entr(pos_hist, neg_hist))
        kl_np = np.sum(rel_entr(neg_hist, pos_hist))
        metrics.kl_divergence = float((kl_pn + kl_np) / 2)
        
        # Overlap (Bhattacharyya coefficient)
        bc = np.sum(np.sqrt(pos_hist * neg_hist))
        metrics.distribution_overlap = float(bc)
    
    # Histogram data for plotting
    bins = np.linspace(0, 1, n_bins + 1)
    pos_hist, _ = np.histogram(positive_scores, bins=bins)
    neg_hist, _ = np.histogram(negative_scores, bins=bins)
    
    metrics.positive_histogram = {
        "counts": pos_hist.tolist(),
        "bin_edges": bins.tolist(),
    }
    metrics.negative_histogram = {
        "counts": neg_hist.tolist(),
        "bin_edges": bins.tolist(),
    }
    
    return metrics


def compute_threshold_analysis(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    fn_cost: float = 100.0,
    fp_cost: float = 10.0,
    n_thresholds: int = 100,
) -> ThresholdAnalysis:
    """
    Analyze performance across different thresholds.
    
    Args:
        y_true: Ground truth labels
        y_scores: Predicted scores
        fn_cost: Cost of false negative
        fp_cost: Cost of false positive
        n_thresholds: Number of thresholds to evaluate
        
    Returns:
        ThresholdAnalysis with optimal thresholds
    """
    analysis = ThresholdAnalysis()
    
    y_true = np.asarray(y_true)
    y_scores = np.asarray(y_scores)
    
    thresholds = np.linspace(0, 1, n_thresholds)
    
    f1_scores = []
    costs = []
    precisions = []
    recalls = []
    
    for thresh in thresholds:
        y_pred = (y_scores >= thresh).astype(int)
        
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        cost = fn * fn_cost + fp * fp_cost
        
        precisions.append(precision)
        recalls.append(recall)
        f1_scores.append(f1)
        costs.append(cost)
    
    f1_scores = np.array(f1_scores)
    costs = np.array(costs)
    precisions = np.array(precisions)
    recalls = np.array(recalls)
    
    # Optimal F1 threshold
    best_f1_idx = np.argmax(f1_scores)
    analysis.optimal_f1_threshold = float(thresholds[best_f1_idx])
    analysis.optimal_f1_score = float(f1_scores[best_f1_idx])
    
    # Optimal cost threshold
    best_cost_idx = np.argmin(costs)
    analysis.optimal_cost_threshold = float(thresholds[best_cost_idx])
    analysis.optimal_cost_value = float(costs[best_cost_idx])
    
    # Thresholds at specific recall levels
    for target_recall, attr_thresh, attr_prec in [
        (0.90, "threshold_at_90_recall", "precision_at_90_recall"),
        (0.95, "threshold_at_95_recall", "precision_at_95_recall"),
        (0.99, "threshold_at_99_recall", "precision_at_99_recall"),
    ]:
        mask = recalls >= target_recall
        if np.any(mask):
            # Find highest threshold that achieves target recall
            valid_indices = np.where(mask)[0]
            best_idx = valid_indices[np.argmax(thresholds[valid_indices])]
            setattr(analysis, attr_thresh, float(thresholds[best_idx]))
            setattr(analysis, attr_prec, float(precisions[best_idx]))
    
    # Threshold sensitivity (std of F1 around optimal)
    window = max(1, n_thresholds // 10)
    start = max(0, best_f1_idx - window)
    end = min(len(f1_scores), best_f1_idx + window + 1)
    analysis.threshold_sensitivity = float(np.std(f1_scores[start:end]))
    
    # PR curve data
    analysis.precision_recall_curve = {
        "thresholds": thresholds.tolist(),
        "precisions": precisions.tolist(),
        "recalls": recalls.tolist(),
        "f1_scores": f1_scores.tolist(),
        "costs": costs.tolist(),
    }
    
    return analysis


def compute_confidence_intervals(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    y_pred: np.ndarray,
    confidence_level: float = 0.95,
    n_bootstrap: int = 1000,
    random_state: int = 42,
) -> ConfidenceIntervals:
    """
    Compute bootstrap confidence intervals for metrics.
    
    Args:
        y_true: Ground truth labels
        y_scores: Predicted scores
        y_pred: Predicted labels
        confidence_level: CI level (default 95%)
        n_bootstrap: Number of bootstrap samples
        random_state: Random seed
        
    Returns:
        ConfidenceIntervals with CIs for key metrics
    """
    ci = ConfidenceIntervals(
        confidence_level=confidence_level,
        n_bootstrap=n_bootstrap,
    )
    
    y_true = np.asarray(y_true)
    y_scores = np.asarray(y_scores)
    y_pred = np.asarray(y_pred)
    
    np.random.seed(random_state)
    n_samples = len(y_true)
    
    # Storage for bootstrap samples
    accuracies = []
    precisions = []
    recalls = []
    f1s = []
    aucs = []
    
    for _ in range(n_bootstrap):
        # Bootstrap sample
        indices = np.random.choice(n_samples, size=n_samples, replace=True)
        y_true_boot = y_true[indices]
        y_scores_boot = y_scores[indices]
        y_pred_boot = y_pred[indices]
        
        # Compute metrics
        tp = np.sum((y_true_boot == 1) & (y_pred_boot == 1))
        tn = np.sum((y_true_boot == 0) & (y_pred_boot == 0))
        fp = np.sum((y_true_boot == 0) & (y_pred_boot == 1))
        fn = np.sum((y_true_boot == 1) & (y_pred_boot == 0))
        
        acc = (tp + tn) / len(y_true_boot) if len(y_true_boot) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        
        accuracies.append(acc)
        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)
        
        # AUC (simplified - rank-based)
        if len(np.unique(y_true_boot)) > 1:
            try:
                from sklearn.metrics import roc_auc_score
                auc_val = roc_auc_score(y_true_boot, y_scores_boot)
                aucs.append(auc_val)
            except:
                pass
    
    # Compute CIs
    alpha = 1 - confidence_level
    
    def get_ci(values):
        if len(values) == 0:
            return (0.0, 0.0, 0.0)
        point = float(np.mean(values))
        lower = float(np.percentile(values, 100 * alpha / 2))
        upper = float(np.percentile(values, 100 * (1 - alpha / 2)))
        return (lower, point, upper)
    
    ci.accuracy_ci = get_ci(accuracies)
    ci.precision_ci = get_ci(precisions)
    ci.recall_ci = get_ci(recalls)
    ci.f1_ci = get_ci(f1s)
    ci.roc_auc_ci = get_ci(aucs)
    
    # Test significance vs random (AUC > 0.5)
    if aucs:
        # One-sample t-test against 0.5
        if SCIPY_AVAILABLE:
            t_stat, p_value = stats.ttest_1samp(aucs, 0.5)
            ci.p_value_vs_random = float(p_value) if not np.isnan(p_value) else 1.0
            ci.is_significantly_better_than_random = p_value < (1 - confidence_level) and np.mean(aucs) > 0.5
        else:
            # Simple check
            ci.is_significantly_better_than_random = np.mean(aucs) > 0.55
    
    return ci


def compute_fairness_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    groups: Optional[np.ndarray] = None,
) -> FairnessMetrics:
    """
    Compute fairness metrics across groups.
    
    Args:
        y_true: Ground truth labels
        y_pred: Predicted labels
        groups: Optional group membership for each sample
        
    Returns:
        FairnessMetrics with parity measures
    """
    metrics = FairnessMetrics()
    
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    
    if groups is None:
        # Without group info, we can only check overall metrics
        metrics.is_fair = True
        metrics.fairness_warnings = ["No group information provided for fairness analysis"]
        return metrics
    
    groups = np.asarray(groups)
    unique_groups = np.unique(groups)
    
    if len(unique_groups) < 2:
        metrics.is_fair = True
        metrics.fairness_warnings = ["Only one group found, fairness comparison not applicable"]
        return metrics
    
    # Compute metrics per group
    positive_rates = []
    tprs = []
    fprs = []
    
    for group in unique_groups:
        mask = groups == group
        y_true_g = y_true[mask]
        y_pred_g = y_pred[mask]
        
        tp = np.sum((y_true_g == 1) & (y_pred_g == 1))
        tn = np.sum((y_true_g == 0) & (y_pred_g == 0))
        fp = np.sum((y_true_g == 0) & (y_pred_g == 1))
        fn = np.sum((y_true_g == 1) & (y_pred_g == 0))
        
        # Positive prediction rate
        pos_rate = (tp + fp) / len(y_true_g) if len(y_true_g) > 0 else 0
        positive_rates.append(pos_rate)
        
        # TPR (recall)
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        tprs.append(tpr)
        
        # FPR
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fprs.append(fpr)
        
        metrics.by_group[str(group)] = {
            "count": int(len(y_true_g)),
            "positive_rate": float(pos_rate),
            "tpr": float(tpr),
            "fpr": float(fpr),
        }
    
    # Demographic parity difference
    metrics.demographic_parity_difference = float(max(positive_rates) - min(positive_rates))
    
    # Equalized odds difference
    tpr_diff = max(tprs) - min(tprs) if tprs else 0
    fpr_diff = max(fprs) - min(fprs) if fprs else 0
    metrics.equalized_odds_difference = float(max(tpr_diff, fpr_diff))
    
    # Disparate impact ratio
    if min(positive_rates) > 0:
        metrics.disparate_impact_ratio = float(min(positive_rates) / max(positive_rates))
    else:
        metrics.disparate_impact_ratio = 0.0
    
    # Fairness assessment
    metrics.fairness_warnings = []
    
    if metrics.demographic_parity_difference > 0.1:
        metrics.fairness_warnings.append(
            f"High demographic parity difference ({metrics.demographic_parity_difference:.2f})"
        )
    
    if metrics.equalized_odds_difference > 0.1:
        metrics.fairness_warnings.append(
            f"High equalized odds difference ({metrics.equalized_odds_difference:.2f})"
        )
    
    if metrics.disparate_impact_ratio < 0.8:
        metrics.fairness_warnings.append(
            f"Disparate impact ratio below 0.8 ({metrics.disparate_impact_ratio:.2f}) - potential legal concern"
        )
    
    metrics.is_fair = len(metrics.fairness_warnings) == 0
    
    return metrics


def compute_all_advanced_metrics(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    y_pred: Optional[np.ndarray] = None,
    groups: Optional[np.ndarray] = None,
    fn_cost: float = 100.0,
    fp_cost: float = 10.0,
    threshold: float = 0.5,
) -> AdvancedMetricsReport:
    """
    Compute all advanced metrics at once.
    
    Args:
        y_true: Ground truth labels
        y_scores: Predicted probability scores
        y_pred: Predicted labels (will be computed from scores if not provided)
        groups: Optional group membership for fairness analysis
        fn_cost: Cost of false negative
        fp_cost: Cost of false positive
        threshold: Threshold for converting scores to predictions
        
    Returns:
        AdvancedMetricsReport with all metrics
    """
    y_true = np.asarray(y_true)
    y_scores = np.asarray(y_scores)
    
    if y_pred is None:
        y_pred = (y_scores >= threshold).astype(int)
    else:
        y_pred = np.asarray(y_pred)
    
    report = AdvancedMetricsReport()
    
    report.calibration = compute_calibration_metrics(y_true, y_scores)
    report.cost_sensitive = compute_cost_sensitive_metrics(y_true, y_pred, fn_cost, fp_cost)
    report.score_distribution = compute_score_distribution_metrics(y_true, y_scores)
    report.threshold_analysis = compute_threshold_analysis(y_true, y_scores, fn_cost, fp_cost)
    report.confidence_intervals = compute_confidence_intervals(y_true, y_scores, y_pred)
    report.fairness = compute_fairness_metrics(y_true, y_pred, groups)
    
    return report

