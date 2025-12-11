# fraudshield/eval/temporal_metrics.py
"""
Temporal metrics and drift detection for fraud detection.

Tracks:
- Performance over time
- Concept drift (label distribution changes)
- Data drift (input distribution changes)
- Model staleness indicators
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import numpy as np

try:
    from scipy import stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


@dataclass
class TimeWindow:
    """Metrics for a specific time window."""
    
    window_id: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Counts
    total_samples: int = 0
    positive_samples: int = 0
    negative_samples: int = 0
    
    # Performance
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    
    # Score distribution
    mean_score: float = 0.0
    std_score: float = 0.0
    
    # Confusion matrix
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0


@dataclass
class DriftDetectionResult:
    """Results from drift detection analysis."""
    
    # Overall drift status
    drift_detected: bool = False
    drift_severity: str = "none"  # none, low, medium, high
    drift_type: str = ""  # concept, data, or both
    
    # Concept drift (label distribution change)
    concept_drift_detected: bool = False
    concept_drift_score: float = 0.0
    positive_rate_change: float = 0.0  # % change in fraud rate
    
    # Data drift (input distribution change)
    data_drift_detected: bool = False
    data_drift_score: float = 0.0
    
    # Performance drift
    performance_drift_detected: bool = False
    accuracy_change: float = 0.0
    recall_change: float = 0.0
    f1_change: float = 0.0
    
    # Statistical tests
    ks_statistic: float = 0.0  # Kolmogorov-Smirnov
    ks_pvalue: float = 1.0
    chi2_statistic: float = 0.0  # Chi-squared for labels
    chi2_pvalue: float = 1.0
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)


@dataclass
class TemporalReport:
    """Complete temporal analysis report."""
    
    # Time range
    analysis_start: Optional[datetime] = None
    analysis_end: Optional[datetime] = None
    total_windows: int = 0
    
    # Per-window metrics
    windows: List[TimeWindow] = field(default_factory=list)
    
    # Trends
    accuracy_trend: str = "stable"  # improving, stable, declining
    recall_trend: str = "stable"
    positive_rate_trend: str = "stable"
    
    # Drift detection
    drift_result: DriftDetectionResult = field(default_factory=DriftDetectionResult)
    
    # Staleness
    model_staleness_score: float = 0.0  # 0-1, higher = more stale
    recommended_retrain: bool = False
    days_since_best_performance: int = 0
    
    # Predictions
    predicted_performance_next_week: Dict[str, float] = field(default_factory=dict)


class TemporalAnalyzer:
    """Analyze model performance over time."""
    
    def __init__(
        self,
        drift_threshold: float = 0.1,
        staleness_threshold: float = 0.05,
        min_samples_per_window: int = 50,
    ):
        """
        Initialize temporal analyzer.
        
        Args:
            drift_threshold: Performance change threshold for drift detection
            staleness_threshold: Performance decline threshold for staleness
            min_samples_per_window: Minimum samples needed per time window
        """
        self.drift_threshold = drift_threshold
        self.staleness_threshold = staleness_threshold
        self.min_samples_per_window = min_samples_per_window
    
    def analyze(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_scores: np.ndarray,
        timestamps: Optional[np.ndarray] = None,
        n_windows: int = 10,
    ) -> TemporalReport:
        """
        Analyze temporal patterns in model performance.
        
        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            y_scores: Predicted scores
            timestamps: Optional timestamps for each sample
            n_windows: Number of time windows to analyze
            
        Returns:
            TemporalReport with temporal analysis
        """
        y_true = np.asarray(y_true)
        y_pred = np.asarray(y_pred)
        y_scores = np.asarray(y_scores)
        
        report = TemporalReport()
        
        # Create time windows
        if timestamps is not None:
            timestamps = np.asarray(timestamps)
            report.analysis_start = datetime.fromtimestamp(np.min(timestamps))
            report.analysis_end = datetime.fromtimestamp(np.max(timestamps))
            
            # Sort by time
            sort_idx = np.argsort(timestamps)
            y_true = y_true[sort_idx]
            y_pred = y_pred[sort_idx]
            y_scores = y_scores[sort_idx]
            timestamps = timestamps[sort_idx]
        
        # Split into windows
        n_samples = len(y_true)
        window_size = n_samples // n_windows
        
        if window_size < self.min_samples_per_window:
            n_windows = max(1, n_samples // self.min_samples_per_window)
            window_size = n_samples // n_windows
        
        report.total_windows = n_windows
        
        # Compute metrics per window
        for i in range(n_windows):
            start_idx = i * window_size
            end_idx = start_idx + window_size if i < n_windows - 1 else n_samples
            
            window = self._compute_window_metrics(
                window_id=f"window_{i}",
                y_true=y_true[start_idx:end_idx],
                y_pred=y_pred[start_idx:end_idx],
                y_scores=y_scores[start_idx:end_idx],
            )
            
            if timestamps is not None:
                window.start_time = datetime.fromtimestamp(timestamps[start_idx])
                window.end_time = datetime.fromtimestamp(timestamps[end_idx - 1])
            
            report.windows.append(window)
        
        # Analyze trends
        if len(report.windows) >= 2:
            report.accuracy_trend = self._analyze_trend(
                [w.accuracy for w in report.windows]
            )
            report.recall_trend = self._analyze_trend(
                [w.recall for w in report.windows]
            )
            report.positive_rate_trend = self._analyze_trend(
                [w.positive_samples / w.total_samples if w.total_samples > 0 else 0 
                 for w in report.windows]
            )
        
        # Detect drift
        if len(report.windows) >= 2:
            report.drift_result = self._detect_drift(
                report.windows,
                y_true,
                y_scores,
            )
        
        # Calculate staleness
        report.model_staleness_score = self._calculate_staleness(report.windows)
        report.recommended_retrain = (
            report.model_staleness_score > self.staleness_threshold or
            report.drift_result.drift_detected
        )
        
        # Find days since best performance
        if report.windows:
            best_window_idx = np.argmax([w.f1_score for w in report.windows])
            report.days_since_best_performance = len(report.windows) - best_window_idx - 1
        
        # Simple prediction for next week
        if len(report.windows) >= 3:
            recent_windows = report.windows[-3:]
            avg_accuracy = np.mean([w.accuracy for w in recent_windows])
            avg_recall = np.mean([w.recall for w in recent_windows])
            
            # Simple trend-based prediction
            acc_trend = (recent_windows[-1].accuracy - recent_windows[0].accuracy) / 3
            rec_trend = (recent_windows[-1].recall - recent_windows[0].recall) / 3
            
            report.predicted_performance_next_week = {
                "accuracy": float(np.clip(avg_accuracy + acc_trend, 0, 1)),
                "recall": float(np.clip(avg_recall + rec_trend, 0, 1)),
            }
        
        return report
    
    def _compute_window_metrics(
        self,
        window_id: str,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_scores: np.ndarray,
    ) -> TimeWindow:
        """Compute metrics for a single time window."""
        window = TimeWindow(window_id=window_id)
        
        window.total_samples = len(y_true)
        window.positive_samples = int(np.sum(y_true == 1))
        window.negative_samples = int(np.sum(y_true == 0))
        
        # Confusion matrix
        window.tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        window.fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        window.tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        window.fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        
        # Metrics
        total = window.tp + window.fp + window.tn + window.fn
        if total > 0:
            window.accuracy = (window.tp + window.tn) / total
        
        if window.tp + window.fp > 0:
            window.precision = window.tp / (window.tp + window.fp)
        
        if window.tp + window.fn > 0:
            window.recall = window.tp / (window.tp + window.fn)
        
        if window.precision + window.recall > 0:
            window.f1_score = 2 * window.precision * window.recall / (window.precision + window.recall)
        
        # Score distribution
        if len(y_scores) > 0:
            window.mean_score = float(np.mean(y_scores))
            window.std_score = float(np.std(y_scores))
        
        return window
    
    def _analyze_trend(self, values: List[float]) -> str:
        """Analyze trend in a series of values."""
        if len(values) < 2:
            return "stable"
        
        # Simple linear trend
        x = np.arange(len(values))
        slope = np.polyfit(x, values, 1)[0]
        
        if slope > self.drift_threshold / len(values):
            return "improving"
        elif slope < -self.drift_threshold / len(values):
            return "declining"
        else:
            return "stable"
    
    def _detect_drift(
        self,
        windows: List[TimeWindow],
        y_true: np.ndarray,
        y_scores: np.ndarray,
    ) -> DriftDetectionResult:
        """Detect concept and data drift."""
        result = DriftDetectionResult()
        
        if len(windows) < 2:
            return result
        
        # Compare first half vs second half
        mid = len(windows) // 2
        first_half = windows[:mid]
        second_half = windows[mid:]
        
        # Concept drift: change in positive rate
        first_pos_rate = sum(w.positive_samples for w in first_half) / sum(w.total_samples for w in first_half)
        second_pos_rate = sum(w.positive_samples for w in second_half) / sum(w.total_samples for w in second_half)
        
        result.positive_rate_change = second_pos_rate - first_pos_rate
        
        if abs(result.positive_rate_change) > 0.05:  # 5% change
            result.concept_drift_detected = True
            result.concept_drift_score = abs(result.positive_rate_change)
        
        # Performance drift
        first_acc = np.mean([w.accuracy for w in first_half])
        second_acc = np.mean([w.accuracy for w in second_half])
        first_recall = np.mean([w.recall for w in first_half])
        second_recall = np.mean([w.recall for w in second_half])
        first_f1 = np.mean([w.f1_score for w in first_half])
        second_f1 = np.mean([w.f1_score for w in second_half])
        
        result.accuracy_change = second_acc - first_acc
        result.recall_change = second_recall - first_recall
        result.f1_change = second_f1 - first_f1
        
        if abs(result.f1_change) > self.drift_threshold:
            result.performance_drift_detected = True
        
        # Statistical tests (if scipy available)
        if SCIPY_AVAILABLE:
            # Split scores
            n = len(y_scores)
            first_scores = y_scores[:n//2]
            second_scores = y_scores[n//2:]
            
            # KS test for score distribution drift
            ks_stat, ks_p = stats.ks_2samp(first_scores, second_scores)
            result.ks_statistic = float(ks_stat)
            result.ks_pvalue = float(ks_p)
            
            if ks_p < 0.05:
                result.data_drift_detected = True
                result.data_drift_score = float(ks_stat)
            
            # Chi-squared test for label drift
            first_labels = y_true[:n//2]
            second_labels = y_true[n//2:]
            
            first_counts = [np.sum(first_labels == 0), np.sum(first_labels == 1)]
            second_counts = [np.sum(second_labels == 0), np.sum(second_labels == 1)]
            
            chi2, chi2_p = stats.chisquare(second_counts, first_counts)
            result.chi2_statistic = float(chi2) if not np.isnan(chi2) else 0.0
            result.chi2_pvalue = float(chi2_p) if not np.isnan(chi2_p) else 1.0
        
        # Overall drift assessment
        result.drift_detected = (
            result.concept_drift_detected or
            result.data_drift_detected or
            result.performance_drift_detected
        )
        
        if result.drift_detected:
            # Determine severity
            severity_score = (
                abs(result.f1_change) + 
                result.concept_drift_score + 
                result.data_drift_score
            )
            
            if severity_score > 0.2:
                result.drift_severity = "high"
            elif severity_score > 0.1:
                result.drift_severity = "medium"
            else:
                result.drift_severity = "low"
            
            # Determine type
            types = []
            if result.concept_drift_detected:
                types.append("concept")
            if result.data_drift_detected:
                types.append("data")
            if result.performance_drift_detected:
                types.append("performance")
            result.drift_type = "+".join(types)
        
        # Generate recommendations
        if result.concept_drift_detected:
            result.recommendations.append(
                f"⚠️ Fraud rate changed by {result.positive_rate_change*100:+.1f}% - review detection thresholds"
            )
        
        if result.data_drift_detected:
            result.recommendations.append(
                "⚠️ Input distribution has shifted - consider retraining with recent data"
            )
        
        if result.performance_drift_detected and result.f1_change < 0:
            result.recommendations.append(
                f"🔴 F1 score declined by {abs(result.f1_change)*100:.1f}% - model may be stale"
            )
        
        return result
    
    def _calculate_staleness(self, windows: List[TimeWindow]) -> float:
        """Calculate model staleness score (0-1)."""
        if len(windows) < 3:
            return 0.0
        
        # Compare recent performance to historical best
        f1_scores = [w.f1_score for w in windows]
        
        best_f1 = max(f1_scores)
        recent_f1 = np.mean(f1_scores[-3:])  # Last 3 windows
        
        if best_f1 > 0:
            staleness = (best_f1 - recent_f1) / best_f1
            return float(np.clip(staleness, 0, 1))
        
        return 0.0


def print_temporal_report(report: TemporalReport) -> None:
    """Print a formatted temporal analysis report."""
    print("\n" + "=" * 70)
    print("              TEMPORAL ANALYSIS REPORT")
    print("=" * 70)
    
    print(f"\nAnalysis Period: {report.analysis_start} to {report.analysis_end}")
    print(f"Total Windows: {report.total_windows}")
    
    print("\n" + "-" * 70)
    print("PERFORMANCE TRENDS")
    print("-" * 70)
    
    trend_icon = {"improving": "📈", "stable": "➡️", "declining": "📉"}
    print(f"  Accuracy: {trend_icon.get(report.accuracy_trend, '?')} {report.accuracy_trend}")
    print(f"  Recall:   {trend_icon.get(report.recall_trend, '?')} {report.recall_trend}")
    print(f"  Fraud Rate: {trend_icon.get(report.positive_rate_trend, '?')} {report.positive_rate_trend}")
    
    print("\n" + "-" * 70)
    print("PER-WINDOW METRICS")
    print("-" * 70)
    print(f"  {'Window':<10} {'Samples':>8} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print(f"  {'-'*10} {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    
    for w in report.windows:
        print(f"  {w.window_id:<10} {w.total_samples:>8} {w.accuracy*100:>9.1f}% {w.precision*100:>9.1f}% {w.recall*100:>9.1f}% {w.f1_score*100:>9.1f}%")
    
    if report.drift_result.drift_detected:
        print("\n" + "-" * 70)
        print("⚠️ DRIFT DETECTED")
        print("-" * 70)
        print(f"  Severity: {report.drift_result.drift_severity.upper()}")
        print(f"  Type: {report.drift_result.drift_type}")
        
        if report.drift_result.recommendations:
            print("\n  Recommendations:")
            for rec in report.drift_result.recommendations:
                print(f"    {rec}")
    
    print("\n" + "-" * 70)
    print("MODEL HEALTH")
    print("-" * 70)
    print(f"  Staleness Score: {report.model_staleness_score*100:.1f}%")
    print(f"  Days Since Best: {report.days_since_best_performance}")
    print(f"  Retrain Recommended: {'Yes ⚠️' if report.recommended_retrain else 'No ✅'}")
    
    if report.predicted_performance_next_week:
        print("\n  Predicted Next Week:")
        for metric, value in report.predicted_performance_next_week.items():
            print(f"    {metric}: {value*100:.1f}%")
    
    print("\n" + "=" * 70 + "\n")

