# fraudshield/eval/business_metrics.py
"""
Business impact metrics for fraud detection.

Translates model performance into business outcomes:
- Dollar value of fraud blocked
- Cost of false positives (customer friction)
- ROI calculations
- Operational efficiency metrics
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import numpy as np


@dataclass
class FraudValueConfig:
    """Configuration for fraud value calculations."""
    
    # Average fraud amount (if not provided per-sample)
    avg_fraud_amount: float = 500.0
    
    # False positive costs
    fp_investigation_cost: float = 15.0      # Cost to investigate false alert
    fp_customer_friction_cost: float = 25.0  # Customer experience cost
    fp_churn_probability: float = 0.02       # Probability customer churns after FP
    customer_lifetime_value: float = 1500.0  # CLV for churn calculation
    
    # Operational costs
    cost_per_analysis: float = 0.01          # API/infrastructure cost per check
    analyst_hourly_rate: float = 50.0        # For manual review calculations
    avg_review_time_minutes: float = 5.0     # Time to manually review flagged item
    
    # Recovery rates
    fraud_recovery_rate: float = 0.15        # % of caught fraud recovered
    
    # Time value
    detection_delay_cost_per_hour: float = 10.0  # Cost of delayed detection


@dataclass
class BusinessImpactMetrics:
    """Business impact metrics in dollar terms."""
    
    # Fraud value metrics
    total_fraud_value: float = 0.0           # Total $ value of fraud in dataset
    fraud_blocked_value: float = 0.0         # $ value of fraud correctly blocked
    fraud_missed_value: float = 0.0          # $ value of fraud that got through (FN)
    fraud_blocked_percentage: float = 0.0
    
    # Recovery value
    potential_recovery_value: float = 0.0    # From blocked fraud
    
    # False positive costs
    fp_investigation_cost: float = 0.0
    fp_friction_cost: float = 0.0
    fp_churn_cost: float = 0.0               # Expected cost from customer churn
    total_fp_cost: float = 0.0
    
    # Operational costs
    total_analysis_cost: float = 0.0
    manual_review_cost: float = 0.0          # Cost to review all positives
    total_operational_cost: float = 0.0
    
    # Net impact
    gross_savings: float = 0.0               # Fraud blocked - FN losses
    net_savings: float = 0.0                 # Gross - all costs
    roi_percentage: float = 0.0              # Return on investment
    
    # Efficiency metrics
    cost_per_fraud_caught: float = 0.0
    cost_per_dollar_protected: float = 0.0
    
    # Comparison metrics
    savings_vs_no_detection: float = 0.0     # vs having no system
    savings_vs_flag_all: float = 0.0         # vs flagging everything


@dataclass
class OperationalMetrics:
    """Operational efficiency metrics."""
    
    # Volume metrics
    total_transactions: int = 0
    flagged_transactions: int = 0
    flagged_percentage: float = 0.0
    
    # Review queue metrics
    alerts_per_analyst_hour: float = 0.0
    analysts_needed_per_day: float = 0.0     # Assuming 8-hour day
    review_queue_hours: float = 0.0          # Time to clear all flags
    
    # Precision efficiency
    investigation_efficiency: float = 0.0    # % of investigations that find fraud
    time_wasted_on_fp_hours: float = 0.0
    
    # Throughput
    avg_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    theoretical_max_tps: float = 0.0         # Transactions per second
    
    # Cost efficiency
    cost_per_transaction: float = 0.0
    cost_per_alert: float = 0.0


@dataclass
class BusinessReport:
    """Complete business impact report."""
    
    # Configuration used
    config: FraudValueConfig = field(default_factory=FraudValueConfig)
    
    # Core metrics
    impact: BusinessImpactMetrics = field(default_factory=BusinessImpactMetrics)
    operational: OperationalMetrics = field(default_factory=OperationalMetrics)
    
    # Summary
    executive_summary: str = ""
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Timestamp
    generated_at: str = ""


def compute_business_impact(
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    fraud_amounts: Optional[np.ndarray] = None,
    config: Optional[FraudValueConfig] = None,
    avg_latency_ms: float = 100.0,
) -> BusinessReport:
    """
    Compute comprehensive business impact metrics.
    
    Args:
        tp: True positives (fraud correctly caught)
        fp: False positives (legitimate flagged)
        tn: True negatives (legitimate correctly passed)
        fn: False negatives (fraud missed)
        fraud_amounts: Optional array of fraud amounts for TP+FN cases
        config: Business value configuration
        avg_latency_ms: Average latency for throughput calculation
        
    Returns:
        BusinessReport with all metrics
    """
    if config is None:
        config = FraudValueConfig()
    
    report = BusinessReport(config=config)
    impact = report.impact
    ops = report.operational
    
    total = tp + fp + tn + fn
    total_fraud = tp + fn
    total_legitimate = tn + fp
    total_flagged = tp + fp
    
    # Calculate fraud values
    if fraud_amounts is not None and len(fraud_amounts) > 0:
        # Use actual amounts
        fraud_amounts = np.asarray(fraud_amounts)
        avg_fraud = float(np.mean(fraud_amounts))
        total_fraud_value = float(np.sum(fraud_amounts))
        
        # Assume TP catches proportionally
        if total_fraud > 0:
            fraud_blocked_value = total_fraud_value * (tp / total_fraud)
            fraud_missed_value = total_fraud_value * (fn / total_fraud)
        else:
            fraud_blocked_value = 0
            fraud_missed_value = 0
    else:
        # Use average
        avg_fraud = config.avg_fraud_amount
        total_fraud_value = total_fraud * avg_fraud
        fraud_blocked_value = tp * avg_fraud
        fraud_missed_value = fn * avg_fraud
    
    impact.total_fraud_value = total_fraud_value
    impact.fraud_blocked_value = fraud_blocked_value
    impact.fraud_missed_value = fraud_missed_value
    impact.fraud_blocked_percentage = (
        fraud_blocked_value / total_fraud_value * 100 if total_fraud_value > 0 else 0
    )
    
    # Recovery value (from blocked fraud)
    impact.potential_recovery_value = fraud_blocked_value * config.fraud_recovery_rate
    
    # False positive costs
    impact.fp_investigation_cost = fp * config.fp_investigation_cost
    impact.fp_friction_cost = fp * config.fp_customer_friction_cost
    impact.fp_churn_cost = (
        fp * config.fp_churn_probability * config.customer_lifetime_value
    )
    impact.total_fp_cost = (
        impact.fp_investigation_cost + 
        impact.fp_friction_cost + 
        impact.fp_churn_cost
    )
    
    # Operational costs
    impact.total_analysis_cost = total * config.cost_per_analysis
    
    # Manual review cost (for all flagged items)
    review_hours = total_flagged * (config.avg_review_time_minutes / 60)
    impact.manual_review_cost = review_hours * config.analyst_hourly_rate
    
    impact.total_operational_cost = (
        impact.total_analysis_cost + impact.manual_review_cost
    )
    
    # Net impact calculations
    impact.gross_savings = fraud_blocked_value - fraud_missed_value
    impact.net_savings = (
        fraud_blocked_value + 
        impact.potential_recovery_value - 
        fraud_missed_value - 
        impact.total_fp_cost - 
        impact.total_operational_cost
    )
    
    # ROI (net savings / total cost)
    total_cost = impact.total_fp_cost + impact.total_operational_cost
    if total_cost > 0:
        impact.roi_percentage = (impact.net_savings / total_cost) * 100
    
    # Efficiency metrics
    if tp > 0:
        impact.cost_per_fraud_caught = total_cost / tp
    if fraud_blocked_value > 0:
        impact.cost_per_dollar_protected = total_cost / fraud_blocked_value
    
    # Comparison: vs no detection (all fraud gets through)
    impact.savings_vs_no_detection = fraud_blocked_value - total_cost
    
    # Comparison: vs flagging everything
    flag_all_fp_cost = total_legitimate * (
        config.fp_investigation_cost + 
        config.fp_customer_friction_cost +
        config.fp_churn_probability * config.customer_lifetime_value
    )
    flag_all_review_cost = total * (config.avg_review_time_minutes / 60) * config.analyst_hourly_rate
    flag_all_total_cost = flag_all_fp_cost + flag_all_review_cost
    impact.savings_vs_flag_all = flag_all_total_cost - total_cost - fraud_missed_value
    
    # Operational metrics
    ops.total_transactions = total
    ops.flagged_transactions = total_flagged
    ops.flagged_percentage = (total_flagged / total * 100) if total > 0 else 0
    
    # Review queue
    alerts_per_hour = 60 / config.avg_review_time_minutes
    ops.alerts_per_analyst_hour = alerts_per_hour
    ops.review_queue_hours = total_flagged / alerts_per_hour if alerts_per_hour > 0 else 0
    ops.analysts_needed_per_day = ops.review_queue_hours / 8  # 8-hour day
    
    # Investigation efficiency
    ops.investigation_efficiency = (tp / total_flagged * 100) if total_flagged > 0 else 0
    ops.time_wasted_on_fp_hours = fp * (config.avg_review_time_minutes / 60)
    
    # Throughput
    ops.avg_latency_ms = avg_latency_ms
    ops.theoretical_max_tps = 1000 / avg_latency_ms if avg_latency_ms > 0 else 0
    
    # Cost efficiency
    ops.cost_per_transaction = total_cost / total if total > 0 else 0
    ops.cost_per_alert = total_cost / total_flagged if total_flagged > 0 else 0
    
    # Generate summary
    report.generated_at = datetime.now().isoformat()
    report.executive_summary = _generate_executive_summary(impact, ops, config)
    report.key_findings = _generate_key_findings(impact, ops)
    report.recommendations = _generate_recommendations(impact, ops, tp, fp, fn)
    
    return report


def _generate_executive_summary(
    impact: BusinessImpactMetrics,
    ops: OperationalMetrics,
    config: FraudValueConfig,
) -> str:
    """Generate executive summary text."""
    return f"""
FRAUD DETECTION BUSINESS IMPACT SUMMARY

The fraud detection system analyzed {ops.total_transactions:,} transactions and flagged 
{ops.flagged_transactions:,} ({ops.flagged_percentage:.1f}%) for review.

FINANCIAL IMPACT:
• Total fraud value in dataset: ${impact.total_fraud_value:,.2f}
• Fraud successfully blocked: ${impact.fraud_blocked_value:,.2f} ({impact.fraud_blocked_percentage:.1f}%)
• Fraud missed (false negatives): ${impact.fraud_missed_value:,.2f}
• Net savings after all costs: ${impact.net_savings:,.2f}
• ROI: {impact.roi_percentage:.1f}%

OPERATIONAL EFFICIENCY:
• Investigation efficiency: {ops.investigation_efficiency:.1f}% of alerts are true fraud
• Analysts needed per day: {ops.analysts_needed_per_day:.1f} (at {config.avg_review_time_minutes} min/review)
• Cost per fraud caught: ${impact.cost_per_fraud_caught:.2f}
""".strip()


def _generate_key_findings(
    impact: BusinessImpactMetrics,
    ops: OperationalMetrics,
) -> List[str]:
    """Generate key findings list."""
    findings = []
    
    if impact.fraud_blocked_percentage >= 90:
        findings.append(f"✅ Excellent fraud capture rate: {impact.fraud_blocked_percentage:.1f}%")
    elif impact.fraud_blocked_percentage >= 70:
        findings.append(f"⚠️ Good fraud capture rate: {impact.fraud_blocked_percentage:.1f}% - room for improvement")
    else:
        findings.append(f"🔴 Low fraud capture rate: {impact.fraud_blocked_percentage:.1f}% - significant fraud exposure")
    
    if impact.net_savings > 0:
        findings.append(f"✅ Positive ROI: System saves ${impact.net_savings:,.2f}")
    else:
        findings.append(f"🔴 Negative ROI: System costs ${-impact.net_savings:,.2f} more than it saves")
    
    if ops.investigation_efficiency >= 50:
        findings.append(f"✅ High investigation efficiency: {ops.investigation_efficiency:.1f}% of alerts are real fraud")
    elif ops.investigation_efficiency >= 20:
        findings.append(f"⚠️ Moderate efficiency: {ops.investigation_efficiency:.1f}% of alerts are real fraud")
    else:
        findings.append(f"🔴 Low efficiency: Only {ops.investigation_efficiency:.1f}% of alerts are real fraud - analyst fatigue risk")
    
    if impact.fp_churn_cost > impact.fraud_missed_value:
        findings.append(f"⚠️ False positive churn cost (${impact.fp_churn_cost:,.2f}) exceeds missed fraud cost")
    
    return findings


def _generate_recommendations(
    impact: BusinessImpactMetrics,
    ops: OperationalMetrics,
    tp: int,
    fp: int,
    fn: int,
) -> List[str]:
    """Generate actionable recommendations."""
    recommendations = []
    
    # High FN - missing too much fraud
    if fn > tp * 0.1:  # More than 10% FN rate
        recommendations.append(
            "📉 Lower detection threshold to catch more fraud (currently missing significant amount)"
        )
    
    # High FP - too many false alarms
    if fp > tp * 2:  # More than 2x FP vs TP
        recommendations.append(
            "📈 Raise detection threshold or add features to reduce false positives"
        )
    
    # Low investigation efficiency
    if ops.investigation_efficiency < 30:
        recommendations.append(
            "🔧 Implement alert prioritization to surface high-confidence fraud first"
        )
    
    # High analyst load
    if ops.analysts_needed_per_day > 5:
        recommendations.append(
            f"👥 Consider automation: {ops.analysts_needed_per_day:.1f} analysts needed daily for review"
        )
    
    # Cost optimization
    if impact.cost_per_fraud_caught > impact.fraud_blocked_value / tp if tp > 0 else float('inf'):
        recommendations.append(
            "💰 Cost per fraud caught exceeds average fraud value - optimize for efficiency"
        )
    
    # Recovery opportunity
    if impact.potential_recovery_value > 10000:
        recommendations.append(
            f"💵 Recovery opportunity: ${impact.potential_recovery_value:,.2f} potentially recoverable from blocked fraud"
        )
    
    return recommendations


def print_business_report(report: BusinessReport) -> None:
    """Print a formatted business report."""
    print("\n" + "=" * 70)
    print("              BUSINESS IMPACT REPORT")
    print("=" * 70)
    
    print("\n" + report.executive_summary)
    
    print("\n" + "-" * 70)
    print("KEY FINDINGS")
    print("-" * 70)
    for finding in report.key_findings:
        print(f"  {finding}")
    
    print("\n" + "-" * 70)
    print("RECOMMENDATIONS")
    print("-" * 70)
    for rec in report.recommendations:
        print(f"  {rec}")
    
    print("\n" + "-" * 70)
    print("DETAILED METRICS")
    print("-" * 70)
    
    impact = report.impact
    print(f"""
  Fraud Blocked:              ${impact.fraud_blocked_value:>12,.2f}
  Fraud Missed:               ${impact.fraud_missed_value:>12,.2f}
  Recovery Potential:         ${impact.potential_recovery_value:>12,.2f}
  
  FP Investigation Cost:      ${impact.fp_investigation_cost:>12,.2f}
  FP Friction Cost:           ${impact.fp_friction_cost:>12,.2f}
  FP Churn Cost:              ${impact.fp_churn_cost:>12,.2f}
  Total FP Cost:              ${impact.total_fp_cost:>12,.2f}
  
  Analysis Cost:              ${impact.total_analysis_cost:>12,.2f}
  Manual Review Cost:         ${impact.manual_review_cost:>12,.2f}
  Total Operational Cost:     ${impact.total_operational_cost:>12,.2f}
  
  GROSS SAVINGS:              ${impact.gross_savings:>12,.2f}
  NET SAVINGS:                ${impact.net_savings:>12,.2f}
  ROI:                        {impact.roi_percentage:>12.1f}%
""")
    
    print("=" * 70 + "\n")

