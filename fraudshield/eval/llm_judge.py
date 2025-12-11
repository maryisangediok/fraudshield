# fraudshield/eval/llm_judge.py
"""
LLM-as-a-Judge evaluation for FraudShield.

Uses GPT-4o-mini to evaluate:
- Explanation quality
- Indicator relevance
- User-friendliness
- FP/FN root cause analysis
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any

from openai import OpenAI


@dataclass
class JudgeScores:
    """Scores from LLM judge evaluation."""
    sample_id: str
    
    # Quality scores (1-5 scale)
    explanation_quality: int = 0
    indicator_relevance: int = 0
    user_friendliness: int = 0
    overall_quality: float = 0.0
    
    # Detailed feedback
    explanation_feedback: str = ""
    indicator_feedback: str = ""
    improvement_suggestions: List[str] = field(default_factory=list)
    
    # Metadata
    ground_truth: str = ""
    prediction: str = ""
    is_correct: bool = False
    
    # Error handling
    success: bool = True
    error: Optional[str] = None


@dataclass 
class FPFNAnalysis:
    """Root cause analysis for false positives/negatives."""
    sample_id: str
    error_type: str  # "FP" or "FN"
    
    # Analysis
    root_cause: str = ""
    severity: str = ""  # "low", "medium", "high"
    category: str = ""  # e.g., "edge_case", "label_error", "model_limitation"
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    similar_patterns: List[str] = field(default_factory=list)
    
    # Raw content for reference
    content: str = ""
    indicators: List[str] = field(default_factory=list)
    
    success: bool = True
    error: Optional[str] = None


class LLMJudge:
    """LLM-based evaluation judge using OpenAI."""
    
    QUALITY_PROMPT = """You are an expert evaluator for a fraud/phishing detection system.

Evaluate the following detection result and provide scores from 1-5 for each criterion:

## Input Content
Type: {content_type}
Content: {content}

## Detection Result
Risk Level: {risk_level}
Confidence Score: {score}
Indicators Found: {indicators}

## Ground Truth
Actual Label: {ground_truth}
Prediction Correct: {is_correct}

## Evaluation Criteria

1. **Explanation Quality (1-5)**: How well do the indicators explain WHY this was flagged?
   - 5: Excellent - Clear, specific, actionable reasoning
   - 3: Adequate - Some useful information but incomplete
   - 1: Poor - Vague, generic, or misleading

2. **Indicator Relevance (1-5)**: Are the detected indicators actually suspicious for this content?
   - 5: All indicators are highly relevant and accurate
   - 3: Some indicators are relevant, others are noise
   - 1: Indicators are mostly irrelevant or wrong

3. **User-Friendliness (1-5)**: Would a non-technical user understand and trust this result?
   - 5: Crystal clear, builds confidence in the system
   - 3: Understandable but could be clearer
   - 1: Confusing, would frustrate users

Respond in JSON format:
{{
    "explanation_quality": <1-5>,
    "indicator_relevance": <1-5>,
    "user_friendliness": <1-5>,
    "explanation_feedback": "<brief feedback on explanation>",
    "indicator_feedback": "<brief feedback on indicators>",
    "improvement_suggestions": ["<suggestion 1>", "<suggestion 2>"]
}}"""

    FPFN_ANALYSIS_PROMPT = """You are an expert analyst reviewing errors in a fraud/phishing detection system.

Analyze this {error_type} and provide root cause analysis:

## Content That Was Misclassified
Type: {content_type}
Content: {content}

## Detection Result
Risk Level Predicted: {risk_level}
Confidence Score: {score}
Indicators Found: {indicators}

## Error Details
- Ground Truth: {ground_truth}
- Prediction: {prediction}
- Error Type: {error_type_full}

## Analysis Required

Provide a detailed root cause analysis:

1. **Root Cause**: Why did the model make this mistake?
2. **Severity**: How bad is this error? (low/medium/high)
   - High: Could cause significant harm (miss dangerous phishing, block legitimate transaction)
   - Medium: Noticeable issue but manageable
   - Low: Minor edge case
3. **Category**: Classify the error type:
   - "edge_case": Unusual content that's hard to classify
   - "label_error": The ground truth label might be wrong
   - "model_limitation": Known weakness in detection approach
   - "adversarial": Appears deliberately crafted to evade detection
   - "context_missing": Needed external context to classify correctly
4. **Recommendations**: How to prevent similar errors

Respond in JSON format:
{{
    "root_cause": "<detailed explanation>",
    "severity": "<low|medium|high>",
    "category": "<category>",
    "recommendations": ["<rec 1>", "<rec 2>"],
    "similar_patterns": ["<pattern that might cause same error>"]
}}"""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        temperature: float = 0.3,
        max_retries: int = 2,
    ):
        """Initialize the LLM judge.
        
        Args:
            model: OpenAI model to use (default: gpt-4o-mini for cost efficiency)
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            temperature: Sampling temperature (lower = more consistent)
            max_retries: Number of retries on failure
        """
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        
        api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY env var.")
        
        self.client = OpenAI(api_key=api_key)
    
    def _call_llm(self, prompt: str) -> Dict[str, Any]:
        """Call the LLM and parse JSON response."""
        for attempt in range(self.max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a precise evaluator. Always respond with valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.temperature,
                    response_format={"type": "json_object"},
                )
                
                content = response.choices[0].message.content
                return json.loads(content)
                
            except Exception as e:
                if attempt == self.max_retries:
                    raise e
        
        return {}
    
    def evaluate_quality(
        self,
        sample_id: str,
        content: str,
        content_type: str,
        risk_level: str,
        score: float,
        indicators: List[str],
        ground_truth: str,
        is_correct: bool,
    ) -> JudgeScores:
        """Evaluate the quality of a detection result.
        
        Args:
            sample_id: Unique identifier for the sample
            content: The original content (URL, text, etc.)
            content_type: Type of content ("url", "sms", "email")
            risk_level: Predicted risk level
            score: Confidence score (0-1)
            indicators: List of detected indicators
            ground_truth: Actual label
            is_correct: Whether prediction was correct
            
        Returns:
            JudgeScores with quality ratings and feedback
        """
        try:
            prompt = self.QUALITY_PROMPT.format(
                content_type=content_type,
                content=content[:1000],  # Truncate for token limits
                risk_level=risk_level,
                score=f"{score:.2f}",
                indicators=", ".join(indicators) if indicators else "None",
                ground_truth=ground_truth,
                is_correct="Yes" if is_correct else "No",
            )
            
            result = self._call_llm(prompt)
            
            return JudgeScores(
                sample_id=sample_id,
                explanation_quality=int(result.get("explanation_quality", 0)),
                indicator_relevance=int(result.get("indicator_relevance", 0)),
                user_friendliness=int(result.get("user_friendliness", 0)),
                overall_quality=(
                    int(result.get("explanation_quality", 0)) +
                    int(result.get("indicator_relevance", 0)) +
                    int(result.get("user_friendliness", 0))
                ) / 3.0,
                explanation_feedback=result.get("explanation_feedback", ""),
                indicator_feedback=result.get("indicator_feedback", ""),
                improvement_suggestions=result.get("improvement_suggestions", []),
                ground_truth=ground_truth,
                prediction=risk_level,
                is_correct=is_correct,
                success=True,
            )
            
        except Exception as e:
            return JudgeScores(
                sample_id=sample_id,
                ground_truth=ground_truth,
                prediction=risk_level,
                is_correct=is_correct,
                success=False,
                error=str(e),
            )
    
    def analyze_error(
        self,
        sample_id: str,
        content: str,
        content_type: str,
        risk_level: str,
        score: float,
        indicators: List[str],
        ground_truth: str,
        prediction: str,
        error_type: str,  # "FP" or "FN"
    ) -> FPFNAnalysis:
        """Analyze a false positive or false negative.
        
        Args:
            sample_id: Unique identifier
            content: Original content
            content_type: Type of content
            risk_level: Predicted risk level
            score: Confidence score
            indicators: Detected indicators
            ground_truth: Actual label
            prediction: What was predicted
            error_type: "FP" for false positive, "FN" for false negative
            
        Returns:
            FPFNAnalysis with root cause and recommendations
        """
        error_type_full = "False Positive (flagged benign as suspicious)" if error_type == "FP" else "False Negative (missed actual phishing/fraud)"
        
        try:
            prompt = self.FPFN_ANALYSIS_PROMPT.format(
                error_type=error_type,
                content_type=content_type,
                content=content[:1000],
                risk_level=risk_level,
                score=f"{score:.2f}",
                indicators=", ".join(indicators) if indicators else "None",
                ground_truth=ground_truth,
                prediction=prediction,
                error_type_full=error_type_full,
            )
            
            result = self._call_llm(prompt)
            
            return FPFNAnalysis(
                sample_id=sample_id,
                error_type=error_type,
                root_cause=result.get("root_cause", ""),
                severity=result.get("severity", "medium"),
                category=result.get("category", "unknown"),
                recommendations=result.get("recommendations", []),
                similar_patterns=result.get("similar_patterns", []),
                content=content[:500],
                indicators=indicators,
                success=True,
            )
            
        except Exception as e:
            return FPFNAnalysis(
                sample_id=sample_id,
                error_type=error_type,
                content=content[:500],
                indicators=indicators,
                success=False,
                error=str(e),
            )


@dataclass
class JudgeReport:
    """Aggregated report from LLM judge evaluation."""
    total_evaluated: int = 0
    successful_evaluations: int = 0
    failed_evaluations: int = 0
    
    # Average scores
    avg_explanation_quality: float = 0.0
    avg_indicator_relevance: float = 0.0
    avg_user_friendliness: float = 0.0
    avg_overall_quality: float = 0.0
    
    # Score distributions
    score_distribution: Dict[str, Dict[int, int]] = field(default_factory=dict)
    
    # Common issues
    common_improvement_suggestions: List[Dict[str, Any]] = field(default_factory=list)
    
    # FP/FN analysis summary
    fp_analysis_count: int = 0
    fn_analysis_count: int = 0
    error_categories: Dict[str, int] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    top_recommendations: List[str] = field(default_factory=list)
    
    # Individual results
    quality_scores: List[Dict] = field(default_factory=list)
    error_analyses: List[Dict] = field(default_factory=list)


def aggregate_judge_results(
    quality_scores: List[JudgeScores],
    error_analyses: List[FPFNAnalysis],
) -> JudgeReport:
    """Aggregate individual judge results into a summary report."""
    report = JudgeReport()
    
    # Quality scores aggregation
    successful_scores = [s for s in quality_scores if s.success]
    report.total_evaluated = len(quality_scores)
    report.successful_evaluations = len(successful_scores)
    report.failed_evaluations = len(quality_scores) - len(successful_scores)
    
    if successful_scores:
        report.avg_explanation_quality = sum(s.explanation_quality for s in successful_scores) / len(successful_scores)
        report.avg_indicator_relevance = sum(s.indicator_relevance for s in successful_scores) / len(successful_scores)
        report.avg_user_friendliness = sum(s.user_friendliness for s in successful_scores) / len(successful_scores)
        report.avg_overall_quality = sum(s.overall_quality for s in successful_scores) / len(successful_scores)
        
        # Score distributions
        for metric in ["explanation_quality", "indicator_relevance", "user_friendliness"]:
            report.score_distribution[metric] = {i: 0 for i in range(1, 6)}
            for s in successful_scores:
                score = getattr(s, metric)
                if 1 <= score <= 5:
                    report.score_distribution[metric][score] += 1
        
        # Common suggestions
        suggestion_counts: Dict[str, int] = {}
        for s in successful_scores:
            for suggestion in s.improvement_suggestions:
                suggestion_counts[suggestion] = suggestion_counts.get(suggestion, 0) + 1
        
        report.common_improvement_suggestions = [
            {"suggestion": k, "count": v}
            for k, v in sorted(suggestion_counts.items(), key=lambda x: -x[1])[:10]
        ]
    
    # Error analysis aggregation
    successful_analyses = [a for a in error_analyses if a.success]
    report.fp_analysis_count = sum(1 for a in successful_analyses if a.error_type == "FP")
    report.fn_analysis_count = sum(1 for a in successful_analyses if a.error_type == "FN")
    
    for a in successful_analyses:
        report.error_categories[a.category] = report.error_categories.get(a.category, 0) + 1
        report.severity_distribution[a.severity] = report.severity_distribution.get(a.severity, 0) + 1
    
    # Top recommendations
    rec_counts: Dict[str, int] = {}
    for a in successful_analyses:
        for rec in a.recommendations:
            rec_counts[rec] = rec_counts.get(rec, 0) + 1
    
    report.top_recommendations = [
        k for k, v in sorted(rec_counts.items(), key=lambda x: -x[1])[:10]
    ]
    
    # Store individual results
    report.quality_scores = [asdict(s) for s in quality_scores]
    report.error_analyses = [asdict(a) for a in error_analyses]
    
    return report

