"""
A/B Testing Framework for FraudShield.

Allows comparing different model versions, prompts, or configurations
to measure their effectiveness.
"""

import hashlib
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class ExperimentStatus(str, Enum):
    DRAFT = "draft"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"


@dataclass
class Variant:
    """A variant in an A/B test."""
    name: str
    weight: float = 1.0  # Relative traffic weight
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Metrics
    impressions: int = 0
    conversions: int = 0  # e.g., correct predictions confirmed by feedback
    total_score: float = 0.0
    
    @property
    def conversion_rate(self) -> float:
        return self.conversions / self.impressions if self.impressions > 0 else 0.0
    
    @property
    def avg_score(self) -> float:
        return self.total_score / self.impressions if self.impressions > 0 else 0.0


@dataclass
class Experiment:
    """An A/B test experiment."""
    id: str
    name: str
    description: str
    variants: Dict[str, Variant]
    status: ExperimentStatus = ExperimentStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    
    # Targeting
    traffic_percentage: float = 100.0  # % of traffic to include
    
    def get_total_weight(self) -> float:
        return sum(v.weight for v in self.variants.values())
    
    def select_variant(self, user_id: Optional[str] = None) -> Optional[Variant]:
        """
        Select a variant for a user.
        Uses consistent hashing if user_id provided, otherwise random.
        """
        if self.status != ExperimentStatus.RUNNING:
            return None
        
        # Check traffic percentage
        if random.random() * 100 > self.traffic_percentage:
            return None
        
        total_weight = self.get_total_weight()
        if total_weight == 0:
            return None
        
        # Consistent assignment based on user_id
        if user_id:
            hash_input = f"{self.id}:{user_id}"
            hash_value = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
            random_value = (hash_value % 10000) / 10000
        else:
            random_value = random.random()
        
        cumulative = 0.0
        for variant in self.variants.values():
            cumulative += variant.weight / total_weight
            if random_value < cumulative:
                return variant
        
        return list(self.variants.values())[-1]


class ABTestingService:
    """
    Manages A/B testing experiments.
    
    Usage:
        ab = ABTestingService()
        
        # Create experiment
        ab.create_experiment(
            id="prompt_v2_test",
            name="New Prompt Testing",
            variants={
                "control": Variant(name="control", config={"prompt_version": "v1"}),
                "treatment": Variant(name="treatment", config={"prompt_version": "v2"}),
            }
        )
        
        # Start experiment
        ab.start_experiment("prompt_v2_test")
        
        # Get variant for user
        variant = ab.get_variant("prompt_v2_test", user_id="user123")
        
        # Track metrics
        ab.track_impression("prompt_v2_test", "control")
        ab.track_conversion("prompt_v2_test", "control")
    """
    
    def __init__(self):
        self._experiments: Dict[str, Experiment] = {}
        self._user_assignments: Dict[str, Dict[str, str]] = defaultdict(dict)  # user_id -> {exp_id: variant_name}
    
    def create_experiment(
        self,
        id: str,
        name: str,
        description: str = "",
        variants: Optional[Dict[str, Variant]] = None,
        traffic_percentage: float = 100.0,
    ) -> Experiment:
        """Create a new experiment."""
        if id in self._experiments:
            raise ValueError(f"Experiment {id} already exists")
        
        if variants is None:
            variants = {
                "control": Variant(name="control"),
                "treatment": Variant(name="treatment"),
            }
        
        experiment = Experiment(
            id=id,
            name=name,
            description=description,
            variants=variants,
            traffic_percentage=traffic_percentage,
        )
        
        self._experiments[id] = experiment
        logger.info(f"Created experiment: {id}")
        return experiment
    
    def start_experiment(self, experiment_id: str) -> bool:
        """Start an experiment."""
        if experiment_id not in self._experiments:
            return False
        
        exp = self._experiments[experiment_id]
        if exp.status == ExperimentStatus.RUNNING:
            return True
        
        exp.status = ExperimentStatus.RUNNING
        exp.started_at = datetime.utcnow()
        logger.info(f"Started experiment: {experiment_id}")
        return True
    
    def pause_experiment(self, experiment_id: str) -> bool:
        """Pause an experiment."""
        if experiment_id not in self._experiments:
            return False
        
        self._experiments[experiment_id].status = ExperimentStatus.PAUSED
        logger.info(f"Paused experiment: {experiment_id}")
        return True
    
    def complete_experiment(self, experiment_id: str) -> bool:
        """Complete an experiment."""
        if experiment_id not in self._experiments:
            return False
        
        exp = self._experiments[experiment_id]
        exp.status = ExperimentStatus.COMPLETED
        exp.ended_at = datetime.utcnow()
        logger.info(f"Completed experiment: {experiment_id}")
        return True
    
    def get_variant(
        self,
        experiment_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[Variant]:
        """Get the variant for a user in an experiment."""
        if experiment_id not in self._experiments:
            return None
        
        exp = self._experiments[experiment_id]
        
        # Check if user already assigned
        if user_id and user_id in self._user_assignments:
            variant_name = self._user_assignments[user_id].get(experiment_id)
            if variant_name and variant_name in exp.variants:
                return exp.variants[variant_name]
        
        # Select new variant
        variant = exp.select_variant(user_id)
        
        # Store assignment
        if variant and user_id:
            self._user_assignments[user_id][experiment_id] = variant.name
        
        return variant
    
    def track_impression(self, experiment_id: str, variant_name: str) -> bool:
        """Track an impression for a variant."""
        if experiment_id not in self._experiments:
            return False
        
        exp = self._experiments[experiment_id]
        if variant_name not in exp.variants:
            return False
        
        exp.variants[variant_name].impressions += 1
        return True
    
    def track_conversion(self, experiment_id: str, variant_name: str) -> bool:
        """Track a conversion for a variant."""
        if experiment_id not in self._experiments:
            return False
        
        exp = self._experiments[experiment_id]
        if variant_name not in exp.variants:
            return False
        
        exp.variants[variant_name].conversions += 1
        return True
    
    def track_score(self, experiment_id: str, variant_name: str, score: float) -> bool:
        """Track a score for a variant."""
        if experiment_id not in self._experiments:
            return False
        
        exp = self._experiments[experiment_id]
        if variant_name not in exp.variants:
            return False
        
        exp.variants[variant_name].total_score += score
        return True
    
    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        """Get an experiment by ID."""
        return self._experiments.get(experiment_id)
    
    def list_experiments(self) -> List[Experiment]:
        """List all experiments."""
        return list(self._experiments.values())
    
    def get_results(self, experiment_id: str) -> Optional[Dict[str, Any]]:
        """Get results for an experiment."""
        if experiment_id not in self._experiments:
            return None
        
        exp = self._experiments[experiment_id]
        
        variants_data = {}
        for name, variant in exp.variants.items():
            variants_data[name] = {
                "impressions": variant.impressions,
                "conversions": variant.conversions,
                "conversion_rate": round(variant.conversion_rate, 4),
                "avg_score": round(variant.avg_score, 2),
                "config": variant.config,
            }
        
        # Find winner (highest conversion rate)
        winner = None
        if exp.status == ExperimentStatus.COMPLETED:
            winner = max(
                exp.variants.keys(),
                key=lambda k: exp.variants[k].conversion_rate,
            )
        
        return {
            "experiment_id": exp.id,
            "name": exp.name,
            "status": exp.status.value,
            "started_at": exp.started_at.isoformat() if exp.started_at else None,
            "ended_at": exp.ended_at.isoformat() if exp.ended_at else None,
            "variants": variants_data,
            "winner": winner,
        }
    
    def delete_experiment(self, experiment_id: str) -> bool:
        """Delete an experiment."""
        if experiment_id not in self._experiments:
            return False
        
        del self._experiments[experiment_id]
        logger.info(f"Deleted experiment: {experiment_id}")
        return True


# Global A/B testing service instance
ab_testing_service = ABTestingService()


# Pre-configured experiments for common use cases
def setup_default_experiments():
    """Set up default experiments."""
    
    # Model comparison experiment
    if "model_comparison" not in [e.id for e in ab_testing_service.list_experiments()]:
        ab_testing_service.create_experiment(
            id="model_comparison",
            name="GPT-4o-mini vs GPT-4o",
            description="Compare accuracy between GPT-4o-mini and GPT-4o",
            variants={
                "gpt4o_mini": Variant(
                    name="gpt4o_mini",
                    config={"model": "gpt-4o-mini"},
                ),
                "gpt4o": Variant(
                    name="gpt4o",
                    weight=0.1,  # Only 10% traffic to expensive model
                    config={"model": "gpt-4o"},
                ),
            },
            traffic_percentage=10.0,  # Only 10% of all requests
        )
    
    # Prompt variation experiment
    if "prompt_v2" not in [e.id for e in ab_testing_service.list_experiments()]:
        ab_testing_service.create_experiment(
            id="prompt_v2",
            name="New Prompt Testing",
            description="Test improved fraud detection prompt",
            variants={
                "control": Variant(
                    name="control",
                    config={"prompt_version": "v1"},
                ),
                "treatment": Variant(
                    name="treatment",
                    config={"prompt_version": "v2"},
                ),
            },
        )


