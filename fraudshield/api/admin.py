"""
Admin API endpoints for FraudShield management.

Includes:
- Blacklist/whitelist management
- A/B testing management
- Metrics and monitoring
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from fraudshield.api.security import verify_api_token
from fraudshield.services.lists_service import pattern_lists, ListType
from fraudshield.services.ab_testing import ab_testing_service, Variant, ExperimentStatus
from fraudshield.services.velocity_service import velocity_tracker
from fraudshield.utils.logging_config import metrics


router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(verify_api_token)],
)


# ============== SCHEMAS ==============


class AddToListRequest(BaseModel):
    value: str
    category: str = "domains"
    is_regex: bool = False


class RemoveFromListRequest(BaseModel):
    value: str
    category: str = "domains"


class ListStatsResponse(BaseModel):
    blacklist_domains: int
    blacklist_urls: int
    blacklist_patterns: int
    whitelist_domains: int
    whitelist_urls: int


class CreateExperimentRequest(BaseModel):
    id: str
    name: str
    description: str = ""
    variants: Optional[Dict[str, Dict[str, Any]]] = None
    traffic_percentage: float = 100.0


class ExperimentResponse(BaseModel):
    experiment_id: str
    name: str
    status: str
    variants: Dict[str, Any]
    winner: Optional[str] = None


# ============== BLACKLIST/WHITELIST ENDPOINTS ==============


@router.post("/blacklist")
async def add_to_blacklist(request: AddToListRequest):
    """Add a domain, URL, or pattern to the blacklist."""
    success = pattern_lists.add_to_blacklist(
        value=request.value,
        category=request.category,
        is_regex=request.is_regex,
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to add to blacklist. Invalid category or regex pattern.",
        )
    
    return {
        "message": "Successfully added to blacklist",
        "value": request.value,
        "category": request.category,
        "is_regex": request.is_regex,
    }


@router.delete("/blacklist")
async def remove_from_blacklist(request: RemoveFromListRequest):
    """Remove a domain or URL from the blacklist."""
    success = pattern_lists.remove_from_blacklist(
        value=request.value,
        category=request.category,
    )
    
    return {
        "message": "Removed from blacklist" if success else "Value not found in blacklist",
        "value": request.value,
        "category": request.category,
    }


@router.post("/whitelist")
async def add_to_whitelist(request: AddToListRequest):
    """Add a domain, URL, or pattern to the whitelist."""
    success = pattern_lists.add_to_whitelist(
        value=request.value,
        category=request.category,
        is_regex=request.is_regex,
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to add to whitelist. Invalid category or regex pattern.",
        )
    
    return {
        "message": "Successfully added to whitelist",
        "value": request.value,
        "category": request.category,
        "is_regex": request.is_regex,
    }


@router.delete("/whitelist")
async def remove_from_whitelist(request: RemoveFromListRequest):
    """Remove a domain or URL from the whitelist."""
    success = pattern_lists.remove_from_whitelist(
        value=request.value,
        category=request.category,
    )
    
    return {
        "message": "Removed from whitelist" if success else "Value not found in whitelist",
        "value": request.value,
        "category": request.category,
    }


@router.get("/lists/stats", response_model=ListStatsResponse)
async def get_lists_stats():
    """Get statistics about blacklist and whitelist."""
    return pattern_lists.get_stats()


@router.get("/lists/check")
async def check_value(value: str, check_type: str = "url"):
    """Check if a value matches blacklist or whitelist."""
    if check_type == "url":
        result = pattern_lists.check_url(value)
    elif check_type == "content":
        result = pattern_lists.check_content_hash(value)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="check_type must be 'url' or 'content'",
        )
    
    return {
        "value": value,
        "matched": result.matched,
        "list_type": result.list_type.value if result.list_type else None,
        "pattern": result.pattern,
        "category": result.category,
        "risk_override": result.risk_override,
    }


# ============== A/B TESTING ENDPOINTS ==============


@router.post("/experiments")
async def create_experiment(request: CreateExperimentRequest):
    """Create a new A/B testing experiment."""
    try:
        variants = None
        if request.variants:
            variants = {
                name: Variant(
                    name=name,
                    weight=data.get("weight", 1.0),
                    config=data.get("config", {}),
                )
                for name, data in request.variants.items()
            }
        
        experiment = ab_testing_service.create_experiment(
            id=request.id,
            name=request.name,
            description=request.description,
            variants=variants,
            traffic_percentage=request.traffic_percentage,
        )
        
        return {
            "message": "Experiment created",
            "experiment_id": experiment.id,
            "name": experiment.name,
            "status": experiment.status.value,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/experiments")
async def list_experiments():
    """List all A/B testing experiments."""
    experiments = ab_testing_service.list_experiments()
    return {
        "experiments": [
            {
                "id": exp.id,
                "name": exp.name,
                "status": exp.status.value,
                "traffic_percentage": exp.traffic_percentage,
                "variants": list(exp.variants.keys()),
            }
            for exp in experiments
        ]
    }


@router.get("/experiments/{experiment_id}")
async def get_experiment(experiment_id: str):
    """Get details and results of an experiment."""
    results = ab_testing_service.get_results(experiment_id)
    
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment {experiment_id} not found",
        )
    
    return results


@router.post("/experiments/{experiment_id}/start")
async def start_experiment(experiment_id: str):
    """Start an experiment."""
    success = ab_testing_service.start_experiment(experiment_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment {experiment_id} not found",
        )
    
    return {"message": "Experiment started", "experiment_id": experiment_id}


@router.post("/experiments/{experiment_id}/pause")
async def pause_experiment(experiment_id: str):
    """Pause an experiment."""
    success = ab_testing_service.pause_experiment(experiment_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment {experiment_id} not found",
        )
    
    return {"message": "Experiment paused", "experiment_id": experiment_id}


@router.post("/experiments/{experiment_id}/complete")
async def complete_experiment(experiment_id: str):
    """Complete an experiment and determine winner."""
    success = ab_testing_service.complete_experiment(experiment_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment {experiment_id} not found",
        )
    
    results = ab_testing_service.get_results(experiment_id)
    return {
        "message": "Experiment completed",
        "experiment_id": experiment_id,
        "winner": results.get("winner") if results else None,
    }


@router.delete("/experiments/{experiment_id}")
async def delete_experiment(experiment_id: str):
    """Delete an experiment."""
    success = ab_testing_service.delete_experiment(experiment_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment {experiment_id} not found",
        )
    
    return {"message": "Experiment deleted", "experiment_id": experiment_id}


# ============== METRICS ENDPOINTS ==============


@router.get("/metrics")
async def get_metrics():
    """Get current application metrics."""
    return metrics.get_stats()


@router.get("/velocity/stats")
async def get_velocity_stats():
    """Get velocity tracker statistics."""
    return velocity_tracker.get_stats()


@router.post("/metrics/reset")
async def reset_metrics():
    """Reset all metrics (use with caution)."""
    metrics.reset()
    return {"message": "Metrics reset"}


