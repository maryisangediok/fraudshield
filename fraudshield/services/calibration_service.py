# fraudshield/services/calibration_service.py
"""
Score calibration using Platt scaling (isotonic regression).

Calibration ensures that when the model outputs 70% confidence,
approximately 70% of those cases are actually fraud.

Usage:
    # Train calibrator on validation set
    calibrator = ScoreCalibrator()
    calibrator.fit(y_true, y_scores)
    calibrator.save("calibrator.json")
    
    # In production
    calibrator = ScoreCalibrator.load("calibrator.json")
    calibrated_score = calibrator.calibrate(raw_score)
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple
import numpy as np


@dataclass
class CalibrationParams:
    """Parameters for Platt scaling: P(y=1|s) = 1 / (1 + exp(A*s + B))"""
    method: str = "platt"
    platt_a: float = -1.0  # Slope (negative means higher score = higher prob)
    platt_b: float = 0.0   # Intercept
    
    # For isotonic regression (piecewise linear)
    isotonic_x: List[float] = None
    isotonic_y: List[float] = None
    
    # Metadata
    n_samples: int = 0
    ece_before: float = 0.0
    ece_after: float = 0.0


class ScoreCalibrator:
    """
    Calibrates raw confidence scores to true probabilities.
    
    Uses Platt scaling by default (fits a logistic function).
    Falls back to isotonic regression for non-monotonic cases.
    """
    
    def __init__(self):
        self.params: Optional[CalibrationParams] = None
        self._is_fitted = False
    
    def fit(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        method: str = "platt",
    ) -> "ScoreCalibrator":
        """
        Fit calibrator on validation data.
        
        Args:
            y_true: Ground truth labels (0 or 1)
            y_scores: Raw model scores (0-10 scale, will be normalized)
            method: "platt" or "isotonic"
        
        Returns:
            self for chaining
        """
        y_true = np.asarray(y_true)
        y_scores = np.asarray(y_scores)
        
        # Normalize scores to 0-1 range
        scores_norm = y_scores / 10.0
        scores_norm = np.clip(scores_norm, 0.001, 0.999)
        
        # Calculate ECE before calibration
        ece_before = self._calculate_ece(y_true, scores_norm)
        
        if method == "platt":
            a, b = self._fit_platt(y_true, scores_norm)
            self.params = CalibrationParams(
                method="platt",
                platt_a=float(a),
                platt_b=float(b),
                n_samples=len(y_true),
                ece_before=ece_before,
            )
        else:
            x_iso, y_iso = self._fit_isotonic(y_true, scores_norm)
            self.params = CalibrationParams(
                method="isotonic",
                isotonic_x=x_iso.tolist(),
                isotonic_y=y_iso.tolist(),
                n_samples=len(y_true),
                ece_before=ece_before,
            )
        
        # Calculate ECE after calibration
        calibrated = np.array([self.calibrate(s * 10) for s in scores_norm])
        self.params.ece_after = self._calculate_ece(y_true, calibrated)
        
        self._is_fitted = True
        return self
    
    def _fit_platt(
        self,
        y_true: np.ndarray,
        scores: np.ndarray,
    ) -> Tuple[float, float]:
        """
        Fit Platt scaling parameters using Newton's method.
        
        Minimizes: -sum(t*log(p) + (1-t)*log(1-p))
        where p = 1 / (1 + exp(A*s + B))
        """
        # Target values with label smoothing
        n_pos = np.sum(y_true == 1)
        n_neg = np.sum(y_true == 0)
        
        t_pos = (n_pos + 1) / (n_pos + 2)
        t_neg = 1 / (n_neg + 2)
        targets = np.where(y_true == 1, t_pos, t_neg)
        
        # Initialize
        a = 0.0
        b = math.log((n_neg + 1) / (n_pos + 1))
        
        # Newton-Raphson iterations
        for _ in range(100):
            # Forward pass
            z = a * scores + b
            p = 1 / (1 + np.exp(-z))
            p = np.clip(p, 1e-10, 1 - 1e-10)
            
            # Gradients
            d = p - targets
            d1_a = np.sum(d * scores)
            d1_b = np.sum(d)
            
            # Hessian
            h = p * (1 - p)
            d2_aa = np.sum(h * scores * scores)
            d2_bb = np.sum(h)
            d2_ab = np.sum(h * scores)
            
            # Regularization
            det = d2_aa * d2_bb - d2_ab * d2_ab
            if abs(det) < 1e-10:
                break
            
            # Update
            a_new = a - (d2_bb * d1_a - d2_ab * d1_b) / det
            b_new = b - (-d2_ab * d1_a + d2_aa * d1_b) / det
            
            # Check convergence
            if abs(a_new - a) < 1e-6 and abs(b_new - b) < 1e-6:
                break
            
            a, b = a_new, b_new
        
        return a, b
    
    def _fit_isotonic(
        self,
        y_true: np.ndarray,
        scores: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Fit isotonic regression (PAVA algorithm)."""
        # Sort by score
        order = np.argsort(scores)
        scores_sorted = scores[order]
        y_sorted = y_true[order].astype(float)
        
        # Pool Adjacent Violators Algorithm
        n = len(y_sorted)
        y_iso = y_sorted.copy()
        
        # Forward pass - ensure monotonicity
        i = 0
        while i < n - 1:
            if y_iso[i] > y_iso[i + 1]:
                # Find range to pool
                j = i + 1
                while j < n - 1 and y_iso[j] > y_iso[j + 1]:
                    j += 1
                
                # Pool values
                mean_val = np.mean(y_iso[i:j + 1])
                y_iso[i:j + 1] = mean_val
                
                # Go back to check
                if i > 0:
                    i -= 1
                else:
                    i = j + 1
            else:
                i += 1
        
        # Get unique x values with averaged y
        unique_x = []
        unique_y = []
        
        i = 0
        while i < n:
            j = i
            while j < n and scores_sorted[j] == scores_sorted[i]:
                j += 1
            unique_x.append(scores_sorted[i])
            unique_y.append(np.mean(y_iso[i:j]))
            i = j
        
        return np.array(unique_x), np.array(unique_y)
    
    def _calculate_ece(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
        n_bins: int = 10,
    ) -> float:
        """Calculate Expected Calibration Error."""
        bins = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        
        for i in range(n_bins):
            mask = (y_prob >= bins[i]) & (y_prob < bins[i + 1])
            if np.sum(mask) > 0:
                avg_conf = np.mean(y_prob[mask])
                avg_acc = np.mean(y_true[mask])
                ece += np.sum(mask) * abs(avg_conf - avg_acc)
        
        return ece / len(y_true)
    
    def calibrate(self, raw_score: float) -> float:
        """
        Calibrate a raw score (0-10) to a probability (0-1).
        
        Args:
            raw_score: Raw model score on 0-10 scale
            
        Returns:
            Calibrated probability (0-1)
        """
        if not self._is_fitted or self.params is None:
            # No calibration, just normalize
            return raw_score / 10.0
        
        # Normalize to 0-1
        s = raw_score / 10.0
        s = max(0.001, min(0.999, s))
        
        if self.params.method == "platt":
            z = self.params.platt_a * s + self.params.platt_b
            return 1 / (1 + math.exp(-z))
        
        elif self.params.method == "isotonic":
            x = np.array(self.params.isotonic_x)
            y = np.array(self.params.isotonic_y)
            
            # Linear interpolation
            if s <= x[0]:
                return y[0]
            if s >= x[-1]:
                return y[-1]
            
            idx = np.searchsorted(x, s)
            x0, x1 = x[idx - 1], x[idx]
            y0, y1 = y[idx - 1], y[idx]
            
            if x1 == x0:
                return y0
            
            return y0 + (y1 - y0) * (s - x0) / (x1 - x0)
        
        return s
    
    def calibrate_batch(self, scores: np.ndarray) -> np.ndarray:
        """Calibrate a batch of scores."""
        return np.array([self.calibrate(s) for s in scores])
    
    def save(self, path: str | Path) -> None:
        """Save calibrator parameters to JSON."""
        if self.params is None:
            raise ValueError("Calibrator not fitted yet")
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w") as f:
            json.dump(asdict(self.params), f, indent=2)
    
    @classmethod
    def load(cls, path: str | Path) -> "ScoreCalibrator":
        """Load calibrator from JSON."""
        path = Path(path)
        
        with open(path) as f:
            data = json.load(f)
        
        calibrator = cls()
        calibrator.params = CalibrationParams(**data)
        calibrator._is_fitted = True
        
        return calibrator
    
    def get_diagnostics(self) -> dict:
        """Get calibration diagnostics."""
        if not self._is_fitted:
            return {"fitted": False}
        
        return {
            "fitted": True,
            "method": self.params.method,
            "n_samples": self.params.n_samples,
            "ece_before": self.params.ece_before,
            "ece_after": self.params.ece_after,
            "improvement": (self.params.ece_before - self.params.ece_after) / self.params.ece_before
            if self.params.ece_before > 0 else 0,
        }


# Global calibrator instance (loaded at startup if file exists)
_calibrator: Optional[ScoreCalibrator] = None


def get_calibrator() -> ScoreCalibrator:
    """Get or initialize the global calibrator."""
    global _calibrator
    
    if _calibrator is None:
        calibrator_path = Path("data/calibrator.json")
        if calibrator_path.exists():
            _calibrator = ScoreCalibrator.load(calibrator_path)
        else:
            _calibrator = ScoreCalibrator()  # Uncalibrated
    
    return _calibrator


def calibrate_score(raw_score: float) -> float:
    """Convenience function to calibrate a single score."""
    return get_calibrator().calibrate(raw_score)

