"""
Structured logging configuration for FraudShield.

Provides JSON-formatted logs suitable for log aggregation services
like Elasticsearch, Datadog, CloudWatch, etc.
"""

import logging
import sys
import json
import time
import traceback
from datetime import datetime
from typing import Dict, Any, Optional
from functools import wraps
from contextvars import ContextVar

from fraudshield.config import settings


# Context variables for request tracking
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar("user_id", default=None)


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add context variables
        if request_id_var.get():
            log_data["request_id"] = request_id_var.get()
        if user_id_var.get():
            log_data["user_id"] = user_id_var.get()
        
        # Add extra fields if present
        if hasattr(record, "extra_data"):
            log_data["data"] = record.extra_data
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }
        
        # Add environment info
        log_data["environment"] = settings.environment
        
        return json.dumps(log_data)


class StructuredLogger:
    """
    Wrapper for structured logging with additional context.
    
    Usage:
        logger = StructuredLogger("fraudshield.api")
        logger.info("Request received", modality="text", score=5.5)
        logger.error("Analysis failed", error=str(e), traceback=True)
    """
    
    def __init__(self, name: str):
        self._logger = logging.getLogger(name)
    
    def _log(self, level: int, message: str, **kwargs):
        """Log with extra data."""
        extra_data = kwargs.pop("extra_data", None) or kwargs
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn="",
            lno=0,
            msg=message,
            args=(),
            exc_info=None,
        )
        if extra_data:
            record.extra_data = extra_data
        self._logger.handle(record)
    
    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        if exc_info:
            self._logger.error(message, exc_info=True, extra={"extra_data": kwargs})
        else:
            self._log(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, **kwargs)


def setup_logging(
    level: str = "INFO",
    json_format: bool = True,
    log_file: Optional[str] = None,
):
    """
    Configure logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON formatting (True for prod, False for dev)
        log_file: Optional file path for file logging
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        # Human-readable format for development
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s"
        )
        console_handler.setFormatter(formatter)
    
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(JSONFormatter())  # Always JSON for files
        root_logger.addHandler(file_handler)
    
    # Suppress noisy loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("python_multipart").setLevel(logging.WARNING)
    logging.getLogger("python_multipart.multipart").setLevel(logging.WARNING)
    logging.getLogger("multipart").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)


# ============== METRICS ==============


class MetricsCollector:
    """
    Collects and aggregates metrics for monitoring.
    
    Usage:
        metrics = MetricsCollector()
        metrics.increment("api.requests.total")
        metrics.timing("api.latency", 0.125)
        metrics.gauge("api.active_requests", 5)
    """
    
    def __init__(self):
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._timings: Dict[str, list] = {}
        self._start_time = time.time()
    
    def increment(self, name: str, value: int = 1):
        """Increment a counter."""
        self._counters[name] = self._counters.get(name, 0) + value
    
    def gauge(self, name: str, value: float):
        """Set a gauge value."""
        self._gauges[name] = value
    
    def timing(self, name: str, value: float):
        """Record a timing value."""
        if name not in self._timings:
            self._timings[name] = []
        self._timings[name].append(value)
        # Keep only last 1000 values
        if len(self._timings[name]) > 1000:
            self._timings[name] = self._timings[name][-1000:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current metrics."""
        timing_stats = {}
        for name, values in self._timings.items():
            if values:
                sorted_vals = sorted(values)
                timing_stats[name] = {
                    "count": len(values),
                    "min": min(values),
                    "max": max(values),
                    "avg": sum(values) / len(values),
                    "p50": sorted_vals[len(sorted_vals) // 2],
                    "p95": sorted_vals[int(len(sorted_vals) * 0.95)] if len(sorted_vals) >= 20 else None,
                    "p99": sorted_vals[int(len(sorted_vals) * 0.99)] if len(sorted_vals) >= 100 else None,
                }
        
        return {
            "uptime_seconds": time.time() - self._start_time,
            "counters": self._counters.copy(),
            "gauges": self._gauges.copy(),
            "timings": timing_stats,
        }
    
    def reset(self):
        """Reset all metrics."""
        self._counters.clear()
        self._gauges.clear()
        self._timings.clear()


# Global metrics instance
metrics = MetricsCollector()


# ============== DECORATORS ==============


def log_execution_time(logger_name: str = "fraudshield"):
    """Decorator to log function execution time."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            logger = StructuredLogger(logger_name)
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start
                logger.info(
                    f"{func.__name__} completed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                )
                metrics.timing(f"function.{func.__name__}", duration)
                return result
            except Exception as e:
                duration = time.time() - start
                logger.error(
                    f"{func.__name__} failed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                    error=str(e),
                    exc_info=True,
                )
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            logger = StructuredLogger(logger_name)
            start = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start
                logger.info(
                    f"{func.__name__} completed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                )
                metrics.timing(f"function.{func.__name__}", duration)
                return result
            except Exception as e:
                duration = time.time() - start
                logger.error(
                    f"{func.__name__} failed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                    error=str(e),
                    exc_info=True,
                )
                raise
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


def track_analysis(modality: str):
    """Decorator to track analysis metrics."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            metrics.increment(f"analysis.{modality}.total")
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start
                metrics.timing(f"analysis.{modality}.latency", duration)
                
                # Track by risk level
                risk_level = result.get("risk_level", "UNKNOWN")
                metrics.increment(f"analysis.{modality}.risk.{risk_level.lower()}")
                
                return result
            except Exception:
                metrics.increment(f"analysis.{modality}.errors")
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            metrics.increment(f"analysis.{modality}.total")
            start = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start
                metrics.timing(f"analysis.{modality}.latency", duration)
                
                risk_level = result.get("risk_level", "UNKNOWN")
                metrics.increment(f"analysis.{modality}.risk.{risk_level.lower()}")
                
                return result
            except Exception:
                metrics.increment(f"analysis.{modality}.errors")
                raise
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


# Initialize logging based on environment
def init_logging():
    """Initialize logging based on environment settings."""
    is_prod = settings.environment == "prod"
    setup_logging(
        level="INFO" if is_prod else "DEBUG",
        json_format=is_prod,
        log_file="logs/fraudshield.log" if is_prod else None,
    )


