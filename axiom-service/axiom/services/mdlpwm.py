"""
Multi-Dimensional Linear Power-Workload Model (MDLPWM)
Uses Ridge Regression to model expected physical power draw as a function of microarchitectural events.
"""

import logging
from typing import Dict, List, Optional
import numpy as np

logger = logging.getLogger("axiom.services.mdlpwm")


class MultiDimensionalLinearPowerWorkloadModel:
    """
    Fits and evaluates linear ridge regression models relating IPC, cache misses,
    and scheduler activity to RAPL package power consumption.
    """

    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha  # Ridge regularization strength
        self.coefficients: Dict[str, np.ndarray] = {}  # workload_class -> [b0, b1, b2, b3]
        self.fitted_classes: set = set()

    def fit(self, workload_class: str, X: np.ndarray, y: np.ndarray) -> bool:
        """
        Fit Ridge regression model: y ~ X.
        X columns: [1 (bias), IPC, CacheMissRate, SchedDelayRatio]
        y: Package Power (uW)
        """
        if len(y) < 10 or X.shape[0] != len(y):
            logger.debug(f"Insufficient samples ({len(y)}) to fit MDLPWM for {workload_class}.")
            return False

        try:
            # Ridge regression closed form: beta = (X^T X + alpha * I)^-1 X^T y
            n_features = X.shape[1]
            identity = np.eye(n_features)
            identity[0, 0] = 0.0  # Do not regularize intercept

            xt_x = np.dot(X.T, X) + self.alpha * identity
            xt_y = np.dot(X.T, y)
            beta = np.linalg.solve(xt_x, xt_y)

            self.coefficients[workload_class] = beta
            self.fitted_classes.add(workload_class)
            logger.info(f"Fitted MDLPWM for {workload_class}: intercept={beta[0]:.2f}")
            return True
        except Exception as e:
            logger.warning(f"Error fitting MDLPWM for {workload_class}: {e}")
            return False

    def predict_power_uw(
        self,
        workload_class: str,
        ipc: Optional[float],
        cache_miss_rate: Optional[float],
        sched_delay_ratio: Optional[float],
    ) -> Optional[float]:
        """
        Predicts expected package power in uW.
        """
        if workload_class not in self.coefficients:
            return None

        beta = self.coefficients[workload_class]
        f_ipc = ipc if ipc is not None else 1.0
        f_cache = cache_miss_rate if cache_miss_rate is not None else 0.01
        f_sched = sched_delay_ratio if sched_delay_ratio is not None else 0.0

        x_vec = np.array([1.0, f_ipc, f_cache, f_sched])
        predicted_uw = float(np.dot(beta, x_vec))
        return max(0.0, predicted_uw)
