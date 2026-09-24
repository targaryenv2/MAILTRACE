"""Exact Shapley Feature Attribution for Multi-Class Calibrated Linear Classifiers.

For a linear model decision f_k(x) = b_k + sum_j w_{kj} * x_j:
  phi_{kj} = w_{kj} * (x_j - E[x_j])
  E[f_k]   = b_k + sum_j w_{kj} * E[x_j]       (Shapley base value)
  f_k(x)   = E[f_k] + sum_j phi_{kj}           (Exact local accuracy)

This is exact in closed form, requiring zero sampling approximations or heavy dependencies.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple
import numpy as np
from ..schemas import FeatureAttribution


def top_attributions(
    x_sparse,
    weights: np.ndarray,
    bias: float,
    means: np.ndarray,
    feature_names: Sequence[str],
    class_name: str = "phishing",
    k: int = 10,
) -> Tuple[List[FeatureAttribution], float]:
    """Compute exact per-token Shapley attributions for the selected class."""
    if hasattr(x_sparse, "toarray"):
        x_dense = x_sparse.toarray().flatten()
    else:
        x_dense = np.asarray(x_sparse).flatten()

    dim = len(weights)
    if len(x_dense) < dim:
        padded = np.zeros(dim)
        padded[:len(x_dense)] = x_dense
        x_dense = padded
    elif len(x_dense) > dim:
        x_dense = x_dense[:dim]

    if len(means) < dim:
        padded_means = np.zeros(dim)
        padded_means[:len(means)] = means
        means = padded_means
    elif len(means) > dim:
        means = means[:dim]

    # phi_j = w_j * (x_j - E[x_j])
    phi = weights * (x_dense - means)
    base_val = float(bias + np.dot(weights, means))

    # Focus ranking on features present in the document first, then largest non-zero phi
    present_indices = np.where(x_dense > 0)[0]
    if len(present_indices) > 0:
        sorted_present = present_indices[np.argsort(-np.abs(phi[present_indices]))]
        other_indices = np.setdiff1d(np.argsort(-np.abs(phi)), present_indices)
        ranked_indices = np.concatenate([sorted_present, other_indices])[:k]
    else:
        ranked_indices = np.argsort(-np.abs(phi))[:k]

    out: List[FeatureAttribution] = []
    for j in ranked_indices:
        feat_name = feature_names[j] if j < len(feature_names) else f"feature_{j}"
        val = float(x_dense[j])
        contrib = float(phi[j])
        direction = class_name if contrib > 0 else "benign"

        out.append(FeatureAttribution(
            feature=feat_name,
            value=round(val, 5),
            contribution=round(contrib, 5),
            direction=direction,
        ))

    return out, round(base_val, 5)
