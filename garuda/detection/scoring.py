from typing import Any, Dict, Tuple


def assemble_score(signals: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """
    Assemble multi-vector threat intelligence signals into a normalized composite threat score.

    Evaluates keyword tiers, NIC brand impersonation similarity, unicode homoglyph spoofing,
    registrar infrastructure affinity, domain age, hosting ASN correlation, open C2 ports,
    threat feed attribution, and applies geopolitical tension multipliers.

    Args:
        signals: Dictionary containing extracted threat signals:
            - keyword_tier (str): 'tier1', 'tier2', 'tld', or 'none'.
            - keyword_score (int): Score from keyword pattern matching.
            - nic_similarity (float): Brand similarity ratio (0.0 - 1.0).
            - nic_match (str): Matched authentic government domain.
            - homoglyph (bool): Whether homoglyph characters were detected.
            - registrar_match (bool): Registrar matched APT36 preferred list.
            - registrar_score (float): Registrar score contribution.
            - domain_age_days (int/None): Age of domain in days.
            - asn_match (bool): Hosted on known APT36 infrastructure ASN.
            - c2_ports (list[int]): Active ports matching known C2 services.
            - otx_attributed (bool): Domain present in actor threat pulses.
            - abuseipdb_reports (int/bool): Reputation report count.
            - tension_index (float): Measured geopolitical tension (0.0 - 1.0).

    Returns:
        Tuple of:
            - int: Final composite threat score between 0 and 100.
            - dict: Detailed itemized breakdown of contributing score weights.
    """
    breakdown: Dict[str, Any] = {}
    base_score = 0.0

    # 1. Keyword Patterns
    kw_score = float(signals.get("keyword_score", 0.0))
    if kw_score > 0:
        base_score += kw_score
        breakdown["keyword_pattern"] = {
            "tier": signals.get("keyword_tier", "none"),
            "points": kw_score,
        }

    # 2. NIC / Brand Similarity
    sim = float(signals.get("nic_similarity", 0.0))
    if sim >= 0.85:
        sim_points = 35.0
    elif sim >= 0.70:
        sim_points = 20.0
    elif sim >= 0.50:
        sim_points = 10.0
    else:
        sim_points = 0.0

    if sim_points > 0:
        base_score += sim_points
        breakdown["nic_similarity"] = {
            "ratio": sim,
            "matched_domain": signals.get("nic_match", ""),
            "points": sim_points,
        }

    # 3. Unicode Homoglyph Spoofing
    has_homoglyph = bool(signals.get("homoglyph", False))
    if has_homoglyph:
        homoglyph_points = 25.0
        base_score += homoglyph_points
        breakdown["homoglyph_detection"] = {
            "detected": True,
            "points": homoglyph_points,
        }

    # 4. Registrar Fingerprint
    reg_score = float(signals.get("registrar_score", 0.0))
    if reg_score > 0:
        base_score += reg_score
        breakdown["registrar_fingerprint"] = {
            "matched": True,
            "points": reg_score,
        }

    # 5. Domain Age Heuristic
    age_days = signals.get("domain_age_days")
    if age_days is not None and isinstance(age_days, (int, float)):
        if age_days <= 14:
            age_points = 20.0
        elif age_days <= 60:
            age_points = 10.0
        else:
            age_points = 0.0

        if age_points > 0:
            base_score += age_points
            breakdown["domain_age"] = {
                "age_days": age_days,
                "points": age_points,
            }

    # 6. Hosting Infrastructure ASN
    if bool(signals.get("asn_match", False)):
        asn_points = 20.0
        base_score += asn_points
        breakdown["hosting_asn"] = {
            "matched": True,
            "points": asn_points,
        }

    # 7. C2 Listening Ports
    c2_ports = signals.get("c2_ports", [])
    if isinstance(c2_ports, list) and len(c2_ports) > 0:
        c2_points = 25.0
        base_score += c2_points
        breakdown["c2_ports"] = {
            "ports": c2_ports,
            "points": c2_points,
        }

    # 8. Threat Pulse Attribution (OTX)
    if bool(signals.get("otx_attributed", False)):
        otx_points = 30.0
        base_score += otx_points
        breakdown["otx_attribution"] = {
            "attributed": True,
            "points": otx_points,
        }

    # 9. AbuseIPDB Reports
    abuse_reports = signals.get("abuseipdb_reports", 0)
    if (isinstance(abuse_reports, int) and abuse_reports > 0) or bool(abuse_reports):
        abuse_points = 15.0
        base_score += abuse_points
        breakdown["abuseipdb"] = {
            "reports": abuse_reports,
            "points": abuse_points,
        }

    # 10. Geopolitical Tension Modifier
    tension_idx = float(signals.get("tension_index", 0.50))
    tension_modifier = 0.0
    if base_score > 0:
        # Tension modifier: tension_index * 0.2 * base_score (capped at max +15)
        raw_modifier = tension_idx * 0.20 * base_score
        tension_modifier = min(15.0, round(raw_modifier, 2))
        breakdown["tension_modifier"] = {
            "tension_index": tension_idx,
            "points": tension_modifier,
        }

    # Total Score Normalization (0 - 100)
    final_score = int(round(base_score + tension_modifier))
    final_score = min(100, max(0, final_score))

    breakdown["base_score"] = round(base_score, 2)
    breakdown["final_score"] = final_score

    return final_score, breakdown


class GarudaActiveLearner:
    """
    Online active learning classifier with convergence guardrails.

    Prevents weight collapse when analysts label benign domains, enforcing
    a minimum weight floor and resetting if the rolling false positive rate exceeds 50%.
    """
    WEIGHT_FLOOR = 0.1
    RESET_FP_THRESHOLD = 0.5

    def __init__(self):
        try:
            from sklearn.linear_model import SGDClassifier
            self.clf = SGDClassifier(loss="log_loss", warm_start=True)
            # Initialize with dummy balanced sample
            import numpy as np
            X_init = np.array([[1.0, 1.0, 1.0, 1.0], [0.0, 0.0, 0.0, 0.0]])
            y_init = [1, 0]
            self.clf.partial_fit(X_init, y_init, classes=[0, 1])
        except Exception:
            self.clf = None
        self._history = []

    def _reset_to_initial_weights(self) -> None:
        if self.clf is not None:
            import numpy as np
            self.clf.coef_ = np.array([[0.25, 0.25, 0.25, 0.25]])
            self._history.clear()

    def update(self, features, label: int) -> None:
        if self.clf is None:
            return
        import numpy as np
        feat_arr = np.array(features, dtype=float).reshape(1, -1)
        self.clf.partial_fit(feat_arr, [label], classes=[0, 1])

        # Guard: enforce minimum weight floor
        coef = self.clf.coef_[0]
        coef[coef < self.WEIGHT_FLOOR] = self.WEIGHT_FLOOR
        self.clf.coef_[0] = coef

        self._history.append(label)
        if len(self._history) >= 100:
            fp_rate = self._history[-100:].count(0) / 100.0
            if fp_rate > self.RESET_FP_THRESHOLD:
                self._reset_to_initial_weights()

