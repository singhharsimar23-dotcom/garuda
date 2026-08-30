"""
Dirichlet-Multinomial Bayesian Kill Chain Engine
Performs conjugate Bayesian updating across 14 MITRE ATT&CK tactics from hardware physics observations.
Strictly implements Rule 8 Attribution Gating and produces verifiable evidence without fake confidence percentages.
"""

from datetime import datetime, timezone
import logging
import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

try:
    from .mitre_pipeline import TACTIC_NAMES, get_mitre_pipeline
except ImportError:
    from mitre_pipeline import TACTIC_NAMES, get_mitre_pipeline

logger = logging.getLogger("brahma.bayesian_engine")

# Base Physics Likelihoods P(Physics Anomaly | Tactic)
BASE_PHYSICS_LIKELIHOODS: Dict[str, float] = {
    "execution": 0.80,          # T1055 process injection -> power spike
    "defense-evasion": 0.65,    # T1055.012 hollowing -> L3 miss spike
    "credential-access": 0.45,  # memory scraping -> cache miss
    "command-and-control": 0.30,# C2 beacon -> entropy consumption
    "exfiltration": 0.50,       # data movement -> memory bus pressure
    "lateral-movement": 0.40,   # network + process creation
    "reconnaissance": 0.10,
    "resource-development": 0.10,
    "initial-access": 0.10,
    "persistence": 0.10,
    "privilege-escalation": 0.10,
    "discovery": 0.10,
    "collection": 0.10,
    "impact": 0.10,
}

APT36_ACTIVE_TACTICS = {
    "execution", "defense-evasion", "credential-access",
    "command-and-control", "exfiltration", "lateral-movement",
}

DISTINCTIVE_PHYSICS_CHANNELS = {"rapl_pkg", "perf_cache_miss", "perf_instructions", "entropy"}


class HostBayesianState:
    """Maintains running Dirichlet alpha counts and attribution evidence per host."""

    def __init__(self, hostname: str, initial_alphas: Optional[List[float]] = None):
        self.hostname = hostname
        self.observation_count: int = 0
        self.medium_ias_observations: int = 0
        self.has_distinctive_physics_corroboration: bool = False
        self.max_distinctive_sigma: float = 0.0
        self.stix_matches_count: int = 0
        self.eppi_events_count: int = 0
        self.ist_anomaly_count: int = 0
        
        # Dirichlet alpha counts
        pipeline = get_mitre_pipeline()
        self.alphas: List[float] = list(initial_alphas) if initial_alphas else list(pipeline.alpha_prior)

    def get_posterior(self) -> Dict[str, float]:
        """Compute normalized posterior distribution P(Tactic | Evidence) = alpha_i / sum(alpha)."""
        total = sum(self.alphas)
        if total <= 0:
            total = float(len(TACTIC_NAMES))
            self.alphas = [1.0] * len(TACTIC_NAMES)
        return {tactic: round(self.alphas[i] / total, 4) for i, tactic in enumerate(TACTIC_NAMES)}

    def get_top_tactic(self) -> Tuple[str, float]:
        """Return (tactic, posterior_mass) for the maximum a posteriori (MAP) tactic."""
        posterior = self.get_posterior()
        top = max(posterior.items(), key=lambda x: x[1])
        return top[0], top[1]

    def evaluate_attribution_status(self) -> str:
        """
        Strict Attribution Gating:
        1. observation_count >= 15
        2. IAS >= MEDIUM on at least 3 separate observations
        3. Physics corroboration: at least 1 channel_sigma >= 3.0 on a distinctive channel
        4. Tactic posterior: top tactic posterior mass >= 0.30
        """
        top_tactic, top_mass = self.get_top_tactic()

        if self.observation_count < 15:
            return f"ACCUMULATING EVIDENCE ({self.observation_count}/15 minimum)"

        cond1 = self.observation_count >= 15
        cond2 = self.medium_ias_observations >= 3
        cond3 = self.has_distinctive_physics_corroboration or self.max_distinctive_sigma >= 3.0
        cond4 = top_mass >= 0.30

        if cond1 and cond2 and cond3 and cond4:
            return "ATTRIBUTED — APT36 (Transparent Tribe)"
        else:
            return "PARTIAL ATTRIBUTION"


class BayesianEngine:
    """
    Central Bayesian Engine orchestrating online Dirichlet updates and evidence generation.
    """

    def __init__(self):
        self._host_states: Dict[str, HostBayesianState] = {}

    def get_or_create_state(
        self,
        hostname: str,
        supabase_client=None,
    ) -> HostBayesianState:
        """Retrieve host state from cache or database."""
        if hostname in self._host_states:
            return self._host_states[hostname]

        # Check Supabase
        if supabase_client:
            try:
                res = (
                    supabase_client.table("brahma_program_models")
                    .select("*")
                    .eq("hostname", hostname)
                    .execute()
                )
                if res.data and len(res.data) > 0:
                    row = res.data[0]
                    state = HostBayesianState(
                        hostname=hostname,
                        initial_alphas=[float(x) for x in row["alpha_counts"]],
                    )
                    state.observation_count = int(row.get("observation_count", 0))
                    evidence = row.get("evidence_summary", {})
                    state.medium_ias_observations = int(evidence.get("medium_ias_observations", 0))
                    state.has_distinctive_physics_corroboration = bool(evidence.get("has_distinctive_physics_corroboration", False))
                    state.max_distinctive_sigma = float(evidence.get("max_distinctive_sigma", 0.0))
                    self._host_states[hostname] = state
                    return state
            except Exception as e:
                logger.debug(f"Failed to load brahma state from Supabase: {e}")

        # New state
        state = HostBayesianState(hostname=hostname)
        self._host_states[hostname] = state
        return state

    def update_from_observation(
        self,
        hostname: str,
        ias_score: float,
        channel_sigmas: Dict[str, float],
        workload_class: str,
        observed_at_iso: Optional[str] = None,
        eppi_technique_id: Optional[str] = None,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """
        Execute Dirichlet-Multinomial Bayesian update from physical observation evidence.
        """
        state = self.get_or_create_state(hostname, supabase_client)
        state.observation_count += 1

        if ias_score >= 3.0:
            state.medium_ias_observations += 1

        # Check distinctive physics channel corroboration (sigma >= 3.0)
        for ch, sig in channel_sigmas.items():
            if ch in DISTINCTIVE_PHYSICS_CHANNELS:
                val = float(sig)
                if val > state.max_distinctive_sigma:
                    state.max_distinctive_sigma = val
                if val >= 3.0:
                    state.has_distinctive_physics_corroboration = True

        # Check IST Timezone Behavioral Signature
        # APT36 operational window: 03:30 - 13:30 UTC (09:00 - 19:00 IST)
        ist_active_hours = False
        try:
            if observed_at_iso:
                obs_dt = datetime.fromisoformat(observed_at_iso.replace("Z", "+00:00"))
            else:
                obs_dt = datetime.now(timezone.utc)
            
            utc_hour_float = obs_dt.hour + (obs_dt.minute / 60.0)
            if 3.5 <= utc_hour_float <= 13.5:
                ist_active_hours = True
                state.ist_anomaly_count += 1
        except Exception:
            ist_active_hours = False

        # Calculate likelihood vector across 14 tactics
        likelihoods: Dict[str, float] = dict(BASE_PHYSICS_LIKELIHOODS)

        # Apply EPPI technique multipliers
        if eppi_technique_id:
            state.eppi_events_count += 1
            if "T1055.012" in eppi_technique_id:
                likelihoods["execution"] *= 8.0
                likelihoods["defense-evasion"] *= 8.0
            elif "T1059.005" in eppi_technique_id:
                likelihoods["execution"] *= 10.0
            elif "T1071.001" in eppi_technique_id:
                likelihoods["command-and-control"] *= 10.0

        # Apply IST operational hours multiplier
        if ist_active_hours:
            for t in APT36_ACTIVE_TACTICS:
                likelihoods[t] *= 1.5

        # Compute evidence update indicator
        if ias_score >= 3.0:
            indicator = 1.0
        elif ias_score >= 1.5:
            indicator = ias_score / 3.0
        else:
            # Smooth low-evidence scaling
            indicator = max(0.005, 0.02 * (ias_score / 1.5))


        # Conjugate Dirichlet update: alpha_posterior = alpha_prior + likelihood * indicator
        for i, tactic in enumerate(TACTIC_NAMES):
            lik = likelihoods.get(tactic, 0.10)
            state.alphas[i] += float(lik * indicator)
            state.alphas[i] = round(state.alphas[i], 4)

        posterior = state.get_posterior()
        top_tactic, top_mass = state.get_top_tactic()
        status = state.evaluate_attribution_status()

        # Build evidence summary (strictly NO confidence percentages)
        narrative_evidence = [
            f"Physics anomaly observations: {state.observation_count} (elevated IAS >= 3.0: {state.medium_ias_observations})",
            f"Distinctive physical corroboration: {'YES (max sigma: ' + str(round(state.max_distinctive_sigma, 2)) + ')' if state.has_distinctive_physics_corroboration else 'PENDING'}",
            f"Top active tactic: {top_tactic.upper()} (posterior probability mass: {top_mass:.4f})",
            f"Adversary IST operational timezone overlap: {'YES' if ist_active_hours else 'NO'}",
        ]

        evidence_summary = {
            "physics_anomaly_events": state.observation_count,
            "medium_ias_observations": state.medium_ias_observations,
            "has_distinctive_physics_corroboration": state.has_distinctive_physics_corroboration,
            "max_distinctive_sigma": round(state.max_distinctive_sigma, 4),
            "top_tactic": top_tactic.upper(),
            "top_tactic_mass": top_mass,
            "ist_active_hours": ist_active_hours,
            "stix_iocs_matched": state.stix_matches_count,
            "eppi_events_count": state.eppi_events_count,
            "narrative_evidence": narrative_evidence,
        }

        # Persist to Supabase
        if supabase_client:
            try:
                upsert_data = {
                    "hostname": hostname,
                    "actor": "APT36 (Transparent Tribe)",
                    "observation_count": state.observation_count,
                    "alpha_counts": state.alphas,
                    "tactic_names": TACTIC_NAMES,
                    "attribution_status": status,
                    "evidence_summary": evidence_summary,
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                }
                supabase_client.table("brahma_program_models").upsert(
                    upsert_data, on_conflict="hostname"
                ).execute()
            except Exception as e:
                logger.warning(f"Failed writing brahma_program_models to Supabase: {e}")

        logger.info(
            f"[BAYESIAN UPDATE] Host '{hostname}': Obs={state.observation_count}, "
            f"TopTactic={top_tactic.upper()} ({top_mass:.2f}), Status='{status}'"
        )

        return {
            "hostname": hostname,
            "observation_count": state.observation_count,
            "attribution_status": status,
            "actor": "APT36 (Transparent Tribe)",
            "top_tactic": top_tactic.upper(),
            "top_tactic_mass": top_mass,
            "posterior": posterior,
            "alpha_counts": state.alphas,
            "evidence_summary": evidence_summary,
        }


_bayesian_engine = BayesianEngine()


def get_bayesian_engine() -> BayesianEngine:
    return _bayesian_engine
