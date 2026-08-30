"""
Monte Carlo Tree Search (MCTS) Engine for Autonomous Novel Path Synthesis (ANPS)
Explores ATT&CK technique transition graphs to uncover high-utility, evasive attack paths against GARUDA baselines.
"""

import hashlib
import logging
import math
import os
import random
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from .attack_graph import get_attack_graph_builder
from .detection_model import get_detection_model

logger = logging.getLogger("kali.mcts_engine")

TACTIC_VALUES: Dict[str, float] = {
    "reconnaissance": 0.1,
    "resource-development": 0.2,
    "initial-access": 0.4,
    "execution": 0.6,
    "persistence": 0.7,
    "privilege-escalation": 0.7,
    "defense-evasion": 0.5,
    "credential-access": 0.8,
    "discovery": 0.5,
    "lateral-movement": 0.7,
    "collection": 0.8,
    "command-and-control": 0.9,
    "exfiltration": 1.0,
    "impact": 1.0,
}

HARDENING_MAPPINGS: Dict[str, str] = {
    "T1059.005": "Deploy EPPI kprobe filter for VBScript execve",
    "T1055.012": "Monitor process memory mappings via EPPI PROT_EXEC kprobe",
    "T1071.001": "Add AXIOM-II C2 beacon power signature to baseline",
    "T1566.001": "Enable GARUDA passive DNS monitoring for lure domains",
    "T1566.002": "Enforce DNS sinkhole on external lure domains in DHARMA Tier 2",
    "T1003.001": "Deploy kernel eBPF probe on /proc/kcore and memory scraping hooks",
    "T1041": "Tune AXIOM-II exfiltration memory-bus baseline model threshold",
}


class MCTSNode:
    """Represents a search tree node corresponding to a sequence of techniques."""

    def __init__(
        self,
        technique_id: str,
        tactic: str,
        parent: Optional["MCTSNode"] = None,
        edge_weight: float = 1.0,
    ):
        self.technique_id = technique_id
        self.tactic = tactic
        self.parent = parent
        self.edge_weight = edge_weight
        self.children: List["MCTSNode"] = []
        self.visits: int = 0
        self.total_reward: float = 0.0
        self.max_reward: float = 0.0

    def get_path(self) -> List[Tuple[str, str]]:
        path = []
        curr = self
        while curr:
            path.append((curr.technique_id, curr.tactic))
            curr = curr.parent
        return list(reversed(path))

    def ucb1(self, c_exploration: float = 1.414) -> float:
        if self.visits == 0:
            return float("inf")
        exploitation = self.total_reward / self.visits
        parent_visits = self.parent.visits if self.parent else self.visits
        exploration = c_exploration * math.sqrt(math.log(parent_visits + 1) / self.visits)
        return exploitation + (exploration * math.sqrt(self.edge_weight))


class KaliMCTSEngine:
    """
    Orchestrates Monte Carlo Tree Search path synthesis over the MITRE ATT&CK technique graph.
    """

    def __init__(
        self,
        c_exploration: float = 1.414,
        max_depth: int = 4,
    ):
        self.c_exploration = c_exploration
        self.max_depth = max_depth
        self.graph_builder = get_attack_graph_builder()
        self.detection_model = get_detection_model()

    def compute_step_reward(
        self,
        technique_id: str,
        tactic: str,
        sample_count: Optional[int] = None,
    ) -> float:
        p_det, _ = self.detection_model.compute_technique_detection_prob(technique_id, tactic, sample_count)
        p_evasion = max(0.01, 1.0 - p_det)
        tactic_val = TACTIC_VALUES.get(tactic.lower(), 0.5)
        return tactic_val * p_evasion

    def compute_path_reward(
        self,
        path: List[Tuple[str, str]],
        sample_count: Optional[int] = None,
    ) -> float:
        if not path:
            return 0.0
        cumulative = 1.0
        for tech_id, tactic in path:
            step_r = self.compute_step_reward(tech_id, tactic, sample_count)
            cumulative *= step_r
        return round(cumulative, 4)

    def is_terminal(self, path: List[Tuple[str, str]]) -> bool:
        if not path:
            return False
        if len(path) >= self.max_depth:
            return True
        last_tactic = path[-1][1].lower()
        if last_tactic in ("exfiltration", "impact"):
            return True
        return False

    def synthesize_novel_paths(
        self,
        num_simulations: Optional[int] = None,
        alpha_counts: Optional[List[float]] = None,
        sample_count: Optional[int] = None,
        top_k: int = 5,
        supabase_client=None,
    ) -> List[Dict[str, Any]]:
        sims = num_simulations or int(os.environ.get("KALI_MCTS_SIMULATIONS", "500"))
        graph = self.graph_builder.build_graph(alpha_counts)

        initial_nodes = [
            n for n, d in graph.nodes(data=True)
            if d.get("tactic") in ("initial-access", "reconnaissance")
        ]
        if not initial_nodes:
            initial_nodes = list(graph.nodes())[:3]

        root = MCTSNode("ROOT", "START")
        for init_node in initial_nodes:
            tactic = graph.nodes[init_node].get("tactic", "initial-access")
            weight = graph.nodes[init_node].get("weight", 1.0)
            root.children.append(MCTSNode(init_node, tactic, parent=root, edge_weight=weight))

        start_time = time.time()
        completed_sims = 0

        for _ in range(sims):
            if time.time() - start_time > 28.0:
                logger.warning(f"MCTS safeguard timeout reached after {completed_sims} simulations.")
                break

            curr = root
            while curr.children and not self.is_terminal(curr.get_path()[1:]):
                curr = max(curr.children, key=lambda c: c.ucb1(self.c_exploration))

            path_so_far = curr.get_path()[1:]

            if not self.is_terminal(path_so_far) and curr.technique_id in graph:
                neighbors = list(graph.neighbors(curr.technique_id))
                for neighbor in neighbors:
                    if neighbor not in [p[0] for p in path_so_far]:
                        tactic = graph.nodes[neighbor].get("tactic", "execution")
                        edge_w = graph[curr.technique_id][neighbor].get("weight", 1.0)
                        child_node = MCTSNode(neighbor, tactic, parent=curr, edge_weight=edge_w)
                        curr.children.append(child_node)

                if curr.children:
                    curr = random.choice(curr.children)
                    path_so_far = curr.get_path()[1:]

            sim_path = list(path_so_far)
            while not self.is_terminal(sim_path):
                last_tech = sim_path[-1][0]
                if last_tech in graph and list(graph.neighbors(last_tech)):
                    next_tech = random.choice(list(graph.neighbors(last_tech)))
                    tactic = graph.nodes[next_tech].get("tactic", "execution")
                    sim_path.append((next_tech, tactic))
                else:
                    break

            rollout_reward = self.compute_path_reward(sim_path, sample_count)
            back_node = curr
            while back_node:
                back_node.visits += 1
                back_node.total_reward += rollout_reward
                if rollout_reward > back_node.max_reward:
                    back_node.max_reward = rollout_reward
                back_node = back_node.parent

            completed_sims += 1

        discovered_paths: Dict[str, Dict[str, Any]] = {}

        def harvest_paths(node: MCTSNode):
            p = node.get_path()[1:]
            if len(p) >= 3:
                tech_seq = [x[0] for x in p]
                tactic_seq = [x[1] for x in p]
                seq_str = "->".join(tech_seq)
                hash_id = hashlib.sha256(seq_str.encode("utf-8")).hexdigest()[:8]
                disc_id = f"kali-disc-{hash_id}"

                utility = self.compute_path_reward(p, sample_count)
                p_detect, uncalibrated = self.detection_model.evaluate_path_detection_prob(p, sample_count)

                is_gap = (p_detect < 0.50) and (utility > 0.70)
                gap_status = "DEFENSIVE_GAP" if is_gap else "COVERED"

                if gap_status == "DEFENSIVE_GAP":
                    lowest_tech = min(
                        p,
                        key=lambda x: self.detection_model.compute_technique_detection_prob(x[0], x[1], sample_count)[0]
                    )[0]
                    recommendation = HARDENING_MAPPINGS.get(
                        lowest_tech,
                        f"Deploy targeted EPPI eBPF hook and YARA rule for {lowest_tech}"
                    )
                else:
                    recommendation = "Baseline power model captures shell execution bursts (rapl_pkg sigma > 3.0)"

                brahma_pref = round(sum(TACTIC_VALUES.get(t, 0.5) for t in tactic_seq) / len(tactic_seq), 3)

                discovered_paths[disc_id] = {
                    "discovery_id": disc_id,
                    "technique_sequence": tech_seq,
                    "tactic_sequence": tactic_seq,
                    "adversary_utility": utility,
                    "p_detection": p_detect,
                    "detection_uncalibrated": uncalibrated,
                    "gap_status": gap_status,
                    "hardening_recommendation": recommendation,
                    "brahma_preference_score": brahma_pref,
                    "mcts_simulations": completed_sims,
                }

            for child in node.children:
                harvest_paths(child)

        harvest_paths(root)

        ranked = sorted(
            discovered_paths.values(),
            key=lambda x: x["adversary_utility"],
            reverse=True,
        )[:top_k]

        return ranked


_mcts_engine = KaliMCTSEngine()


def get_kali_mcts_engine() -> KaliMCTSEngine:
    return _mcts_engine
