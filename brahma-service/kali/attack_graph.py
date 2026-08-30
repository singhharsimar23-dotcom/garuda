"""
MITRE ATT&CK Technique Graph Builder
Constructs a NetworkX DiGraph of empirical APT36 (Group G0134) techniques with kill-chain transition weights.
"""

from collections import defaultdict
import logging
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx

try:
    from brahma.mitre_pipeline import TACTIC_NAMES, get_mitre_pipeline
except ImportError:
    try:
        from ..brahma.mitre_pipeline import TACTIC_NAMES, get_mitre_pipeline
    except ImportError:
        TACTIC_NAMES = [
            "reconnaissance", "resource-development", "initial-access", "execution",
            "persistence", "privilege-escalation", "defense-evasion", "credential-access",
            "discovery", "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]
        get_mitre_pipeline = lambda: None

logger = logging.getLogger("kali.attack_graph")

# Documented MITRE ATT&CK Group G0134 (APT36) Techniques with primary tactics
APT36_TECHNIQUE_CATALOG: Dict[str, Dict[str, str]] = {
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "initial-access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "initial-access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1059.005": {"name": "Visual Basic", "tactic": "execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution"},
    "T1055.012": {"name": "Process Hollowing", "tactic": "defense-evasion"},
    "T1055.001": {"name": "Dynamic-link Library Injection", "tactic": "defense-evasion"},
    "T1055.002": {"name": "Portable Executable Injection", "tactic": "defense-evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "persistence"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "persistence"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential-access"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral-movement"},
    "T1005": {"name": "Data from Local System", "tactic": "collection"},
    "T1071.001": {"name": "Web Protocols (C2)", "tactic": "command-and-control"},
    "T1071.004": {"name": "DNS C2 Beacon", "tactic": "command-and-control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
}

# Empirical co-occurrence transitions in documented APT36 campaigns
APT36_CAMPAIGN_EDGES: List[Tuple[str, str, float]] = [
    ("T1566.001", "T1059.005", 5.0),
    ("T1566.001", "T1059.003", 3.0),
    ("T1566.002", "T1082", 4.0),
    ("T1190", "T1059.004", 4.0),
    ("T1059.005", "T1055.012", 6.0),
    ("T1059.003", "T1055.002", 4.0),
    ("T1059.004", "T1055.001", 3.0),
    ("T1055.012", "T1071.001", 6.0),
    ("T1055.001", "T1071.004", 4.0),
    ("T1055.002", "T1041", 4.0),
    ("T1082", "T1027", 3.0),
    ("T1027", "T1041", 3.0),
    ("T1071.001", "T1041", 5.0),
    ("T1071.004", "T1041", 4.0),
    ("T1055.012", "T1003.001", 3.0),
    ("T1003.001", "T1021.001", 3.0),
    ("T1021.001", "T1005", 3.0),
    ("T1005", "T1041", 4.0),
]


class AttackGraphBuilder:
    """
    Builds a directed technique graph for APT36 campaigns.
    """

    def __init__(self, technique_catalog: Optional[Dict[str, Dict[str, str]]] = None):
        self.technique_catalog = dict(technique_catalog or APT36_TECHNIQUE_CATALOG)
        self.graph = nx.DiGraph()

    def build_graph(self, alpha_counts: Optional[List[float]] = None) -> nx.DiGraph:
        """
        Constructs the NetworkX DiGraph populated with nodes, forward kill-chain edges, and weights.
        """
        self.graph.clear()

        # Build alpha weight lookup per tactic
        alpha_weights: Dict[str, float] = {}
        if alpha_counts and len(alpha_counts) == len(TACTIC_NAMES):
            for i, tactic in enumerate(TACTIC_NAMES):
                alpha_weights[tactic] = float(alpha_counts[i])
        else:
            for tactic in TACTIC_NAMES:
                alpha_weights[tactic] = 1.0

        # Step 1: Add Nodes
        for tech_id, meta in self.technique_catalog.items():
            tactic = meta.get("tactic", "execution")
            tactic_idx = TACTIC_NAMES.index(tactic) if tactic in TACTIC_NAMES else 3
            self.graph.add_node(
                tech_id,
                name=meta.get("name", tech_id),
                tactic=tactic,
                tactic_index=tactic_idx,
                weight=alpha_weights.get(tactic, 1.0),
            )

        # Step 2: Add Documented APT36 Campaign Edges
        for u, v, base_weight in APT36_CAMPAIGN_EDGES:
            if u in self.graph and v in self.graph:
                src_tactic = self.graph.nodes[u].get("tactic", "execution")
                src_alpha = alpha_weights.get(src_tactic, 1.0)
                final_weight = base_weight * (1.0 + (src_alpha / 10.0))
                self.graph.add_edge(u, v, weight=round(final_weight, 4), source="campaign")

        # Step 3: Infer Tactic Progression Edges for Inter-Tactic Reachability
        nodes_by_tactic: Dict[str, List[str]] = defaultdict(list)
        for node, data in self.graph.nodes(data=True):
            nodes_by_tactic[data["tactic"]].append(node)

        for i, curr_tactic in enumerate(TACTIC_NAMES[:-1]):
            curr_nodes = nodes_by_tactic.get(curr_tactic, [])
            # Connect to next tactics in kill chain
            for j in range(i + 1, min(i + 4, len(TACTIC_NAMES))):
                next_tactic = TACTIC_NAMES[j]
                next_nodes = nodes_by_tactic.get(next_tactic, [])
                for u in curr_nodes:
                    for v in next_nodes:
                        if not self.graph.has_edge(u, v):
                            src_alpha = alpha_weights.get(curr_tactic, 1.0)
                            inferred_weight = round(1.0 * (1.0 + (src_alpha / 20.0)), 4)
                            self.graph.add_edge(u, v, weight=inferred_weight, source="inferred")

        logger.info(
            f"Built ATT&CK Technique Graph: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} directed edges."
        )
        return self.graph

    def get_adjacency_dict(self) -> Dict[str, List[Dict[str, Any]]]:
        """Export graph as adjacency JSON dict."""
        adj = {}
        for u in self.graph.nodes():
            neighbors = []
            for v, edge_data in self.graph[u].items():
                neighbors.append({
                    "target": v,
                    "weight": edge_data.get("weight", 1.0),
                    "source": edge_data.get("source", "inferred"),
                })
            adj[u] = neighbors
        return adj


_graph_builder = AttackGraphBuilder()


def get_attack_graph_builder() -> AttackGraphBuilder:
    return _graph_builder
