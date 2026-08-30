"""
PROVDAG Execution Provenance & Physical Fusion Processor
Builds execution Directed Acyclic Graphs (DAGs) from EPPI events,
fuses physical RAPL power readings within a ±500ms window, and reconstructs causal attack chains.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

logger = logging.getLogger("axiom.services.provenance")


class ProvenanceProcessor:
    """
    Processes kernel provenance events and fuses them with microarchitectural RAPL power measurements.
    """

    def __init__(self):
        self.dag = nx.DiGraph()

    def add_eppi_events(self, events: List[Dict[str, Any]]) -> None:
        """
        Adds EPPI kernel events to the provenance DAG.
        Handles FORK, EXEC, CONNECT, and OPEN events.
        """
        for ev in events:
            pid = ev.get("pid")
            ppid = ev.get("ppid")
            event_type = str(ev.get("event_type", "EXEC")).upper()
            comm = ev.get("comm", "unknown")
            target = ev.get("target", "")
            ts_ns = ev.get("timestamp_ns", 0)

            if pid is None:
                continue

            node_id = f"proc_{pid}"

            # Create or update child node
            if not self.dag.has_node(node_id):
                self.dag.add_node(
                    node_id,
                    pid=pid,
                    ppid=ppid,
                    comm=comm,
                    target=target,
                    timestamp_ns=ts_ns,
                    rapl_pkg_mw=0.0,
                    anomaly_score=0.0,
                    is_anomalous=False,
                )
            else:
                # Update attributes
                self.dag.nodes[node_id]["comm"] = comm
                if target:
                    self.dag.nodes[node_id]["target"] = target

            # Create edge from parent to child on FORK or EXEC
            if ppid is not None and ppid > 0:
                parent_id = f"proc_{ppid}"
                if not self.dag.has_node(parent_id):
                    self.dag.add_node(
                        parent_id,
                        pid=ppid,
                        ppid=0,
                        comm="systemd" if ppid == 1 else "parent",
                        target="",
                        timestamp_ns=0,  # Implicit parent initialized without timestamp
                        rapl_pkg_mw=0.0,
                        anomaly_score=0.0,
                        is_anomalous=False,
                    )
                self.dag.add_edge(parent_id, node_id, event_type=event_type, timestamp_ns=ts_ns)

    def fuse_rapl_readings(
        self,
        rapl_observations: List[Dict[str, Any]],
        baseline_pkg_mw: float = 15000.0,
        baseline_pkg_std: float = 2000.0,
        time_window_sec: float = 0.5,
    ) -> int:
        """
        Tags each PROVDAG process node with RAPL power observations within a ±500ms time window.
        Marks nodes as anomalous if power > baseline + 3 * sigma.
        """
        anomalous_tagged = 0
        threshold_mw = baseline_pkg_mw + (3.0 * (baseline_pkg_std / 1000.0))

        for node_id in self.dag.nodes():
            node_data = self.dag.nodes[node_id]
            ts_ns = node_data.get("timestamp_ns", 0)
            if not ts_ns:
                continue

            node_ts_sec = float(ts_ns) / 1e9

            # Find matching RAPL readings in time window
            matched_powers = []
            for obs in rapl_observations:
                obs_ts = float(obs.get("timestamp", 0))
                if abs(obs_ts - node_ts_sec) <= time_window_sec:
                    pkg_uw = obs.get("rapl_pkg_uw")
                    if pkg_uw is not None:
                        matched_powers.append(float(pkg_uw) / 1000.0)  # Convert to mW

            if matched_powers:
                avg_power_mw = sum(matched_powers) / len(matched_powers)
                node_data["rapl_pkg_mw"] = round(avg_power_mw, 2)
                
                # Check 3-sigma physical power threshold
                if avg_power_mw > threshold_mw:
                    node_data["is_anomalous"] = True
                    node_data["anomaly_score"] = round((avg_power_mw - baseline_pkg_mw) / baseline_pkg_std, 2)
                    anomalous_tagged += 1

        return anomalous_tagged

    def reconstruct_attack_chain(self) -> Dict[str, Any]:
        """
        Identifies the root entry point process by walking DAG ancestors from anomalous leaf processes.
        """
        if self.dag.number_of_nodes() == 0:
            return {
                "nodes_count": 0,
                "edges_count": 0,
                "root_entry_pid": None,
                "attack_chain": [],
                "anomalous_nodes": [],
            }

        # 1. Collect all anomalous nodes
        anomalous_nodes = [
            n for n in self.dag.nodes() if self.dag.nodes[n].get("is_anomalous", False)
        ]

        if not anomalous_nodes:
            # Return full graph summary
            return {
                "nodes_count": self.dag.number_of_nodes(),
                "edges_count": self.dag.number_of_edges(),
                "root_entry_pid": None,
                "attack_chain": [],
                "anomalous_nodes": [],
            }

        # 2. Walk ancestors to identify root cause
        all_causal_nodes: Set[str] = set(anomalous_nodes)
        roots: Set[str] = set()

        for an_node in anomalous_nodes:
            ancestors = nx.ancestors(self.dag, an_node)
            all_causal_nodes.update(ancestors)
            
            # Find in-degree == 0 ancestor (the root process)
            for anc in ancestors:
                if self.dag.in_degree(anc) == 0:
                    roots.add(anc)

            if not ancestors and self.dag.in_degree(an_node) == 0:
                roots.add(an_node)

        primary_root = list(roots)[0] if roots else anomalous_nodes[0]
        root_pid = self.dag.nodes[primary_root].get("pid")

        # If primary root is PID 1 (systemd/init), resolve to the actual launched process in subgraph
        if root_pid == 1:
            descendants = [
                d for d in self.dag.successors(primary_root) if d in all_causal_nodes
            ]
            if descendants:
                primary_root = descendants[0]
                root_pid = self.dag.nodes[primary_root].get("pid")

        # 3. Build linear attack path from root to most divergent anomalous leaf
        subgraph = self.dag.subgraph(all_causal_nodes)
        attack_chain_path = []

        try:
            # Find longest or shortest causal path from primary root to deepest anomalous leaf
            deepest_leaf = anomalous_nodes[-1]
            if nx.has_path(subgraph, primary_root, deepest_leaf):
                path_nodes = nx.shortest_path(subgraph, primary_root, deepest_leaf)
                for pn in path_nodes:
                    attack_chain_path.append({
                        "node_id": pn,
                        "pid": self.dag.nodes[pn].get("pid"),
                        "comm": self.dag.nodes[pn].get("comm"),
                        "target": self.dag.nodes[pn].get("target"),
                        "rapl_pkg_mw": self.dag.nodes[pn].get("rapl_pkg_mw"),
                        "is_anomalous": self.dag.nodes[pn].get("is_anomalous"),
                    })
        except Exception as e:
            logger.debug(f"Path extraction exception: {e}")

        return {
            "nodes_count": self.dag.number_of_nodes(),
            "edges_count": self.dag.number_of_edges(),
            "root_entry_pid": root_pid,
            "attack_chain": attack_chain_path,
            "anomalous_nodes": [self.dag.nodes[n] for n in anomalous_nodes],
        }
