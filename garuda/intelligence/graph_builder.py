import asyncio
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set
import httpx
import networkx as nx

from garuda.cache import get_cached_json, set_cached_json
from garuda.database import get_supabase_client
from garuda.sources.circl_pdns import query_pdns

logger = logging.getLogger("garuda.intelligence.graph_builder")


async def _pivot_ssl_sans(client: httpx.AsyncClient, domain: str) -> List[str]:
    """Pivot 1: Query crt.sh to extract Subject Alternative Names (SANs)."""
    url = f"https://crt.sh/?q={domain}&output=json"
    cache_key = f"garuda:pivot:crtsh:{domain}"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, list):
        return cached

    san_domains: Set[str] = set()
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for cert in data:
                    name_val = cert.get("name_value", "")
                    for line in name_val.split("\n"):
                        clean = line.strip().lower().lstrip("*.")
                        if clean and "." in clean and clean != domain:
                            san_domains.add(clean)
        san_list = list(san_domains)[:20]
        await set_cached_json(cache_key, san_list, ex=86400)
        return san_list
    except Exception as e:
        logger.warning(f"[graph_builder] SSL SAN pivot failed for '{domain}': {e}")
        return []


async def _pivot_reverse_ip(client: httpx.AsyncClient, ip: str) -> List[str]:
    """Pivot 2: Query HackerTarget Reverse IP Lookup for co-hosted domains."""
    if not ip or ip in {"127.0.0.1", "0.0.0.0"}:
        return []

    cache_key = f"garuda:pivot:revip:{ip}"
    cached = await get_cached_json(cache_key)
    if cached is not None and isinstance(cached, list):
        return cached

    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    domains: List[str] = []
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            # HackerTarget returns plain text with newline-separated domains
            text = resp.text.strip()
            if "No DNS A records found" not in text and "API count exceeded" not in text:
                for line in text.splitlines():
                    cleaned = line.strip().lower().lstrip("*.")
                    if cleaned and "." in cleaned:
                        domains.append(cleaned)
        domains = domains[:25]
        await set_cached_json(cache_key, domains, ex=86400)
        return domains
    except Exception as e:
        logger.warning(f"[graph_builder] Reverse IP pivot failed for IP '{ip}': {e}")
        return []


async def _pivot_pdns_nameservers(domain: str) -> List[Dict[str, str]]:
    """Pivot 3: Extract nameservers via CIRCL PDNS and find co-located domains."""
    records = await query_pdns(domain)
    pivots: List[Dict[str, str]] = []
    ns_servers: Set[str] = set()

    for r in records:
        if r.get("rrtype") == "NS":
            rdata = str(r.get("rdata", "")).strip().lower().rstrip(".")
            if rdata:
                ns_servers.add(rdata)

    for ns in list(ns_servers)[:3]:
        co_records = await query_pdns(ns)
        for cr in co_records:
            co_domain = str(cr.get("rrname", "")).strip().lower().rstrip(".")
            if co_domain and co_domain != domain:
                pivots.append({"domain": co_domain, "nameserver": ns})

    return pivots[:20]


def _compute_registrant_hash(registrar: Optional[str], created_at_str: Optional[str]) -> Optional[str]:
    """Pivot 4: Compute normalized hash of registrar and creation month."""
    if not registrar or not created_at_str:
        return None
    try:
        month_str = str(created_at_str)[:7]  # YYYY-MM
        raw_key = f"{registrar.lower().strip()}_{month_str}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return None


async def build_ioc_graph(domain: str, alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construct an interconnected threat infrastructure graph across 4 pivot dimensions.

    Pivots:
        1. SSL SAN (crt.sh Certificate Transparency)
        2. Reverse IP Lookup (HackerTarget co-hosted domains)
        3. Passive DNS Nameservers (CIRCL PDNS)
        4. Registrant Hash Temporal Clustering

    Args:
        domain: Primary root domain being investigated.
        alert: Associated alert metadata dictionary (score, ip, registrar, etc.).

    Returns:
        Dict representing serialized NetworkX graph:
            - nodes: list[{"id": str, "type": str, "domain": str, "score": int}]
            - edges: list[{"s": str, "t": str, "type": str}]
    """
    domain = domain.lower().strip().lstrip("*.")
    hosting_ip = alert.get("hosting_ip") or alert.get("signals", {}).get("hosting_ip")
    root_score = alert.get("score", 70)

    g = nx.DiGraph()

    # Add Root Domain Node
    g.add_node(
        domain,
        id=domain,
        type="domain",
        domain=domain,
        score=root_score,
        is_root=True,
    )

    # Add IP Node
    if hosting_ip:
        g.add_node(hosting_ip, id=hosting_ip, type="ip", domain=hosting_ip, score=root_score)
        g.add_edge(domain, hosting_ip, type="resolves_to")

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        san_task = _pivot_ssl_sans(client, domain)
        revip_task = _pivot_reverse_ip(client, hosting_ip) if hosting_ip else asyncio.sleep(0, result=[])
        pdns_task = _pivot_pdns_nameservers(domain)

        results = await asyncio.gather(san_task, revip_task, pdns_task, return_exceptions=True)

        sans = results[0] if isinstance(results[0], list) else []
        rev_domains = results[1] if isinstance(results[1], list) else []
        pdns_pivots = results[2] if isinstance(results[2], list) else []

    # Process SSL SAN Nodes
    for san in sans:
        if san not in g:
            g.add_node(san, id=san, type="domain", domain=san, score=max(40, root_score - 15))
        g.add_edge(domain, san, type="ssl_san_pivot")

    # Process Reverse IP Nodes
    for co_dom in rev_domains:
        if co_dom not in g:
            g.add_node(co_dom, id=co_dom, type="domain", domain=co_dom, score=max(30, root_score - 20))
        if hosting_ip:
            g.add_edge(co_dom, hosting_ip, type="co_hosted")

    # Process Passive DNS Nameserver Nodes
    for item in pdns_pivots:
        ns = item.get("nameserver", "")
        co_dom = item.get("domain", "")
        if ns and ns not in g:
            g.add_node(ns, id=ns, type="nameserver", domain=ns, score=50)
            g.add_edge(domain, ns, type="uses_nameserver")
        if co_dom and co_dom not in g:
            g.add_node(co_dom, id=co_dom, type="domain", domain=co_dom, score=40)
            if ns:
                g.add_edge(co_dom, ns, type="shares_nameserver")

    # Process Pivot 4: Registrant Hash
    registrar = alert.get("registrar") or alert.get("signals", {}).get("registrar")
    creation_date = alert.get("registered_at") or alert.get("signals", {}).get("creation_date")
    reg_hash = _compute_registrant_hash(registrar, creation_date)

    if reg_hash:
        g.add_node(f"reg_{reg_hash}", id=f"reg_{reg_hash}", type="registrant_cluster", domain=reg_hash, score=60)
        g.add_edge(domain, f"reg_{reg_hash}", type="registrant_affinity")

    # Serialize NetworkX Graph to standard GARUDA JSON format
    nodes_payload = []
    for n, data in g.nodes(data=True):
        nodes_payload.append({
            "id": str(n),
            "type": data.get("type", "unknown"),
            "domain": data.get("domain", str(n)),
            "score": data.get("score", 0),
        })

    edges_payload = []
    for u, v, data in g.edges(data=True):
        edges_payload.append({
            "s": str(u),
            "t": str(v),
            "type": data.get("type", "connected"),
        })

    graph_dict = {"nodes": nodes_payload, "edges": edges_payload}

    # Store graph in Supabase alerts table
    client = get_supabase_client()
    alert_id = alert.get("id")
    if client and alert_id:
        try:
            # Update signals with graph payload
            client.table("alerts").update({
                "signals": {**alert.get("signals", {}), "graph": graph_dict}
            }).eq("id", alert_id).execute()
        except Exception as e:
            logger.warning(f"[graph_builder] Failed updating graph in Supabase for alert {alert_id}: {e}")

    return graph_dict
