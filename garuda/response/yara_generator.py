from datetime import datetime, timezone
import re
from typing import Any, Dict


def generate_yara_rule(alert: Dict[str, Any]) -> str:
    """
    Generate a syntactically valid YARA detection rule for endpoint and network scanning.

    Includes domain string matching (nocase), hosting IP correlation, and targeted
    BOSS Linux binary strings for defense research (DRDO/Army) campaign sectors.

    Args:
        alert: Complete threat alert dictionary.

    Returns:
        str: Pure YARA rule text (no external module imports).
    """
    domain = alert.get("domain", "threat.space").strip().lower()
    raw_id = str(alert.get("id", "alert_001"))[:8]
    clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", raw_id)
    rule_name = f"APT36_domain_{clean_id}"

    score = alert.get("score", 70)
    sector = alert.get("sector", "Critical Infrastructure")
    hosting_ip = alert.get("hosting_ip")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    string_lines = [f'        $domain = "{domain}" nocase']

    if hosting_ip and "." in hosting_ip and hosting_ip != "127.0.0.1":
        string_lines.append(f'        $hosting_ip = "{hosting_ip}"')

    # Add BOSS Linux / Bharat Operating System targeted strings if sector matches DRDO/Army
    sector_lower = sector.lower()
    if "drdo" in sector_lower or "army" in sector_lower or "defence" in sector_lower:
        string_lines.extend([
            '        $boss_str1 = "/etc/boss-version" ascii',
            '        $boss_str2 = "/usr/share/doc/boss" ascii',
            '        $boss_str3 = "apt36_poseidon_payload" ascii',
        ])

    strings_block = "\n".join(string_lines)

    yara_rule = f"""rule {rule_name}
{{
    meta:
        description = "Detection rule for APT36 / Transparent Tribe infrastructure targeting {sector}"
        author = "GARUDA Automated Threat Intelligence Platform"
        reference = "GARUDA-RULE-{clean_id}"
        date = "{date_str}"
        threat_score = "{score}/100"
        target_sector = "{sector}"
        confidence = "{"HIGH" if score >= 70 else "MEDIUM"}"

    strings:
{strings_block}

    condition:
        any of them
}}
"""
    return yara_rule
