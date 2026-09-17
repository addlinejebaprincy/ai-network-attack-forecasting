"""
MITRE ATT&CK Contextual Mapping Module.
Provides defensive decision-support context for network traffic anomalies.
IMPORTANT: Displays 'Possible MITRE ATT&CK investigation context', NOT definitive attribution.
"""

from typing import Any


MITRE_KNOWLEDGE_BASE = {
    "T1046": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery (TA0007)",
        "traffic_indicators": ["SYN Flag Count", "Flow Packets/s", "Fwd Packets/s", "Flow Duration"],
        "rationale": (
            "Observed bursts in SYN flags, elevated packet transmission rates, and brief flow durations "
            "are characteristic of automated port sweeps and host discovery enumeration."
        ),
        "triage_actions": [
            "Review firewall and perimeter edge logs for port scanning activity across multiple destinations.",
            "Verify if source IP belongs to an authorized internal vulnerability management scanner.",
            "Check for subsequent connection attempts on detected open listening ports.",
        ],
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access (TA0006)",
        "traffic_indicators": ["Flow Duration", "Total Backward Packets", "Packet Length Mean", "Flow IAT Mean"],
        "rationale": (
            "Repeated bidirectional communication bursts with consistent packet lengths and rapid re-connections "
            "strongly match credential brute-forcing (such as SSH-Patator or FTP-Patator present in CICIDS2017 Tuesday)."
        ),
        "triage_actions": [
            "Query SSH (port 22) or FTP (port 21) server authentication logs for repeated failed login attempts.",
            "Check for account lockout events or abnormal credential spraying patterns.",
            "Implement automated IP rate-limiting or temporary connection throttling at the perimeter.",
        ],
    },
    "T1498": {
        "technique_id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact (TA0040)",
        "traffic_indicators": ["Flow Bytes/s", "Flow Packets/s", "Subflow Fwd Bytes", "Subflow Fwd Packets"],
        "rationale": (
            "Severe anomalies in volumetric throughput (Flow Bytes/s and Packets/s) indicate possible "
            "bandwidth exhaustion or protocol state saturation targeting network infrastructure."
        ),
        "triage_actions": [
            "Analyze router and switch interface utilization to identify saturated uplinks.",
            "Enable SYN cookie protection and rate-limiting on target load balancers.",
            "Coordinate with upstream ISP / scrubbing providers if external DDoS is confirmed.",
        ],
    },
    "T1071": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control (TA0011)",
        "traffic_indicators": ["PSH Flag Count", "ACK Flag Count", "Avg Fwd Segment Size", "Idle Mean"],
        "rationale": (
            "Unusual application payload delivery flags combined with periodic inter-flow active/idle intervals "
            "may indicate periodic beaconing or covert command-and-control communication."
        ),
        "triage_actions": [
            "Extract flow destination domain/IP and check against threat intelligence reputation feeds.",
            "Review deep packet inspection (DPI) payload captures for non-standard protocol handshakes.",
            "Inspect endpoint process trees originating outbound network sessions.",
        ],
    },
}


def get_mitre_investigation_context(
    risk_level: str,
    top_feature_names: list[str],
) -> list[dict[str, Any]]:
    """
    Derives plausible MITRE ATT&CK contextual possibilities based on top contributing features.
    Strictly marked as investigatory hypothesis to prevent false-positive over-confidence.
    """
    if risk_level == "LOW":
        return [{
            "technique_id": "N/A",
            "name": "Normal Baseline Traffic",
            "tactic": "Operational Baseline",
            "rationale": "Observed flow characteristics match normal enterprise baseline. No immediate MITRE ATT&CK threat profile indicated.",
            "triage_actions": [
                "Continue standard continuous network telemetry ingestion.",
                "Verify sensor health and baseline model calibration.",
            ],
            "confidence": "Low Alert",
        }]

    # Match against indicators
    matched_techniques = []
    top_set = set(top_feature_names)

    for tech_id, info in MITRE_KNOWLEDGE_BASE.items():
        overlap = top_set.intersection(info["traffic_indicators"])
        score = len(overlap)

        if score > 0 or (risk_level in ["HIGH", "CRITICAL"] and tech_id in ["T1110.001", "T1046"]):
            matched_techniques.append({
                "technique_id": info["technique_id"],
                "name": info["name"],
                "tactic": info["tactic"],
                "rationale": info["rationale"],
                "matching_features": list(overlap) if overlap else ["Temporal Risk Surge"],
                "triage_actions": info["triage_actions"],
                "priority": "Immediate" if risk_level == "CRITICAL" else "Elevated",
            })

    # Return top 2 relevant contextual mappings
    if not matched_techniques:
        # Fallback to Patator / Brute Force context characteristic of CICIDS2017 Tuesday
        fallback = MITRE_KNOWLEDGE_BASE["T1110.001"].copy()
        fallback["matching_features"] = top_feature_names[:2]
        fallback["priority"] = "Elevated"
        matched_techniques = [fallback]

    return matched_techniques[:2]
