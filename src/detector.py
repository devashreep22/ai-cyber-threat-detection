
"""
Hybrid rule/statistical threat detector.

The detector uses behavioural flow features to identify suspicious
network activity. It is designed for passive, metadata-only analysis.
"""

import pandas as pd


THREAT_CLASSES = [
    "Normal",
    "DDoS",
    "C2 Beaconing",
    "DGA / DNS Tunnelling",
    "Encrypted Malware",
    "Reconnaissance",
    "Data Exfiltration",
]


def detect_ddos(row):
    """Detect volumetric/protocol DDoS-like behaviour."""

    packet_rate = float(row.get("packet_rate", 0))
    fan_out = float(row.get("fan_out", 0))
    protocol = str(row.get("protocol", "")).upper()

    score = 0.0
    evidence = []

    if packet_rate > 1000:
        score += 0.55
        evidence.append("High packet rate")

    elif packet_rate > 500:
        score += 0.35
        evidence.append("Elevated packet rate")

    if protocol == "TCP" and packet_rate > 500:
        score += 0.20
        evidence.append("High-rate TCP traffic")

    if fan_out > 50:
        score += 0.20
        evidence.append("High source/destination fan-out")

    return score, evidence


def detect_c2(row):
    """Detect periodic command-and-control beaconing."""

    periodicity = float(row.get("periodicity_score", 0))
    iat = float(row.get("inter_arrival_time", 0))
    destination_diversity = float(
        row.get("destination_diversity", 0)
    )

    score = 0.0
    evidence = []

    if periodicity > 0.65:
        score += 0.55
        evidence.append("Regular communication periodicity")

    if 1 <= iat <= 120:
        score += 0.20
        evidence.append("Repeated short inter-arrival interval")

    if destination_diversity <= 3:
        score += 0.25
        evidence.append("Limited destination diversity")

    return score, evidence


def detect_dga_dns(row):
    """Detect suspicious DGA/DNS-tunnelling characteristics."""

    entropy = float(row.get("domain_entropy", 0))
    domain_length = float(row.get("domain_length", 0))
    labels = float(row.get("domain_labels", 0))

    score = 0.0
    evidence = []

    if entropy > 3.5:
        score += 0.40
        evidence.append("High domain entropy")

    if domain_length > 30:
        score += 0.30
        evidence.append("Unusually long domain/query")

    if labels > 4:
        score += 0.15
        evidence.append("High DNS label count")

    if entropy > 4.0 and domain_length > 25:
        score += 0.20
        evidence.append("Combined entropy and length anomaly")

    return min(score, 1.0), evidence


def detect_encrypted_malware(row):
    """Detect suspicious encrypted-session metadata."""

    protocol = str(row.get("protocol", "")).upper()
    fingerprint = str(row.get("tls_fingerprint", "")).strip()
    packet_rate = float(row.get("packet_rate", 0))

    score = 0.0
    evidence = []

    if protocol in {"TLS", "HTTPS", "QUIC"}:
        score += 0.25
        evidence.append("Encrypted session metadata")

    if fingerprint:
        score += 0.35
        evidence.append("TLS/QUIC fingerprint available")

    if packet_rate > 200:
        score += 0.20
        evidence.append("Elevated encrypted traffic rate")

    return min(score, 1.0), evidence


def detect_recon(row):
    """Detect reconnaissance and port-scanning behaviour."""

    fan_out = float(row.get("fan_out", 0))
    destination_diversity = float(
        row.get("destination_diversity", 0)
    )
    dst_port = row.get("dst_port", 0)

    score = 0.0
    evidence = []

    if fan_out > 20:
        score += 0.50
        evidence.append("High destination fan-out")

    if destination_diversity > 10:
        score += 0.35
        evidence.append("High destination diversity")

    if dst_port:
        score += 0.10
        evidence.append("Multiple destination-port activity")

    return min(score, 1.0), evidence


def detect_exfiltration(row):
    """Detect outbound data-exfiltration-like behaviour."""

    byte_ratio = float(row.get("byte_ratio", 1))
    asymmetry = float(row.get("byte_asymmetry", 0))
    bytes_total = float(row.get("bytes", 0))

    score = 0.0
    evidence = []

    if byte_ratio > 5:
        score += 0.50
        evidence.append("Strong outbound/inbound byte asymmetry")

    if asymmetry > 0.70:
        score += 0.30
        evidence.append("High traffic asymmetry")

    if bytes_total > 1_000_000:
        score += 0.20
        evidence.append("Large outbound traffic volume")

    return min(score, 1.0), evidence


def classify_flow(row):
    """
    Classify one flow using multiple behavioural detectors.

    Returns:
        threat_class
        confidence
        evidence
    """

    detectors = {
        "DDoS": detect_ddos,
        "C2 Beaconing": detect_c2,
        "DGA / DNS Tunnelling": detect_dga_dns,
        "Encrypted Malware": detect_encrypted_malware,
        "Reconnaissance": detect_recon,
        "Data Exfiltration": detect_exfiltration,
    }

    results = {}

    for threat_name, detector in detectors.items():
        score, evidence = detector(row)
        results[threat_name] = {
            "score": min(max(score, 0.0), 1.0),
            "evidence": evidence,
        }

    # Select the strongest detector
    best_threat = max(
        results,
        key=lambda threat: results[threat]["score"]
    )

    best_score = results[best_threat]["score"]
    evidence = results[best_threat]["evidence"]

    # Threshold for an alert
    if best_score < 0.45:
        return {
            "threat_class": "Normal",
            "confidence": round(1.0 - best_score, 3),
            "evidence": ["No strong threat indicators"],
            "scores": results,
        }

    return {
        "threat_class": best_threat,
        "confidence": round(best_score, 3),
        "evidence": evidence,
        "scores": results,
    }


def detect_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Run threat classification across an entire flow dataframe.
    """

    if df is None or df.empty:
        return pd.DataFrame()

    results = []

    for _, row in df.iterrows():
        detection = classify_flow(row)

        results.append({
            "threat_class": detection["threat_class"],
            "confidence": detection["confidence"],
            "evidence": "; ".join(
                detection["evidence"]
            ),
        })

    output = df.copy()

    detection_df = pd.DataFrame(results, index=output.index)

    output[
        ["threat_class", "confidence", "evidence"]
    ] = detection_df[
        ["threat_class", "confidence", "evidence"]
    ]

    return output
