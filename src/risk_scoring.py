
"""
Risk scoring for detected cyber threats.

Converts threat confidence into a simple, explainable risk score
and severity level.
"""


SEVERITY_THRESHOLDS = {
    "LOW": 0.45,
    "MEDIUM": 0.65,
    "HIGH": 0.80,
}


def calculate_risk_score(confidence, threat_class):
    """
    Calculate a normalized risk score from 0 to 100.

    A small threat-specific weighting is applied so that
    high-impact threats receive appropriate priority.
    """

    confidence = max(0.0, min(float(confidence), 1.0))

    threat_weights = {
        "DDoS": 1.00,
        "C2 Beaconing": 0.90,
        "DGA / DNS Tunnelling": 0.85,
        "Encrypted Malware": 0.95,
        "Reconnaissance": 0.70,
        "Data Exfiltration": 1.00,
        "Normal": 0.20,
    }

    weight = threat_weights.get(threat_class, 0.80)

    score = confidence * weight * 100

    return round(min(score, 100.0), 1)


def get_severity(risk_score):
    """Convert a risk score into a severity level."""

    score = float(risk_score) / 100.0

    if score >= SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"

    if score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"

    if score >= SEVERITY_THRESHOLDS["LOW"]:
        return "LOW"

    return "INFO"


def build_risk_record(detection):
    """
    Convert a detector result into a dashboard-ready alert record.
    """

    threat_class = detection.get(
        "threat_class",
        "Normal"
    )

    confidence = float(
        detection.get("confidence", 0.0)
    )

    evidence = detection.get(
        "evidence",
        []
    )

    risk_score = calculate_risk_score(
        confidence,
        threat_class
    )

    severity = get_severity(risk_score)

    return {
        "threat_class": threat_class,
        "confidence": round(confidence * 100, 1),
        "risk_score": risk_score,
        "severity": severity,
        "evidence": evidence,
    }


def add_risk_scores(df):
    """
    Add risk score and severity columns to detection results.
    """

    if df is None or df.empty:
        return df

    result = df.copy()

    risk_scores = []
    severities = []

    for _, row in result.iterrows():

        threat_class = row.get(
            "threat_class",
            "Normal"
        )

        confidence = float(
            row.get("confidence", 0.0)
        )

        score = calculate_risk_score(
            confidence,
            threat_class
        )

        risk_scores.append(score)
        severities.append(
            get_severity(score)
        )

    result["risk_score"] = risk_scores
    result["severity"] = severities

    return result
