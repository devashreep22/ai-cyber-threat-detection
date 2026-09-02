"""
Feature engineering for network-flow based cyber threat detection.

The module converts raw flow records into behavioural security features.
It does not inspect or decrypt packet payloads.
"""

import numpy as np
import pandas as pd


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not value:
        return 0.0

    counts = pd.Series(list(str(value))).value_counts()
    probabilities = counts / counts.sum()

    return float(
        -(probabilities * np.log2(probabilities)).sum()
    )


def add_basic_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add general traffic-behaviour features.

    Expected columns where available:
    duration, packets, bytes, src_bytes, dst_bytes,
    src_ip, dst_ip, dst_port, protocol
    """

    result = df.copy()

    # Avoid division by zero
    duration = result.get("duration", pd.Series(1.0, index=result.index))
    duration = pd.to_numeric(duration, errors="coerce").fillna(1.0)
    duration = duration.clip(lower=0.001)

    if "packets" in result.columns:
        packets = pd.to_numeric(
            result["packets"], errors="coerce"
        ).fillna(0)

        result["packet_rate"] = packets / duration

    if "bytes" in result.columns:
        bytes_ = pd.to_numeric(
            result["bytes"], errors="coerce"
        ).fillna(0)

        result["byte_rate"] = bytes_ / duration

    # Outbound / inbound byte asymmetry
    if "src_bytes" in result.columns and "dst_bytes" in result.columns:
        src_bytes = pd.to_numeric(
            result["src_bytes"], errors="coerce"
        ).fillna(0)

        dst_bytes = pd.to_numeric(
            result["dst_bytes"], errors="coerce"
        ).fillna(0)

        result["byte_ratio"] = (
            (src_bytes + 1) / (dst_bytes + 1)
        )

        result["byte_asymmetry"] = (
            (src_bytes - dst_bytes).abs()
            / (src_bytes + dst_bytes + 1)
        )

    return result


def add_dns_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add DNS-related metadata features."""

    result = df.copy()

    if "domain" not in result.columns:
        return result

    domains = result["domain"].fillna("").astype(str)

    result["domain_length"] = domains.str.len()

    result["domain_entropy"] = domains.apply(calculate_entropy)

    # Approximate number of subdomain labels
    result["domain_labels"] = domains.apply(
        lambda x: len(x.split(".")) if x else 0
    )

    return result


def add_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add temporal behavioural features.

    inter_arrival_time:
        Time between observed communication events.

    periodicity_score:
        Higher values indicate more regular communication.
    """

    result = df.copy()

    if "inter_arrival_time" in result.columns:
        iat = pd.to_numeric(
            result["inter_arrival_time"],
            errors="coerce"
        ).fillna(0)

        result["iat_mean"] = iat
        result["periodicity_score"] = 1 / (1 + iat)

    return result


def add_communication_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add communication-pattern features."""

    result = df.copy()

    if "dst_port" in result.columns:
        result["dst_port"] = pd.to_numeric(
            result["dst_port"],
            errors="coerce"
        ).fillna(0)

    if "fan_out" in result.columns:
        result["fan_out"] = pd.to_numeric(
            result["fan_out"],
            errors="coerce"
        ).fillna(0)

    if "destination_diversity" in result.columns:
        result["destination_diversity"] = pd.to_numeric(
            result["destination_diversity"],
            errors="coerce"
        ).fillna(0)

    return result


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Complete feature-engineering pipeline.

    Returns a dataframe containing the original flow information
    plus behavioural security features.
    """

    if df is None or df.empty:
        return pd.DataFrame()

    result = df.copy()

    result = add_basic_features(result)
    result = add_dns_features(result)
    result = add_temporal_features(result)
    result = add_communication_features(result)

    return result
