import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field

from app.schemas.alert import AlertCreate
from app.config import settings

logger = logging.getLogger("detection.icmp")

# State constants
STATE_NORMAL = "NORMAL"
STATE_SUSPICIOUS = "SUSPICIOUS"
STATE_POSSIBLE_DOS = "POSSIBLE_DOS"
STATE_POSSIBLE_DDOS = "POSSIBLE_DDOS"

# Rule constants
RULE_06_ICMP_DOS = "RULE_06_ICMP_DOS"
RULE_07_ICMP_DDOS = "RULE_07_ICMP_DDOS"

@dataclass
class IcmpPacketData:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str = "ICMP"
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    packet_size: int = 64
    interface: Optional[str] = None
    source: str = "live_icmp"

@dataclass
class IcmpDetectionResult:
    state: str  # NORMAL, SUSPICIOUS, POSSIBLE_DOS, POSSIBLE_DDOS
    state_label: str  # e.g., "🟢 NORMAL", "🟡 SUSPICIOUS ICMP ACTIVITY", "🔴 POSSIBLE ICMP DOS DETECTED"
    total_packets: int
    packets_per_second: float
    unique_sources: int
    unique_destinations: int
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    primary_source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    alert_candidate: Optional[AlertCreate] = None
    detection_category: str = "Network Availability"
    detection_type: str = "NORMAL"
    description: str = "Traffic volume within normal operating limits."
    protected_target_ips: List[str] = field(default_factory=list)
    protected_incoming_requests: int = 0
    outgoing_requests: int = 0
    replies_observed: int = 0
    unrelated_packets: int = 0

class IcmpDosDetector:
    """
    Phase 5 ICMP DoS/DDoS Detection Engine.
    Analyzes packet telemetry within a sliding time window to identify:
      - Normal ICMP traffic
      - Suspicious elevated ICMP activity
      - Possible ICMP DoS (single or concentrated sources)
      - Possible ICMP DDoS (distributed sources exceeding threshold)
    Specifically targets incoming ICMP Echo Requests directed at configured PROTECTED_TARGET_IPS,
    excluding outgoing requests (e.g. ping 8.8.8.8), echo replies, and unrelated traffic.
    """

    def __init__(
        self,
        window_seconds: Optional[int] = None,
        suspicious_threshold: Optional[int] = None,
        dos_threshold: Optional[int] = None,
        ddos_threshold: Optional[int] = None,
        unique_source_threshold: Optional[int] = None,
        protected_target_ips: Optional[List[str]] = None,
    ):
        self.window_seconds = window_seconds if window_seconds is not None else settings.ICMP_WINDOW_SECONDS
        self.suspicious_threshold = (
            suspicious_threshold if suspicious_threshold is not None else settings.ICMP_SUSPICIOUS_THRESHOLD
        )
        self.dos_threshold = dos_threshold if dos_threshold is not None else settings.ICMP_DOS_THRESHOLD
        self.ddos_threshold = ddos_threshold if ddos_threshold is not None else settings.ICMP_DDOS_THRESHOLD
        self.unique_source_threshold = (
            unique_source_threshold if unique_source_threshold is not None else settings.ICMP_UNIQUE_SOURCE_THRESHOLD
        )
        self.protected_target_ips = (
            [ip.strip() for ip in protected_target_ips if ip.strip()]
            if protected_target_ips is not None
            else settings.protected_target_ips_list
        )

    @staticmethod
    def _is_local_sender(ip: str) -> bool:
        if not ip or ip == "unknown":
            return False
        return (
            ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.2")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
            or ip == "127.0.0.1"
            or ip.lower() == "localhost"
        )

    def set_protected_targets(self, targets: List[str]):
        """Dynamically update protected target destination IPs."""
        self.protected_target_ips = [ip.strip() for ip in targets if ip.strip()]

    def analyze_window(
        self, 
        packets: List[IcmpPacketData],
        protected_target_ips: Optional[List[str]] = None
    ) -> IcmpDetectionResult:
        """
        Evaluates a list of ICMP packets captured within the current sliding window.
        Filters incoming Echo Requests (type 8) directed at protected_target_ips,
        separating them from outgoing pings (e.g. to 8.8.8.8) and echo replies (type 0).
        """
        total_packets = len(packets)
        effective_window = max(1.0, float(self.window_seconds))

        active_targets = protected_target_ips if protected_target_ips is not None else self.protected_target_ips
        protected_targets_set = set(active_targets)

        protected_packets: List[IcmpPacketData] = []
        outgoing_count = 0
        reply_count = 0
        unrelated_count = 0

        for pkt in packets:
            src = pkt.source_ip or "unknown"
            dst = pkt.destination_ip or "unknown"
            itype = pkt.icmp_type

            # Check if echo reply (type 0)
            if itype == 0:
                reply_count += 1
                continue

            # If protected targets are defined:
            if protected_targets_set:
                if dst in protected_targets_set and (itype == 8 or itype is None):
                    protected_packets.append(pkt)
                elif (src in protected_targets_set or self._is_local_sender(src)) and (itype == 8 or itype is None):
                    outgoing_count += 1
                else:
                    unrelated_count += 1
            else:
                # If no protected targets configured, treat any incoming echo request as target
                if itype == 8 or itype is None:
                    protected_packets.append(pkt)
                else:
                    unrelated_count += 1

        target_count = len(protected_packets)
        pps = round(target_count / effective_window, 2)

        # Count packets by source and destination for PROTECTED traffic
        source_counts: Dict[str, int] = {}
        dest_counts: Dict[str, int] = {}

        for pkt in protected_packets:
            src = pkt.source_ip or "unknown"
            dst = pkt.destination_ip or "unknown"
            source_counts[src] = source_counts.get(src, 0) + 1
            dest_counts[dst] = dest_counts.get(dst, 0) + 1

        unique_sources = len(source_counts)
        unique_destinations = len(dest_counts)

        # Sort top sources & destinations
        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_destinations = sorted(dest_counts.items(), key=lambda x: x[1], reverse=True)

        top_sources = [{"ip": ip, "count": count} for ip, count in sorted_sources[:5]]
        top_destinations = [{"ip": ip, "count": count} for ip, count in sorted_destinations[:5]]

        primary_source_ip = sorted_sources[0][0] if sorted_sources else None
        target_ip = sorted_destinations[0][0] if sorted_destinations else (
            active_targets[0] if active_targets else None
        )

        # Determine detection state strictly from protected target packets!
        # 1. Distributed DoS (DDoS) Condition:
        is_ddos = (
            (target_count >= self.ddos_threshold or target_count >= self.dos_threshold)
            and unique_sources >= self.unique_source_threshold
        )

        # 2. Single/Low-source DoS Condition:
        is_dos = (
            target_count >= self.dos_threshold
            and unique_sources < self.unique_source_threshold
        )

        # 3. Suspicious Traffic:
        is_suspicious = (
            not (is_ddos or is_dos)
            and target_count >= self.suspicious_threshold
        )

        now = datetime.now(timezone.utc)

        if is_ddos:
            desc = (
                f"Possible ICMP DDoS detected: {target_count} incoming ICMP Echo Requests ({pps} pps) "
                f"observed across {unique_sources} distributed sources targeting {target_ip or 'protected server'} "
                f"within {self.window_seconds}s window."
            )
            alert = AlertCreate(
                title="Possible ICMP DDoS Detected",
                description=desc,
                source_ip=f"{unique_sources} distributed IPs",
                destination_ip=target_ip,
                severity="CRITICAL",
                status="OPEN",
                detection_rule="RULE_07_ICMP_DDOS",
                timestamp=now,
            )
            return IcmpDetectionResult(
                state=STATE_POSSIBLE_DDOS,
                state_label="🔴 POSSIBLE ICMP DDOS DETECTED",
                total_packets=total_packets,
                packets_per_second=pps,
                unique_sources=unique_sources,
                unique_destinations=unique_destinations,
                top_sources=top_sources,
                top_destinations=top_destinations,
                primary_source_ip=primary_source_ip,
                target_ip=target_ip,
                alert_candidate=alert,
                detection_category="Network Availability",
                detection_type="ICMP Distributed Flood",
                description=desc,
                protected_target_ips=list(self.protected_target_ips),
                protected_incoming_requests=target_count,
                outgoing_requests=outgoing_count,
                replies_observed=reply_count,
                unrelated_packets=unrelated_count,
            )

        if is_dos:
            desc = (
                f"Possible ICMP DoS detected: {target_count} incoming ICMP Echo Requests ({pps} pps) "
                f"observed from primary source {primary_source_ip} targeting {target_ip or 'protected server'} "
                f"within {self.window_seconds}s window."
            )
            alert = AlertCreate(
                title="Possible ICMP DoS Detected",
                description=desc,
                source_ip=primary_source_ip,
                destination_ip=target_ip,
                severity="HIGH",
                status="OPEN",
                detection_rule="RULE_06_ICMP_DOS",
                timestamp=now,
            )
            return IcmpDetectionResult(
                state=STATE_POSSIBLE_DOS,
                state_label="🔴 POSSIBLE ICMP DOS DETECTED",
                total_packets=total_packets,
                packets_per_second=pps,
                unique_sources=unique_sources,
                unique_destinations=unique_destinations,
                top_sources=top_sources,
                top_destinations=top_destinations,
                primary_source_ip=primary_source_ip,
                target_ip=target_ip,
                alert_candidate=alert,
                detection_category="Network Availability",
                detection_type="ICMP Flood",
                description=desc,
                protected_target_ips=list(self.protected_target_ips),
                protected_incoming_requests=target_count,
                outgoing_requests=outgoing_count,
                replies_observed=reply_count,
                unrelated_packets=unrelated_count,
            )

        if is_suspicious:
            desc = (
                f"Suspicious ICMP traffic: {target_count} incoming Echo Requests ({pps} pps) "
                f"exceeds suspicious threshold of {self.suspicious_threshold} targeting {target_ip or 'protected server'} within {self.window_seconds}s window."
            )
            return IcmpDetectionResult(
                state=STATE_SUSPICIOUS,
                state_label="🟡 SUSPICIOUS ICMP ACTIVITY",
                total_packets=total_packets,
                packets_per_second=pps,
                unique_sources=unique_sources,
                unique_destinations=unique_destinations,
                top_sources=top_sources,
                top_destinations=top_destinations,
                primary_source_ip=primary_source_ip,
                target_ip=target_ip,
                alert_candidate=None,
                detection_category="Network Availability",
                detection_type="ICMP Elevated Activity",
                description=desc,
                protected_target_ips=list(self.protected_target_ips),
                protected_incoming_requests=target_count,
                outgoing_requests=outgoing_count,
                replies_observed=reply_count,
                unrelated_packets=unrelated_count,
            )

        # NORMAL STATE
        return IcmpDetectionResult(
            state=STATE_NORMAL,
            state_label="🟢 NORMAL",
            total_packets=total_packets,
            packets_per_second=pps,
            unique_sources=unique_sources,
            unique_destinations=unique_destinations,
            top_sources=top_sources,
            top_destinations=top_destinations,
            primary_source_ip=primary_source_ip,
            target_ip=target_ip,
            alert_candidate=None,
            detection_category="Network Availability",
            detection_type="NORMAL",
            description="ICMP traffic is within normal baseline limits.",
            protected_target_ips=list(self.protected_target_ips),
            protected_incoming_requests=target_count,
            outgoing_requests=outgoing_count,
            replies_observed=reply_count,
            unrelated_packets=unrelated_count,
        )
