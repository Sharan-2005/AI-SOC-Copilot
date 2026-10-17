import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.detection.icmp_dos_detector import (
    IcmpDosDetector,
    IcmpPacketData,
    RULE_06_ICMP_DOS,
    RULE_07_ICMP_DDOS,
    STATE_NORMAL,
    STATE_SUSPICIOUS,
    STATE_POSSIBLE_DOS,
    STATE_POSSIBLE_DDOS,
)
from app.services.icmp_monitor import icmp_monitor_service

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_icmp_monitor():
    """Ensure ICMP monitor is stopped and state is clean before each test."""
    if icmp_monitor_service.is_running:
        icmp_monitor_service.stop()
    icmp_monitor_service.reset_stats()
    yield
    if icmp_monitor_service.is_running:
        icmp_monitor_service.stop()
    icmp_monitor_service.reset_stats()


# =========================================================================
# 1. ACTUAL PACKET PARSING TESTS (ECHO REQUEST & ECHO REPLY)
# =========================================================================

def test_actual_packet_parsing_echo_request():
    """Verify Scapy ICMP Echo Request (type 8) is correctly parsed."""
    from scapy.layers.inet import IP, ICMP
    pkt = IP(src="192.168.1.150", dst="10.171.83.105") / ICMP(type=8, code=0)
    
    parsed = icmp_monitor_service.parse_packet(pkt)
    assert parsed is not None
    assert parsed.source_ip == "192.168.1.150"
    assert parsed.destination_ip == "10.171.83.105"
    assert parsed.protocol == "ICMP"
    assert parsed.icmp_type == 8  # Echo Request
    assert parsed.icmp_code == 0
    assert parsed.packet_size > 0
    assert parsed.source == "live_icmp"


def test_actual_packet_parsing_echo_reply():
    """Verify Scapy ICMP Echo Reply (type 0) is correctly parsed."""
    from scapy.layers.inet import IP, ICMP
    pkt = IP(src="10.171.83.105", dst="192.168.1.150") / ICMP(type=0, code=0)
    
    parsed = icmp_monitor_service.parse_packet(pkt)
    assert parsed is not None
    assert parsed.source_ip == "10.171.83.105"
    assert parsed.destination_ip == "192.168.1.150"
    assert parsed.protocol == "ICMP"
    assert parsed.icmp_type == 0  # Echo Reply
    assert parsed.icmp_code == 0


def test_non_icmp_packet_ignored():
    """Verify non-ICMP packets (e.g. TCP/UDP) are cleanly ignored."""
    from scapy.layers.inet import IP, TCP
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80)
    parsed = icmp_monitor_service.parse_packet(pkt)
    assert parsed is None


# =========================================================================
# 2. SLIDING WINDOW COUNTING & PACKET RATE CALCULATION
# =========================================================================

def test_sliding_window_counting_and_rate_calculation():
    """Verify sliding window trims older packets and accurately calculates pps."""
    detector = IcmpDosDetector(
        window_seconds=10,
        suspicious_threshold=100,
        dos_threshold=300,
        ddos_threshold=500,
        unique_source_threshold=10
    )
    now = datetime.now(timezone.utc)
    packets = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=i * 0.2),  # 50 packets over 10s = 5 pps
            source_ip="192.168.1.50",
            destination_ip="10.171.83.105",
            protocol="ICMP"
        )
        for i in range(50)
    ]
    result = detector.analyze_window(packets)
    assert result.total_packets == 50
    assert result.packets_per_second == 5.0
    assert result.state == STATE_NORMAL
    assert result.alert_candidate is None


# =========================================================================
# 3. UNIQUE SOURCE CALCULATION
# =========================================================================

def test_unique_source_calculation():
    """Verify unique source IPs are accurately counted across sliding window."""
    detector = IcmpDosDetector(window_seconds=10)
    now = datetime.now(timezone.utc)
    unique_ips = [f"10.0.0.{i}" for i in range(7)]
    packets = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=0.1),
            source_ip=unique_ips[i % len(unique_ips)],
            destination_ip="192.168.1.1",
            protocol="ICMP"
        )
        for i in range(35)
    ]
    result = detector.analyze_window(packets)
    assert result.unique_sources == 7
    assert len(result.top_sources) <= 10


# =========================================================================
# 4. RULE_06: ICMP DOS DETECTION
# =========================================================================

def test_rule_06_icmp_dos_detection():
    """Verify abnormal packet volume from single/concentrated source triggers RULE_06."""
    detector = IcmpDosDetector(
        window_seconds=10,
        suspicious_threshold=50,
        dos_threshold=150,
        ddos_threshold=300,
        unique_source_threshold=10
    )
    now = datetime.now(timezone.utc)
    attacker_ip = "192.168.1.200"
    target_ip = "10.171.83.105"
    packets = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=i * 0.05),
            source_ip=attacker_ip,
            destination_ip=target_ip,
            protocol="ICMP"
        )
        for i in range(160)
    ]
    result = detector.analyze_window(packets)
    assert result.state == STATE_POSSIBLE_DOS
    assert "POSSIBLE ICMP DOS" in result.state_label
    assert result.alert_candidate is not None
    assert result.alert_candidate.detection_rule == RULE_06_ICMP_DOS
    assert result.alert_candidate.severity == "HIGH"
    assert result.detection_category == "Network Availability"
    assert result.alert_candidate.source_ip == attacker_ip
    assert result.alert_candidate.destination_ip == target_ip


# =========================================================================
# 5. RULE_07: ICMP DDOS DETECTION
# =========================================================================

def test_rule_07_icmp_ddos_detection():
    """Verify abnormal packet volume distributed across many sources triggers RULE_07."""
    detector = IcmpDosDetector(
        window_seconds=10,
        suspicious_threshold=50,
        dos_threshold=150,
        ddos_threshold=200,
        unique_source_threshold=5
    )
    now = datetime.now(timezone.utc)
    target_ip = "10.171.83.105"
    sources = [f"192.168.1.{i}" for i in range(12)]
    packets = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=i * 0.04),
            source_ip=sources[i % 12],
            destination_ip=target_ip,
            protocol="ICMP"
        )
        for i in range(220)
    ]
    result = detector.analyze_window(packets)
    assert result.state == STATE_POSSIBLE_DDOS
    assert "POSSIBLE ICMP DDOS" in result.state_label
    assert result.alert_candidate is not None
    assert result.alert_candidate.detection_rule == RULE_07_ICMP_DDOS
    assert result.alert_candidate.severity == "CRITICAL"
    assert result.detection_category == "Network Availability"
    assert result.unique_sources == 12


# =========================================================================
# 6. THRESHOLD BEHAVIOR OVERRIDE
# =========================================================================

def test_threshold_behavior_override():
    """Verify custom thresholds behave accurately."""
    detector = IcmpDosDetector(
        window_seconds=5,
        suspicious_threshold=10,
        dos_threshold=25,
        ddos_threshold=50,
        unique_source_threshold=3
    )
    now = datetime.now(timezone.utc)
    # 26 packets with 1 source -> triggers DoS at custom threshold 25
    packets = [
        IcmpPacketData(timestamp=now, source_ip="1.1.1.1", destination_ip="2.2.2.2")
        for _ in range(26)
    ]
    result = detector.analyze_window(packets)
    assert result.state == STATE_POSSIBLE_DOS


# =========================================================================
# 7. INTERFACE DETECTION & ACTIVE ADAPTER AUTO-DETECTION
# =========================================================================

def test_interface_detection_and_active_adapter():
    """Verify interface filtering (no clutter by default) and active adapter resolution."""
    clean_ifaces = icmp_monitor_service.get_interfaces(include_advanced=False)
    assert isinstance(clean_ifaces, list)
    assert len(clean_ifaces) > 0

    # Ensure none of the default interfaces are flagged as clutter
    for iface in clean_ifaces:
        assert not iface.get("is_clutter", False)

    # Active interface resolution
    active_iface = icmp_monitor_service.get_active_interface()
    assert active_iface is not None
    assert "name" in active_iface
    assert "ip" in active_iface

    # Advanced list includes all
    adv_ifaces = icmp_monitor_service.get_interfaces(include_advanced=True)
    assert len(adv_ifaces) >= len(clean_ifaces)


# =========================================================================
# 8. CAPTURE DRIVER UNAVAILABLE / NPCAP UNAVAILABLE
# =========================================================================

def test_capture_unavailable_npcap_missing():
    """
    Verify that when Npcap is unavailable, start() raises the exact error:
    'Real packet capture is unavailable. Please install/configure Npcap and restart the application.'
    and does NOT silently generate fake packets.
    """
    with patch.object(
        icmp_monitor_service,
        "_inspect_packet_capture_driver",
        return_value=(False, "Real packet capture is unavailable. Please install/configure Npcap and restart the application.")
    ):
        with pytest.raises(RuntimeError) as exc_info:
            icmp_monitor_service.start()
        assert "Real packet capture is unavailable. Please install/configure Npcap and restart the application." in str(exc_info.value)

        # Also verify API endpoint returns 400 with the exact error
        res = client.post("/api/icmp/start", json={"interface": "default"})
        assert res.status_code == 400
        assert "Real packet capture is unavailable. Please install/configure Npcap and restart the application." in res.json()["detail"]


# =========================================================================
# 9. MONITORING START & STOP LIFECYCLE (WITH MOCKED DRIVER)
# =========================================================================

def test_monitoring_start_stop_lifecycle():
    """Verify clean start, duplicate prevention, and stop behavior when driver is functional."""
    with patch.object(icmp_monitor_service, "_inspect_packet_capture_driver", return_value=(True, "Npcap driver ready")), \
         patch.object(icmp_monitor_service, "_run_real_capture_loop", return_value=None):
        
        # 1. Start monitoring
        start_res = client.post("/api/icmp/start", json={"interface": "Wi-Fi"})
        assert start_res.status_code == 200
        data = start_res.json()["data"]
        assert data["is_running"] is True
        assert data["status_display"] == "REAL CAPTURE ACTIVE"

        # 2. Duplicate start returns 409
        dup_res = client.post("/api/icmp/start", json={"interface": "Wi-Fi"})
        assert dup_res.status_code == 409

        # 3. Stop monitoring
        stop_res = client.post("/api/icmp/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["data"]["is_running"] is False
        assert stop_res.json()["data"]["status_display"] == "MONITORING STOPPED"


# =========================================================================
# 10. REAL COUNTERS NOT TAINTED BY SIMULATION
# =========================================================================

def test_real_counters_not_tainted_by_simulation():
    """Verify that simulate_traffic does NOT increment real packet counters."""
    # Ensure fresh reset
    icmp_monitor_service.reset_stats()

    # Trigger simulation DoS
    sim_res = client.post("/api/icmp/simulate", json={"scenario": "dos", "count": 350})
    assert sim_res.status_code == 200
    assert sim_res.json()["is_simulation"] is True

    # Real status MUST NOT be tainted
    status_res = client.get("/api/icmp/status")
    assert status_res.status_code == 200
    real_status = status_res.json()
    assert real_status["packets_observed"] == 0
    assert real_status["current_rate_pps"] == 0.0
    assert real_status["detection_state"] == STATE_NORMAL


# =========================================================================
# 11. RECORD REAL PACKET INCREMENTS REAL TELEMETRY
# =========================================================================

def test_record_real_packet_increments_real_counters():
    """Verify record_real_packet updates real counters and sliding window."""
    now = datetime.now(timezone.utc)
    pkt_data = IcmpPacketData(
        timestamp=now,
        source_ip="192.168.1.55",
        destination_ip="10.171.83.105",
        protocol="ICMP",
        icmp_type=8,
        icmp_code=0,
        packet_size=64,
        interface="Wi-Fi",
        source="live_icmp",
    )
    icmp_monitor_service.record_real_packet(pkt_data)

    with icmp_monitor_service._lock:
        assert icmp_monitor_service._real_total_observed == 1
        assert len(icmp_monitor_service._real_packets) == 1


# =========================================================================
# 12. MITRE RULES REGISTRY TABLE (RULE_01 TO RULE_07)
# =========================================================================

def test_mitre_rules_endpoint_includes_all_rules():
    """Verify /api/mitre/rules returns RULE_01 through RULE_07 with accurate metadata."""
    res = client.get("/api/mitre/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) == 7

    rule_map = {r["rule_id"]: r for r in rules}

    # Verify existing RULE_01 - RULE_05
    assert "RULE_01" in rule_map
    assert "RULE_02" in rule_map
    assert "RULE_03" in rule_map
    assert "RULE_04" in rule_map
    assert "RULE_05" in rule_map

    # Verify Phase 5 RULE_06
    assert "RULE_06" in rule_map
    r6 = rule_map["RULE_06"]
    assert "ICMP Flood" in r6["name"] or "DoS" in r6["name"]
    assert r6["category"] == "Network Availability"
    assert r6["severity"] == "HIGH"
    assert r6["source"] == "Live ICMP Monitor"
    assert "N/A" in r6["mitre_id"]

    # Verify Phase 5 RULE_07
    assert "RULE_07" in rule_map
    r7 = rule_map["RULE_07"]
    assert "DDoS" in r7["name"] or "Distributed" in r7["name"]
    assert r7["category"] == "Network Availability"
    assert r7["severity"] == "CRITICAL"
    assert r7["source"] == "Live ICMP Monitor"
    assert "N/A" in r7["mitre_id"]


# =========================================================================
# 13. PROTECTED TARGET FILTERING & EXCLUSION OF PING 8.8.8.8
# =========================================================================

def test_ping_8888_and_unrelated_traffic_excluded_from_protected_server():
    """
    Ensure pinging 8.8.8.8 or unrelated hosts from laptop does NOT trigger
    an alert for a protected server (e.g. 203.0.113.10).
    """
    detector = IcmpDosDetector(
        window_seconds=10,
        dos_threshold=300,
        ddos_threshold=500,
        protected_target_ips=["203.0.113.10"]
    )
    now = datetime.now(timezone.utc)
    laptop_ip = "192.168.1.100"

    # 1. 400 Outgoing echo requests: Laptop -> 8.8.8.8 (type 8)
    outgoing_pings = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=i * 0.02),
            source_ip=laptop_ip,
            destination_ip="8.8.8.8",
            icmp_type=8,
            protocol="ICMP"
        )
        for i in range(400)
    ]

    # 2. 400 Incoming echo replies: 8.8.8.8 -> Laptop (type 0 pong)
    incoming_replies = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=i * 0.02),
            source_ip="8.8.8.8",
            destination_ip=laptop_ip,
            icmp_type=0,
            protocol="ICMP"
        )
        for i in range(400)
    ]

    # 3. 400 Packets directed to some unrelated third-party IP (type 8, external source)
    unrelated_traffic = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=i * 0.02),
            source_ip="198.51.100.5",
            destination_ip="1.1.1.1",
            icmp_type=8,
            protocol="ICMP"
        )
        for i in range(400)
    ]

    all_packets = outgoing_pings + incoming_replies + unrelated_traffic

    result = detector.analyze_window(all_packets, protected_target_ips=["203.0.113.10"])

    # ZERO packets matched the protected target
    assert result.protected_incoming_requests == 0
    assert result.total_packets == 1200
    assert result.packets_per_second == 0.0
    assert result.state == STATE_NORMAL
    assert result.alert_candidate is None

    # Telemetry classification checks
    assert result.outgoing_requests == 400
    assert result.replies_observed == 400
    assert result.unrelated_packets == 400


def test_protected_target_traffic_analyzed_correctly():
    """
    Ensure packets directed to the protected target IP are properly counted
    and trigger RULE_06 (DoS) and RULE_07 (DDoS).
    """
    detector = IcmpDosDetector(
        window_seconds=10,
        dos_threshold=300,
        ddos_threshold=500,
        unique_source_threshold=5,
        protected_target_ips=["203.0.113.10"]
    )
    now = datetime.now(timezone.utc)
    protected_ip = "203.0.113.10"

    # Single-source flood directed at protected server
    dos_packets = [
        IcmpPacketData(
            timestamp=now - timedelta(seconds=i * 0.02),
            source_ip="198.51.100.99",
            destination_ip=protected_ip,
            icmp_type=8,
            protocol="ICMP"
        )
        for i in range(350)
    ]

    result = detector.analyze_window(dos_packets, protected_target_ips=[protected_ip])

    assert result.total_packets == 350
    assert result.target_ip == protected_ip
    assert result.protected_incoming_requests == 350
    assert result.state == STATE_POSSIBLE_DOS
    assert result.alert_candidate is not None
    assert result.alert_candidate.detection_rule == RULE_06_ICMP_DOS
    assert result.alert_candidate.destination_ip == protected_ip


def test_service_record_real_packet_directional_counters():
    """
    Verify icmp_monitor_service categorizes live packets into
    protected incoming, outgoing, reply, and unrelated counters.
    """
    icmp_monitor_service.reset_stats()
    icmp_monitor_service.set_protected_targets(["192.168.1.100"])
    now = datetime.now(timezone.utc)

    # 1. Incoming echo request to protected IP
    icmp_monitor_service.record_real_packet(IcmpPacketData(
        timestamp=now,
        source_ip="10.0.0.1",
        destination_ip="192.168.1.100",
        icmp_type=8
    ))

    # 2. Outgoing echo request from protected IP to 8.8.8.8
    icmp_monitor_service.record_real_packet(IcmpPacketData(
        timestamp=now,
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        icmp_type=8
    ))

    # 3. Echo reply from 8.8.8.8 (type 0)
    icmp_monitor_service.record_real_packet(IcmpPacketData(
        timestamp=now,
        source_ip="8.8.8.8",
        destination_ip="192.168.1.100",
        icmp_type=0
    ))

    # 4. Unrelated packet (external public IPs)
    icmp_monitor_service.record_real_packet(IcmpPacketData(
        timestamp=now,
        source_ip="198.51.100.1",
        destination_ip="198.51.100.2",
        icmp_type=8
    ))

    with icmp_monitor_service._lock:
        assert icmp_monitor_service._real_protected_incoming_count == 1
        assert icmp_monitor_service._real_outgoing_count == 1
        assert icmp_monitor_service._real_replies_count == 1
        assert icmp_monitor_service._real_unrelated_count == 1
        assert icmp_monitor_service._real_total_observed == 4


# =========================================================================
# 14. PROTECTED TARGET API ENDPOINTS
# =========================================================================

def test_protected_targets_api_get_and_put():
    """Verify GET and PUT /api/icmp/targets endpoints."""
    # 1. GET returns current targets
    get_res = client.get("/api/icmp/targets")
    assert get_res.status_code == 200
    assert "protected_targets" in get_res.json()
    assert "count" in get_res.json()

    # 2. PUT updates targets successfully
    put_res = client.put("/api/icmp/targets", json={"protected_targets": ["198.51.100.1", "203.0.113.5"]})
    assert put_res.status_code == 200
    assert put_res.json()["protected_targets"] == ["198.51.100.1", "203.0.113.5"]

    # 3. Verify status reflects the update
    status_res = client.get("/api/icmp/status")
    assert status_res.status_code == 200
    assert "198.51.100.1" in status_res.json()["protected_target_ips"]
    assert status_res.json()["sensor_info"]["sensor_mode"] == "REMOTE_TARGET"

    # 4. PUT with invalid IP format returns 400
    bad_res = client.put("/api/icmp/targets", json={"protected_targets": ["invalid_ip_###"]})
    assert bad_res.status_code == 400
    assert "Invalid IP address or hostname" in bad_res.json()["detail"]

