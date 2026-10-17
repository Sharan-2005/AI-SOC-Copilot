import logging
import threading
import time
import socket
import select
from datetime import datetime, timedelta, timezone
from collections import deque
from typing import List, Dict, Any, Optional, Tuple

from app.config import settings
from app.detection.icmp_dos_detector import (
    IcmpDosDetector,
    IcmpPacketData,
    IcmpDetectionResult,
    STATE_NORMAL,
    STATE_SUSPICIOUS,
    STATE_POSSIBLE_DOS,
    STATE_POSSIBLE_DDOS,
)
from app.database.connection import SessionLocal
from app.models.event import Event
from app.models.alert import Alert
from app.detection.correlator import correlate_alerts

logger = logging.getLogger("services.icmp_monitor")

class IcmpMonitorService:
    """
    Production-grade Live ICMP Network Monitoring and DoS/DDoS Detection Service.
    Strictly separates REAL captured network telemetry from local synthetic simulations.
    Features:
      - Automatic active network interface detection (Wi-Fi / Ethernet with real IPs)
      - Filtered interface listing (suppressing low-level WFP / virtual filter clutter)
      - Verification of real packet capture support (Npcap / driver check)
      - Real packet capture via Scapy AsyncSniffer or raw socket
      - Sliding time-window analysis of actual packet metadata (type 8 echo request, type 0 reply)
      - Deterministic evaluation of RULE_06 (Possible DoS) and RULE_07 (Possible DDoS)
      - Full Supabase PostgreSQL persistence and incident correlation
      - Completely isolated Local Test / Simulation mode with distinct metrics
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._running = False
        self._stop_event = threading.Event()
        self._sniffer_thread: Optional[threading.Thread] = None

        self._active_interface_name: Optional[str] = None
        self._active_interface_ip: Optional[str] = None
        self._capture_driver_available: bool = False
        self._driver_status_message: str = ""

        self.window_seconds: int = settings.ICMP_WINDOW_SECONDS
        self._protected_target_ips: List[str] = list(settings.protected_target_ips_list)
        self.detector = IcmpDosDetector(
            window_seconds=settings.ICMP_WINDOW_SECONDS,
            suspicious_threshold=settings.ICMP_SUSPICIOUS_THRESHOLD,
            dos_threshold=settings.ICMP_DOS_THRESHOLD,
            ddos_threshold=settings.ICMP_DDOS_THRESHOLD,
            unique_source_threshold=settings.ICMP_UNIQUE_SOURCE_THRESHOLD,
            protected_target_ips=self._protected_target_ips,
        )

        # -------------------------------------------------------------
        # 1. REAL LIVE CAPTURE TELEMETRY BUFFER (Populated ONLY by real packets)
        # -------------------------------------------------------------
        self._real_packets: deque[IcmpPacketData] = deque()
        self._real_total_observed: int = 0
        self._real_protected_incoming_count: int = 0
        self._real_outgoing_count: int = 0
        self._real_replies_count: int = 0
        self._real_unrelated_count: int = 0
        self._real_last_packet_time: Optional[datetime] = None
        self._real_rate_history: deque[Dict[str, Any]] = deque(maxlen=60)
        self._real_recent_events: deque[Dict[str, Any]] = deque(maxlen=50)
        self._real_current_result: IcmpDetectionResult = self.detector.analyze_window([])
        self._real_last_alert_time: Optional[datetime] = None
        self._real_last_alert_state: Optional[str] = None

        # -------------------------------------------------------------
        # 2. ISOLATED LOCAL TEST / SIMULATION BUFFER (Separated from real counters)
        # -------------------------------------------------------------
        self._sim_packets: deque[IcmpPacketData] = deque()
        self._sim_total_observed: int = 0
        self._sim_rate_history: deque[Dict[str, Any]] = deque(maxlen=60)
        self._sim_recent_events: deque[Dict[str, Any]] = deque(maxlen=50)
        self._sim_current_result: IcmpDetectionResult = self.detector.analyze_window([])
        self._sim_last_alert_time: Optional[datetime] = None
        self._sim_last_alert_state: Optional[str] = None

        # Perform initial driver check and active adapter discovery
        self._inspect_packet_capture_driver()
        self._detect_primary_interface()

    def _inspect_packet_capture_driver(self) -> Tuple[bool, str]:
        """
        Verifies if real packet capture support (Npcap/WinPcap or operational raw socket)
        is functional on this host.
        """
        try:
            from scapy.all import conf
            if getattr(conf, "use_pcap", False):
                # Verify whether interfaces can be enumerated
                if len(conf.ifaces) > 0:
                    self._capture_driver_available = True
                    self._driver_status_message = "Npcap driver active and ready for live capture."
                    return True, self._driver_status_message
        except Exception as exc:
            logger.debug(f"Pcap driver check error: {exc}")

        # Check if raw socket can be bound on Windows
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            # Note: without Npcap or Admin on modern Windows, promiscuous packet capture is restricted
        except Exception:
            pass

        self._capture_driver_available = False
        self._driver_status_message = (
            "Real packet capture is unavailable. Please install/configure Npcap and restart the application."
        )
        return False, self._driver_status_message

    def is_capture_driver_available(self) -> bool:
        return self._capture_driver_available

    def get_driver_status(self) -> Dict[str, Any]:
        available, msg = self._inspect_packet_capture_driver()
        return {
            "available": available,
            "message": msg,
            "requirement": "Npcap (Windows) or root raw-socket permissions (Linux/macOS)"
        }

    # =========================================================================
    # ACTIVE ADAPTER AUTO-DETECTION & FILTERED INTERFACE LISTING
    # =========================================================================
    def _detect_primary_interface(self):
        """
        Automatically selects the primary active network adapter (e.g. Wi-Fi with valid IPv4).
        """
        ifaces = self.get_interfaces(include_advanced=False)
        active = next((i for i in ifaces if i.get("is_active")), None)
        if active:
            self._active_interface_name = active["name"]
            self._active_interface_ip = active["ip"]
        elif ifaces:
            self._active_interface_name = ifaces[0]["name"]
            self._active_interface_ip = ifaces[0].get("ip")
        else:
            self._active_interface_name = "default"
            self._active_interface_ip = "127.0.0.1"

        if not self._protected_target_ips:
            fallback_target = self._active_interface_ip or "10.171.83.105"
            self._protected_target_ips = [fallback_target, "127.0.0.1"]
            self.detector.set_protected_targets(self._protected_target_ips)

    def _is_local_sender(self, ip: str) -> bool:
        if not ip or ip == "unknown":
            return False
        return (
            ip == self._active_interface_ip
            or ip == "127.0.0.1"
            or ip.lower() == "localhost"
            or ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.2")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
        )

    def get_protected_targets(self) -> List[str]:
        """Returns the list of active protected destination IPs."""
        with self._lock:
            return list(self._protected_target_ips)

    def set_protected_targets(self, targets: List[str]) -> List[str]:
        """Dynamically configures protected destination IPs."""
        import ipaddress
        import re
        cleaned = []
        for t in targets:
            if not t or not t.strip():
                continue
            item = t.strip()
            try:
                ipaddress.ip_address(item)
            except ValueError:
                if not re.match(r"^[a-zA-Z0-9.-]+$", item) or "#" in item or "_" in item:
                    raise ValueError(f"Invalid IP address or hostname: '{item}'")
            cleaned.append(item)

        with self._lock:
            self._protected_target_ips = cleaned
            self.detector.set_protected_targets(self._protected_target_ips)
            self._maintain_real_sliding_window()
            logger.info(f"Updated protected target IPs: {self._protected_target_ips}")
            return list(self._protected_target_ips)

    def get_active_interface(self) -> Dict[str, Any]:
        """
        Returns details of the automatically detected primary active interface.
        """
        with self._lock:
            if not self._active_interface_name:
                self._detect_primary_interface()

            # Find matching info
            all_ifaces = self.get_interfaces(include_advanced=True)
            match = next((i for i in all_ifaces if i["name"].lower() == self._active_interface_name.lower()), None)
            if match:
                return match

            return {
                "name": self._active_interface_name or "Wi-Fi",
                "ip": self._active_interface_ip or "127.0.0.1",
                "description": "Primary active network connection",
                "is_active": True,
                "is_default": True
            }

    def get_interfaces(self, include_advanced: bool = False) -> List[Dict[str, Any]]:
        """
        Returns network interfaces.
        By default (include_advanced=False), suppresses low-level Windows clutter (WFP, 802.3, virtual filters)
        and returns clean user-facing adapters with their actual IPv4 addresses.
        """
        clean_interfaces = []
        raw_interfaces = []

        try:
            from scapy.arch.windows import get_windows_if_list
            raw_interfaces = get_windows_if_list()
        except Exception as exc:
            logger.debug(f"Could not load Windows interfaces: {exc}")

        # Helper to check if IP is a normal routable IPv4 (not link-local 169.254, not loopback)
        def is_routable_ipv4(ip_str: str) -> bool:
            return bool(
                ip_str
                and not ip_str.startswith("169.254.")
                and not ip_str.startswith("127.")
                and ":" not in ip_str
            )

        for iface in raw_interfaces:
            name = iface.get("name") or "Unknown"
            desc = iface.get("description") or ""
            guid = iface.get("guid") or ""
            all_ips = iface.get("ips") or []
            valid_ips = [ip for ip in all_ips if is_routable_ipv4(ip)]
            primary_ip = valid_ips[0] if valid_ips else (all_ips[0] if all_ips else None)

            combined_str = f"{name} {desc}".lower()
            is_loopback = "loopback" in combined_str or "127.0.0.1" in all_ips
            is_clutter = not is_loopback and any(k in combined_str for k in [
                "wfp", "native mac", "802.3", "qos packet scheduler", "filter",
                "virtualbox host-only", "vmware virtual ethernet", "direct virtual adapter",
                "bluetooth"
            ])

            if is_loopback and not primary_ip:
                primary_ip = "127.0.0.1"

            is_active = (len(valid_ips) > 0 or is_loopback) and not is_clutter

            item = {
                "id": name,
                "name": name,
                "description": desc or ("Loopback Interface" if is_loopback else ""),
                "ip": primary_ip,
                "ips": all_ips if all_ips else (["127.0.0.1"] if is_loopback else []),
                "guid": guid,
                "is_active": is_active,
                "is_clutter": is_clutter,
            }

            if not is_clutter or include_advanced:
                clean_interfaces.append(item)

        # Sort so active physical interfaces with real IPs appear first, followed by loopback
        clean_interfaces.sort(
            key=lambda x: (
                not x.get("is_active", False),
                x.get("ip") == "127.0.0.1",
                x.get("is_clutter", False)
            )
        )

        # Fallback if list is empty
        if not clean_interfaces:
            try:
                host_name = socket.gethostname()
                host_ip = socket.gethostbyname(host_name)
                clean_interfaces.append({
                    "id": "Wi-Fi",
                    "name": "Wi-Fi",
                    "description": "Primary Network Adapter",
                    "ip": host_ip,
                    "ips": [host_ip],
                    "guid": "",
                    "is_active": True,
                    "is_clutter": False
                })
            except Exception:
                clean_interfaces.append({
                    "id": "default",
                    "name": "Default Interface",
                    "description": "Active Interface",
                    "ip": "127.0.0.1",
                    "ips": ["127.0.0.1"],
                    "guid": "",
                    "is_active": True,
                    "is_clutter": False
                })

        return clean_interfaces

    # =========================================================================
    # REAL PACKET MONITORING LIFECYCLE (START / STOP)
    # =========================================================================
    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, interface: Optional[str] = None, protected_targets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Starts REAL ICMP packet monitoring on the active network interface.
        If packet capture driver is unavailable on this host, raises a clear RuntimeError
        requiring Npcap installation rather than silently generating fake data.
        """
        with self._lock:
            if self._running:
                raise ValueError("Real ICMP Monitor is already active.")

            if protected_targets is not None:
                cleaned = [t.strip() for t in protected_targets if t and t.strip()]
                if cleaned:
                    self.set_protected_targets(cleaned)

            # Resolve interface
            active_info = self.get_active_interface()
            selected_name = interface or active_info.get("name") or "default"
            self._active_interface_name = selected_name
            self._active_interface_ip = active_info.get("ip") or "10.171.83.105"

            # Check if real capture driver is available
            driver_ok, driver_msg = self._inspect_packet_capture_driver()
            if not driver_ok:
                logger.warning(f"Cannot start real packet capture: {driver_msg}")
                raise RuntimeError(
                    "Real packet capture is unavailable. Please install/configure Npcap and restart the application."
                )

            # Start real capture worker thread
            self._stop_event.clear()
            self._running = True

            self._sniffer_thread = threading.Thread(
                target=self._run_real_capture_loop,
                name="RealIcmpSnifferWorker",
                daemon=True
            )
            self._sniffer_thread.start()

            logger.info(
                f"REAL CAPTURE ACTIVE on interface: '{self._active_interface_name}' ({self._active_interface_ip}) "
                f"| Protected Targets: {self._protected_target_ips}"
            )

        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """
        Stops the active real ICMP packet capture worker thread.
        """
        with self._lock:
            if not self._running:
                raise ValueError("ICMP Monitor is not running.")
            self._running = False
            self._stop_event.set()

        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=2.0)
            self._sniffer_thread = None

        logger.info("Real ICMP packet capture stopped.")
        return self.get_status()

    def _run_real_capture_loop(self):
        """
        Captures actual ICMP packets from the network adapter using Scapy AsyncSniffer.
        On Windows, captures from the selected physical interface as well as the Npcap Loopback adapter
        so that both external network traffic and local pings (ping 127.0.0.1, ping own IP) are captured.
        """
        target_iface = self._active_interface_name
        logger.info(f"Beginning packet sniffer thread on {target_iface}")

        sniffer = None
        try:
            from scapy.all import AsyncSniffer, conf

            ifaces_to_listen = []
            if target_iface and target_iface != "default":
                for iface in conf.ifaces.values():
                    if (target_iface.lower() in iface.name.lower() or 
                        target_iface.lower() in iface.description.lower() or 
                        target_iface == getattr(iface, "guid", "")):
                        ifaces_to_listen.append(iface)
                        break

            # On Windows, always include Loopback adapter if available
            # so local test pings (ping 127.0.0.1, ping own IP) are also captured
            loop_iface = next(
                (i for i in conf.ifaces.values() if "loopback" in i.name.lower() or "loopback" in i.description.lower()),
                None
            )
            if loop_iface and loop_iface not in ifaces_to_listen:
                ifaces_to_listen.append(loop_iface)

            sniff_target = ifaces_to_listen if len(ifaces_to_listen) > 1 else (ifaces_to_listen[0] if ifaces_to_listen else None)
            logger.info(f"AsyncSniffer listening on: {sniff_target}")

            sniffer = AsyncSniffer(
                iface=sniff_target,
                filter="icmp",
                prn=self._process_real_packet,
                store=False
            )
            sniffer.start()
        except Exception as exc:
            logger.error(f"AsyncSniffer failed on {target_iface}: {exc}")
            with self._lock:
                self._running = False
            return

        last_tick = time.time()
        try:
            while not self._stop_event.is_set():
                now_sec = time.time()
                if now_sec - last_tick >= 1.0:
                    self._maintain_real_sliding_window()
                    last_tick = now_sec
                self._stop_event.wait(0.2)
        finally:
            if sniffer:
                try:
                    sniffer.stop()
                except Exception:
                    pass

    def parse_packet(self, pkt) -> Optional[IcmpPacketData]:
        """
        Parses an actual or captured network packet, extracting IPv4 and ICMP metadata.
        Returns IcmpPacketData if valid ICMP packet, else None.
        Supports ICMP Type 8 (Echo Request) and Type 0 (Echo Reply).
        """
        try:
            from scapy.layers.inet import IP, ICMP
            if IP in pkt and ICMP in pkt:
                icmp_layer = pkt[ICMP]
                return IcmpPacketData(
                    timestamp=datetime.now(timezone.utc),
                    source_ip=str(pkt[IP].src),
                    destination_ip=str(pkt[IP].dst),
                    protocol="ICMP",
                    icmp_type=int(icmp_layer.type), # 8 = echo request, 0 = echo reply
                    icmp_code=int(icmp_layer.code),
                    packet_size=len(pkt),
                    interface=self._active_interface_name or "Wi-Fi",
                    source="live_icmp",
                )
        except Exception as exc:
            logger.debug(f"Error parsing packet: {exc}")
        return None

    def _process_real_packet(self, pkt):
        """
        Callback for each REAL captured ICMP packet.
        Extracts source IP, destination IP, ICMP type/code, and feeds real sliding window.
        """
        parsed = self.parse_packet(pkt)
        if parsed:
            self.record_real_packet(parsed)

    def record_real_packet(self, pkt_data: IcmpPacketData):
        """
        Ingests an actual captured ICMP packet into the real sliding window,
        categorizing it into protected incoming, outgoing, reply, or unrelated.
        """
        with self._lock:
            self._real_packets.append(pkt_data)
            self._real_total_observed += 1
            self._real_last_packet_time = pkt_data.timestamp

            itype = pkt_data.icmp_type
            dst = pkt_data.destination_ip
            src = pkt_data.source_ip
            targets = set(self._protected_target_ips)

            if itype == 0:
                self._real_replies_count += 1
            elif targets:
                if dst in targets and (itype == 8 or itype is None):
                    self._real_protected_incoming_count += 1
                elif (src in targets or self._is_local_sender(src)) and (itype == 8 or itype is None):
                    self._real_outgoing_count += 1
                else:
                    self._real_unrelated_count += 1
            else:
                if itype == 8 or itype is None:
                    self._real_protected_incoming_count += 1
                else:
                    self._real_unrelated_count += 1

    def _maintain_real_sliding_window(self):
        """
        Sliding-window evaluation for REAL packets.
        Trims packets older than window_seconds, calculates real pps and source count,
        and triggers RULE_06 / RULE_07 upon abnormal volume.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)

        with self._lock:
            while self._real_packets and self._real_packets[0].timestamp < cutoff:
                self._real_packets.popleft()
            current_window = list(self._real_packets)

        # Run deterministic detector
        result = self.detector.analyze_window(current_window)

        with self._lock:
            self._real_current_result = result
            time_str = now.strftime("%H:%M:%S")
            self._real_rate_history.append({
                "time": time_str,
                "pps": result.packets_per_second,
                "packets": result.total_packets,
                "state": result.state
            })

        # Alert generation on abnormal real traffic
        if result.alert_candidate:
            self._persist_real_alert(result, now)

    def _persist_real_alert(self, result: IcmpDetectionResult, now: datetime):
        """
        Persists real ICMP anomaly alert to Supabase and triggers incident correlation.
        """
        cand = result.alert_candidate
        if not cand:
            return

        # Cooldown check: 15s between duplicate alerts of same state
        if self._real_last_alert_state == result.state and self._real_last_alert_time:
            if (now - self._real_last_alert_time).total_seconds() < 15.0:
                return

        self._real_last_alert_time = now
        self._real_last_alert_state = result.state

        db = None
        try:
            db = SessionLocal()
            event_type = "icmp_flood" if result.state == STATE_POSSIBLE_DOS else "icmp_distributed_flood"

            event = Event(
                timestamp=now,
                source="live_icmp",
                host="soc-icmp-sensor",
                source_ip=result.primary_source_ip if result.state == STATE_POSSIBLE_DOS else f"{result.unique_sources} distributed IPs",
                destination_ip=result.target_ip or self._active_interface_ip or "127.0.0.1",
                source_port=None,
                destination_port=None,
                protocol="ICMP",
                event_type=event_type,
                raw_data={
                    "detection_type": result.detection_type,
                    "category": result.detection_category,
                    "packet_count": result.total_packets,
                    "pps": result.packets_per_second,
                    "unique_sources": result.unique_sources,
                    "interface": self._active_interface_name,
                    "interface_ip": self._active_interface_ip,
                    "description": result.description
                }
            )
            db.add(event)
            db.commit()
            db.refresh(event)

            alert = Alert(
                event_id=event.id,
                title=cand.title,
                description=cand.description,
                source_ip=cand.source_ip,
                destination_ip=cand.destination_ip,
                severity=cand.severity,
                status="OPEN",
                detection_rule=cand.detection_rule,
                timestamp=now
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)

            # Correlate alert into incident system
            try:
                correlate_alerts([alert], db)
            except Exception as corr_err:
                logger.error(f"Incident correlation error: {corr_err}")

            with self._lock:
                self._real_recent_events.append({
                    "id": event.id,
                    "alert_id": alert.id,
                    "timestamp": now.isoformat(),
                    "title": alert.title,
                    "severity": alert.severity,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "detection_type": result.detection_type,
                    "packet_count": result.total_packets,
                    "packets_per_second": result.packets_per_second,
                    "unique_sources": result.unique_sources,
                    "status": alert.status
                })

            logger.info(f"Persisted REAL ICMP Alert: [{alert.severity}] {alert.title}")
        except Exception as exc:
            logger.warning(f"Could not persist real ICMP alert to DB: {exc}")
        finally:
            if db:
                db.close()

    # =========================================================================
    # TELEMETRY STATUS (STRICTLY REAL VS SIMULATION)
    # =========================================================================
    def get_status(self) -> Dict[str, Any]:
        """
        Returns status representing REAL captured ICMP packets.
        Does NOT mix simulated statistics with real packet telemetry.
        """
        with self._lock:
            res = self._real_current_result
            active_iface = self.get_active_interface()
            driver_ok, driver_msg = self._inspect_packet_capture_driver()

            status_display = "REAL CAPTURE ACTIVE" if self._running else "MONITORING STOPPED"

            # Check network sensor visibility for protected targets
            targets = self.get_protected_targets()
            host_ips = {self._active_interface_ip, "127.0.0.1", "localhost"}
            is_local_host_target = bool(not targets or any(t in host_ips for t in targets))

            sensor_info = {
                "sensor_host_ip": self._active_interface_ip or "10.171.83.105",
                "sensor_mode": "HOST_BASED" if is_local_host_target else "REMOTE_TARGET",
                "can_observe_target_traffic": is_local_host_target,
                "visibility_explanation": (
                    "Sensor is actively observing local interface traffic for configured target."
                    if is_local_host_target else
                    "Notice: Configured target is a remote host. A standard personal laptop cannot observe packets directed at remote websites/servers across the Internet unless the agent is installed directly on the protected server or on a network TAP/SPAN port at the target gateway."
                )
            }

            return {
                "is_running": self._running,
                "status_display": status_display,
                "interface": active_iface.get("name") or self._active_interface_name or "Wi-Fi",
                "interface_ip": active_iface.get("ip") or self._active_interface_ip or "10.171.83.105",
                "protected_target_ips": targets,
                "sensor_info": sensor_info,
                "driver_available": driver_ok,
                "driver_message": driver_msg if not driver_ok else None,
                "capture_mode": "REAL" if self._running else "STOPPED",
                "packets_observed": self._real_total_observed if self._running else 0,
                "protected_incoming_requests": res.protected_incoming_requests if self._running else 0,
                "outgoing_requests": res.outgoing_requests if self._running else 0,
                "replies_observed": res.replies_observed if self._running else 0,
                "unrelated_packets": res.unrelated_packets if self._running else 0,
                "total_protected_incoming_observed": self._real_protected_incoming_count if self._running else 0,
                "total_outgoing_observed": self._real_outgoing_count if self._running else 0,
                "total_replies_observed": self._real_replies_count if self._running else 0,
                "total_unrelated_observed": self._real_unrelated_count if self._running else 0,
                "current_rate_pps": res.packets_per_second if self._running else 0.0,
                "active_window_packets": res.total_packets if self._running else 0,
                "unique_sources": res.unique_sources if self._running else 0,
                "unique_destinations": res.unique_destinations if self._running else 0,
                "detection_state": res.state if self._running else STATE_NORMAL,
                "detection_label": res.state_label if self._running else "⚪ MONITORING STOPPED",
                "detection_type": res.detection_type if self._running else "NONE",
                "window_seconds": self.window_seconds,
                "last_packet_time": self._real_last_packet_time.isoformat() if self._real_last_packet_time else None,
                "thresholds": {
                    "window_seconds": self.window_seconds,
                    "suspicious_threshold": self.detector.suspicious_threshold,
                    "dos_threshold": self.detector.dos_threshold,
                    "ddos_threshold": self.detector.ddos_threshold,
                    "unique_source_threshold": self.detector.unique_source_threshold,
                }
            }

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns real traffic statistics for charting.
        """
        with self._lock:
            status_data = self.get_status()
            res = self._real_current_result
            history = list(self._real_rate_history)

            if not history:
                now = datetime.now(timezone.utc)
                for i in range(10):
                    t = (now - timedelta(seconds=(9 - i))).strftime("%H:%M:%S")
                    history.append({"time": t, "pps": 0.0, "packets": 0, "state": STATE_NORMAL})

            return {
                **status_data,
                "top_sources": res.top_sources if self._running else [],
                "top_destinations": res.top_destinations if self._running else [],
                "history": history
            }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Returns recent real ICMP detection events.
        """
        with self._lock:
            return list(self._real_recent_events)[-limit:]

    def reset_stats(self):
        """
        Clears real telemetry sliding window and packet counters, as well as simulation buffers.
        """
        with self._lock:
            self._real_packets.clear()
            self._real_total_observed = 0
            self._real_protected_incoming_count = 0
            self._real_outgoing_count = 0
            self._real_replies_count = 0
            self._real_unrelated_count = 0
            self._real_rate_history.clear()
            self._real_recent_events.clear()
            self._real_current_result = self.detector.analyze_window([])
            self._real_last_alert_time = None
            self._real_last_alert_state = None

            self._sim_packets.clear()
            self._sim_total_observed = 0
            self._sim_rate_history.clear()
            self._sim_recent_events.clear()
            self._sim_current_result = self.detector.analyze_window([])
            self._sim_last_alert_time = None
            self._sim_last_alert_state = None

    # =========================================================================
    # ISOLATED DEMONSTRATION / SIMULATION (SECTION 1, 8, 11)
    # Strictly separated from live real telemetry!
    # =========================================================================
    def simulate_traffic(
        self,
        scenario: str = "normal",
        count: Optional[int] = None,
        target_ip: str = "127.0.0.1",
        attacker_ip: str = "192.168.1.185",
    ) -> Dict[str, Any]:
        """
        LOCAL TEST / SIMULATION ONLY:
        Generates synthetic ICMP packets to verify RULE_06 and RULE_07 detection logic
        and Supabase alert persistence without attacking external networks or polluting real packet counters.
        """
        sc = scenario.lower().strip()
        now = datetime.now(timezone.utc)
        synthetic_packets: List[IcmpPacketData] = []

        # Target IP defaults to active protected target if default 127.0.0.1 was supplied
        effective_target = target_ip
        if target_ip == "127.0.0.1" and self._protected_target_ips:
            effective_target = self._protected_target_ips[0]

        if sc in ("normal", "baseline"):
            pkt_count = count or 15
            for i in range(pkt_count):
                ts = now - timedelta(seconds=(pkt_count - i) * 0.4)
                synthetic_packets.append(IcmpPacketData(
                    timestamp=ts,
                    source_ip=attacker_ip,
                    destination_ip=effective_target,
                    protocol="ICMP",
                    icmp_type=8, # Echo Request
                    icmp_code=0,
                    packet_size=64,
                    interface="SIMULATOR",
                    source="simulator_icmp",
                ))

        elif sc in ("suspicious", "elevated"):
            pkt_count = count or max(settings.ICMP_SUSPICIOUS_THRESHOLD + 20, 120)
            for i in range(pkt_count):
                ts = now - timedelta(seconds=(pkt_count - i) * (self.window_seconds / (pkt_count + 1)))
                synthetic_packets.append(IcmpPacketData(
                    timestamp=ts,
                    source_ip=attacker_ip,
                    destination_ip=effective_target,
                    protocol="ICMP",
                    icmp_type=8,
                    icmp_code=0,
                    packet_size=64,
                    interface="SIMULATOR",
                    source="simulator_icmp",
                ))

        elif sc in ("dos", "flood", "possible_dos"):
            pkt_count = count or max(settings.ICMP_DOS_THRESHOLD + 50, 350)
            for i in range(pkt_count):
                ts = now - timedelta(seconds=(pkt_count - i) * (self.window_seconds / (pkt_count + 1)))
                synthetic_packets.append(IcmpPacketData(
                    timestamp=ts,
                    source_ip=attacker_ip,
                    destination_ip=effective_target,
                    protocol="ICMP",
                    icmp_type=8,
                    icmp_code=0,
                    packet_size=64,
                    interface="SIMULATOR",
                    source="simulator_icmp",
                ))

        elif sc in ("ddos", "distributed_flood", "possible_ddos"):
            pkt_count = count or max(settings.ICMP_DDOS_THRESHOLD + 100, 600)
            num_sources = max(settings.ICMP_UNIQUE_SOURCE_THRESHOLD + 5, 25)
            sources = [f"192.168.1.{10 + idx}" for idx in range(num_sources)]
            for i in range(pkt_count):
                src_ip = sources[i % num_sources]
                ts = now - timedelta(seconds=(pkt_count - i) * (self.window_seconds / (pkt_count + 1)))
                synthetic_packets.append(IcmpPacketData(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip=effective_target,
                    protocol="ICMP",
                    icmp_type=8,
                    icmp_code=0,
                    packet_size=64,
                    interface="SIMULATOR",
                    source="simulator_icmp",
                ))
        else:
            raise ValueError(f"Unknown scenario '{scenario}'. Choose from: normal, suspicious, dos, ddos")

        # Ingest into ISOLATED simulation buffer
        with self._lock:
            self._sim_packets.clear()
            for p in synthetic_packets:
                self._sim_packets.append(p)
            self._sim_total_observed += len(synthetic_packets)
            sim_window = list(self._sim_packets)

        # Dedicated detector for simulation ensuring accurate evaluation of effective_target
        sim_detector = IcmpDosDetector(
            window_seconds=self.window_seconds,
            suspicious_threshold=self.detector.suspicious_threshold,
            dos_threshold=self.detector.dos_threshold,
            ddos_threshold=self.detector.ddos_threshold,
            unique_source_threshold=self.detector.unique_source_threshold,
            protected_target_ips=[effective_target],
        )
        sim_result = sim_detector.analyze_window(sim_window)

        with self._lock:
            self._sim_current_result = sim_result

        # Persist alert to Supabase to verify pipeline
        if sim_result.alert_candidate:
            db = None
            try:
                db = SessionLocal()
                ev = Event(
                    timestamp=now,
                    source="simulator_icmp",
                    host="soc-demo-simulator",
                    source_ip=sim_result.primary_source_ip if sim_result.state == STATE_POSSIBLE_DOS else f"{sim_result.unique_sources} distributed IPs (SIMULATED)",
                    destination_ip=target_ip,
                    protocol="ICMP",
                    event_type="icmp_flood" if sim_result.state == STATE_POSSIBLE_DOS else "icmp_distributed_flood",
                    raw_data={
                        "simulation": True,
                        "label": "SIMULATION — NOT LIVE PACKET CAPTURE",
                        "detection_type": sim_result.detection_type,
                        "packet_count": len(synthetic_packets),
                        "pps": sim_result.packets_per_second,
                        "unique_sources": sim_result.unique_sources,
                    }
                )
                db.add(ev)
                db.commit()
                db.refresh(ev)

                al = Alert(
                    event_id=ev.id,
                    title=f"[SIMULATION] {sim_result.alert_candidate.title}",
                    description=f"[SIMULATION DEMO] {sim_result.alert_candidate.description}",
                    source_ip=sim_result.alert_candidate.source_ip,
                    destination_ip=target_ip,
                    severity=sim_result.alert_candidate.severity,
                    status="OPEN",
                    detection_rule=sim_result.alert_candidate.detection_rule,
                    timestamp=now
                )
                db.add(al)
                db.commit()
                db.refresh(al)

                try:
                    correlate_alerts([al], db)
                except Exception:
                    pass

                with self._lock:
                    self._sim_recent_events.append({
                        "id": ev.id,
                        "alert_id": al.id,
                        "timestamp": now.isoformat(),
                        "title": al.title,
                        "severity": al.severity,
                        "detection_type": sim_result.detection_type,
                        "packet_count": len(synthetic_packets),
                        "status": "OPEN",
                        "is_simulation": True
                    })
            except Exception as exc:
                logger.warning(f"Could not persist simulation alert: {exc}")
            finally:
                if db:
                    db.close()

        return {
            "status": "success",
            "is_simulation": True,
            "mode": "SIMULATION — NOT LIVE PACKET CAPTURE",
            "scenario": sc,
            "packets_generated": len(synthetic_packets),
            "target_ip": target_ip,
            "detection_state": sim_result.state,
            "detection_label": sim_result.state_label,
            "current_rate_pps": sim_result.packets_per_second,
            "unique_sources": sim_result.unique_sources,
            "message": f"Successfully executed simulation scenario '{sc}'. (LOCAL TEST ONLY)"
        }

# Global singleton
icmp_monitor_service = IcmpMonitorService()
