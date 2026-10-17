import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.icmp_monitor import icmp_monitor_service

logger = logging.getLogger("routers.icmp")

router = APIRouter(prefix="/api/icmp", tags=["Live ICMP Monitoring & DoS Detection"])

class StartMonitoringRequest(BaseModel):
    interface: Optional[str] = Field(default=None, description="Network interface name (e.g., Wi-Fi, Ethernet, default)")
    protected_targets: Optional[List[str]] = Field(default=None, description="Optional protected destination IPs to monitor")

class UpdateProtectedTargetsRequest(BaseModel):
    targets: Optional[List[str]] = Field(default=None, description="List of protected IPv4 addresses to monitor for ICMP flood attacks")
    protected_targets: Optional[List[str]] = Field(default=None, description="Alias for targets")

    @property
    def effective_targets(self) -> List[str]:
        if self.targets is not None:
            return self.targets
        if self.protected_targets is not None:
            return self.protected_targets
        return []

class SimulationRequest(BaseModel):
    scenario: str = Field(default="normal", description="Traffic pattern: normal, suspicious, dos, ddos")
    count: Optional[int] = Field(default=None, description="Custom packet volume override")
    target_ip: str = Field(default="127.0.0.1", description="Controlled target destination IP")
    attacker_ip: str = Field(default="192.168.1.185", description="Simulated attacker IP")

@router.get("/status", summary="Get ICMP Monitoring Status")
def get_monitor_status() -> Dict[str, Any]:
    """
    Returns current REAL ICMP monitoring status, packet rate (pps),
    unique source counts, and real-time detection state.
    """
    return icmp_monitor_service.get_status()

@router.get("/targets", summary="Get Configured Protected Target Destination IPs")
def get_protected_targets() -> Dict[str, Any]:
    """
    Returns the list of protected destination IPs monitored for ICMP floods,
    along with sensor placement visibility info.
    """
    st = icmp_monitor_service.get_status()
    targets = st["protected_target_ips"]
    return {
        "protected_targets": targets,
        "count": len(targets),
        "sensor_info": st["sensor_info"],
        "interface": st["interface"],
        "interface_ip": st["interface_ip"],
    }

@router.put("/targets", summary="Update Configured Protected Target Destination IPs")
def update_protected_targets(payload: UpdateProtectedTargetsRequest) -> Dict[str, Any]:
    """
    Dynamically configures the destination IPv4 addresses considered 'protected targets'.
    Incoming ICMP echo requests directed to these IPs are analyzed for DoS/DDoS,
    while outgoing pings (e.g. to 8.8.8.8) and unrelated destinations are excluded from alerts.
    """
    try:
        updated = icmp_monitor_service.set_protected_targets(payload.effective_targets)
        st = icmp_monitor_service.get_status()
        return {
            "status": "success",
            "message": f"Updated protected targets: {', '.join(updated) if updated else 'All Local'}",
            "protected_targets": updated,
            "sensor_info": st["sensor_info"],
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.get("/active-interface", summary="Get Automatically Detected Active Interface")
def get_active_interface() -> Dict[str, Any]:
    """
    Returns the primary active network interface (e.g. Wi-Fi with valid IP).
    """
    return icmp_monitor_service.get_active_interface()

@router.get("/driver-status", summary="Check Npcap / Packet Capture Driver Status")
def get_driver_status() -> Dict[str, Any]:
    """
    Returns whether real packet capture driver (Npcap) is available on this host.
    """
    return icmp_monitor_service.get_driver_status()

@router.post("/start", summary="Start Live ICMP Monitoring")
def start_monitor(payload: Optional[StartMonitoringRequest] = None) -> Dict[str, Any]:
    """
    Starts REAL packet capture on the selected network interface.
    If Npcap/driver is unavailable, raises a clear error.
    """
    iface = payload.interface if payload else None
    targets = payload.protected_targets if payload else None
    try:
        status_data = icmp_monitor_service.start(interface=iface, protected_targets=targets)
        return {
            "status": "success",
            "message": f"Real ICMP packet capture active on interface '{status_data['interface']}'.",
            "data": status_data
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error(f"Error starting ICMP monitor: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

@router.post("/stop", summary="Stop Live ICMP Monitoring")
def stop_monitor() -> Dict[str, Any]:
    """
    Stops the active real ICMP packet capture worker.
    """
    try:
        status_data = icmp_monitor_service.stop()
        return {
            "status": "success",
            "message": "Real ICMP monitoring stopped.",
            "data": status_data
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except Exception as exc:
        logger.error(f"Error stopping ICMP monitor: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

@router.get("/stats", summary="Get Traffic Telemetry Statistics")
def get_traffic_stats() -> Dict[str, Any]:
    """
    Returns real traffic rates, packet counters, top source/dest IPs,
    and historical points for real-time charting.
    """
    return icmp_monitor_service.get_stats()

@router.get("/events", summary="Get Recent ICMP Detection Events")
def get_recent_icmp_events(limit: int = Query(default=50, ge=1, le=200)) -> List[Dict[str, Any]]:
    """
    Returns recent ICMP security alerts and events captured during monitoring.
    """
    return icmp_monitor_service.get_recent_events(limit=limit)

@router.get("/interfaces", summary="List Available Network Interfaces")
def get_interfaces(include_advanced: bool = Query(default=False)) -> List[Dict[str, Any]]:
    """
    Returns available host network adapters.
    Suppresses low-level Windows clutter (WFP, 802.3, virtual filters) unless include_advanced=True.
    """
    return icmp_monitor_service.get_interfaces(include_advanced=include_advanced)

@router.post("/simulate", summary="Generate Controlled ICMP Demo Traffic")
def simulate_traffic(payload: SimulationRequest) -> Dict[str, Any]:
    """
    LOCAL TEST / SIMULATION ONLY:
    Injects synthetic ICMP packets into the isolated simulation buffer to demonstrate
    RULE_06 (DoS) and RULE_07 (DDoS) detection and Supabase persistence.
    Does NOT affect real packet counters.
    """
    try:
        return icmp_monitor_service.simulate_traffic(
            scenario=payload.scenario,
            count=payload.count,
            target_ip=payload.target_ip,
            attacker_ip=payload.attacker_ip
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error(f"Error generating ICMP test traffic: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

@router.post("/reset", summary="Reset Monitoring Telemetry Buffer")
def reset_monitor_stats() -> Dict[str, Any]:
    """
    Clears real packet sliding window records and historical counters.
    """
    icmp_monitor_service.reset_stats()
    return {"status": "success", "message": "ICMP telemetry buffer has been reset."}
