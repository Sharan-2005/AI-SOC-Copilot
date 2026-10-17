from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.database.connection import get_db
from app.models.mitre import MitreTechnique
from app.schemas.mitre import MitreTechniqueResponse

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK & Detection Rules"])

DETECTION_RULES = [
    {
        "rule_id": "RULE_01",
        "name": "SSH Brute Force Attack",
        "category": "Credential Access",
        "severity": "HIGH",
        "source": "SSH / Auth Log",
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "description": "Triggered when repeated failed authentications (> 10) occur within time window."
    },
    {
        "rule_id": "RULE_02",
        "name": "Network Service Scanning",
        "category": "Discovery",
        "severity": "HIGH",
        "source": "Firewall / Connection Log",
        "mitre_id": "T1046",
        "mitre_name": "Network Service Scanning",
        "description": "Triggered when a single source IP probes multiple distinct destination ports (>= 8)."
    },
    {
        "rule_id": "RULE_03",
        "name": "Suspicious Command Execution",
        "category": "Execution",
        "severity": "HIGH",
        "source": "Audit / Process Telemetry",
        "mitre_id": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "description": "Detects suspicious command invocations (powershell, cmd.exe, whoami, net user, curl | sh)."
    },
    {
        "rule_id": "RULE_04",
        "name": "Web Exploit / SQLi / Traversal",
        "category": "Initial Access",
        "severity": "HIGH",
        "source": "Web Server / HTTP Access Log",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Detects SQL injection signatures (UNION SELECT, OR 1=1) and directory traversal patterns."
    },
    {
        "rule_id": "RULE_05",
        "name": "Privilege Escalation Indicator",
        "category": "Privilege Escalation",
        "severity": "HIGH",
        "source": "System / Sudo Log",
        "mitre_id": "T1548",
        "mitre_name": "Abuse Elevation Control Mechanism",
        "description": "Detects unauthorized sudo operations, root shell spawning, and modification of /etc/sudoers."
    },
    {
        "rule_id": "RULE_06",
        "name": "ICMP Flood / Possible DoS",
        "category": "Network Availability",
        "severity": "HIGH",
        "source": "Live ICMP Monitor",
        "mitre_id": "N/A — Network Availability Detection",
        "mitre_name": "ICMP Flood",
        "description": "Triggered when abnormal ICMP packet volume exceeds configured threshold from concentrated source(s)."
    },
    {
        "rule_id": "RULE_07",
        "name": "ICMP Distributed Flood / Possible DDoS",
        "category": "Network Availability",
        "severity": "CRITICAL",
        "source": "Live ICMP Monitor",
        "mitre_id": "N/A — Network Availability Detection",
        "mitre_name": "ICMP Distributed Flood",
        "description": "Triggered when abnormal ICMP packet volume exceeds threshold distributed across multiple distinct source IPs."
    }
]

@router.get("/rules", summary="List All Active SOC Detection Rules (RULE_01 to RULE_07)")
def list_detection_rules() -> List[Dict[str, Any]]:
    """
    Returns the complete registry of SOC detection rules including Phase 5 ICMP network availability rules.
    """
    return DETECTION_RULES

@router.get("/techniques", response_model=List[MitreTechniqueResponse])
def list_mitre_techniques(db: Session = Depends(get_db)):
    """
    List all supported MITRE ATT&CK techniques.
    """
    techniques = db.scalars(select(MitreTechnique).order_by(MitreTechnique.technique_id)).all()
    return techniques

@router.get("/techniques/{technique_id}", response_model=MitreTechniqueResponse)
def get_mitre_technique(technique_id: str, db: Session = Depends(get_db)):
    """
    Retrieve technique details by ID (e.g., T1110, T1046).
    """
    technique = db.scalar(
        select(MitreTechnique).where(MitreTechnique.technique_id == technique_id.upper())
    )
    if not technique:
        raise HTTPException(
            status_code=404,
            detail=f"MITRE ATT&CK technique '{technique_id}' not found"
        )
    return technique
