import logging
from datetime import datetime, timezone
from sqlalchemy import select
from app.database.connection import engine, SessionLocal
from app.models import (
    Base,
    User,
    Event,
    Alert,
    Incident,
    IncidentAlert,
    MitreTechnique
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc_copilot.init_db")

DEFAULT_MITRE_TECHNIQUES = [
    {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt credential access through trial and error guessing of passwords or tokens."
    },
    {
        "technique_id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts by probing ports across network segments."
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters such as PowerShell, Bash, or cmd.exe to execute arbitrary code."
    },
    {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend in with legitimate network traffic."
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program to gain initial entry."
    },
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of maintaining access and circumventing access controls."
    }
]

def init_tables():
    """
    Non-destructively creates database tables according to SQLAlchemy metadata.
    Existing tables and data are preserved.
    """
    logger.info("Verifying/creating database tables in PostgreSQL...")
    Base.metadata.create_all(bind=engine)
    logger.info("Tables created or already exist.")

def seed_baseline_data():
    """
    Seeds initial reference data idempotently. Safe to run multiple times.
    """
    db = SessionLocal()
    try:
        # 1. Seed MITRE ATT&CK Techniques
        logger.info("Seeding MITRE ATT&CK reference data...")
        for tech_data in DEFAULT_MITRE_TECHNIQUES:
            existing = db.scalar(
                select(MitreTechnique).where(MitreTechnique.technique_id == tech_data["technique_id"])
            )
            if not existing:
                tech = MitreTechnique(**tech_data)
                db.add(tech)
                logger.info(f"Added MITRE technique: {tech_data['technique_id']} - {tech_data['name']}")
        db.commit()

        # 2. Seed Default Analyst User
        default_username = "analyst_soc"
        existing_user = db.scalar(select(User).where(User.username == default_username))
        if not existing_user:
            analyst = User(
                username=default_username,
                email="analyst@soc-copilot.internal",
                password_hash="$2b$12$e8YqAOmrIevvTzK9o6NqP.uU85qVp7c4gDlh4j1z9bW0Gv8xK4eCe", # Placeholder demo hash
                role="analyst"
            )
            db.add(analyst)
            logger.info(f"Created default demo user: {default_username}")
            db.commit()

        # 3. Seed Initial Demonstration Event, Alert, and Incident
        existing_event = db.scalar(select(Event).where(Event.event_type == "failed_login"))
        if not existing_event:
            logger.info("Seeding initial baseline security event and alert...")
            sample_event = Event(
                source="auth_log",
                host="srv-prod-web01",
                source_ip="198.51.100.45",
                destination_ip="10.0.1.15",
                source_port=54812,
                destination_port=22,
                protocol="TCP",
                event_type="failed_login",
                raw_data={"service": "sshd", "user": "root", "failure_count": 14}
            )
            db.add(sample_event)
            db.flush()

            sample_alert = Alert(
                event_id=sample_event.id,
                title="Possible SSH Brute Force",
                description="Excessive failed SSH authentication attempts detected from 198.51.100.45 targeting root account.",
                source_ip="198.51.100.45",
                destination_ip="10.0.1.15",
                severity="HIGH",
                status="OPEN",
                detection_rule="RULE_01_SSH_BRUTE_FORCE"
            )
            db.add(sample_alert)
            db.flush()

            sample_incident = Incident(
                title="Suspicious Remote Ingress & Authentication Anomaly",
                description="Repeated SSH credential attack from external untrusted IP address.",
                severity="HIGH",
                status="OPEN",
                summary="Observed high-frequency credential stuffing targeting edge server. Further observation advised.",
                confidence=0.88
            )
            db.add(sample_incident)
            db.flush()

            assoc = IncidentAlert(incident_id=sample_incident.id, alert_id=sample_alert.id)
            db.add(assoc)
            db.commit()
            logger.info("Initial demo security telemetry seeded successfully.")

    except Exception as exc:
        db.rollback()
        logger.error(f"Error seeding database: {exc}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    init_tables()
    seed_baseline_data()
