import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    ENVIRONMENT: str = Field(default="development")
    DEBUG: bool = Field(default=True)
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    
    # PostgreSQL only - local Docker or Supabase
    DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/soc_copilot"
    )
    
    # Comma-separated or list of allowed CORS origins
    CORS_ORIGINS: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
    )

    # Phase 5 - Live ICMP Monitoring & DoS/DDoS Detection
    ICMP_MONITOR_ENABLED: bool = Field(default=True)
    ICMP_INTERFACE: Optional[str] = Field(default=None)
    ICMP_WINDOW_SECONDS: int = Field(default=10)
    ICMP_SUSPICIOUS_THRESHOLD: int = Field(default=100)
    ICMP_DOS_THRESHOLD: int = Field(default=300)
    ICMP_DDOS_THRESHOLD: int = Field(default=500)
    ICMP_UNIQUE_SOURCE_THRESHOLD: int = Field(default=10)
    PROTECTED_TARGET_IPS: str = Field(
        default="",
        description="Comma-separated list of protected target IPv4 addresses to monitor for ICMP flood attacks (e.g. '10.171.83.105,198.51.100.10'). If empty, defaults to the active host interface IP and loopback."
    )

    @property
    def protected_target_ips_list(self) -> List[str]:
        if not self.PROTECTED_TARGET_IPS:
            return []
        return [ip.strip() for ip in self.PROTECTED_TARGET_IPS.split(",") if ip.strip()]
    
    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def sqlalchemy_database_url(self) -> str:
        """
        Normalize database URL for SQLAlchemy with psycopg 3 driver.
        Ensures postgresql:// is mapped to postgresql+psycopg:// if not already prefixed.
        """
        url = self.DATABASE_URL
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg://", 1)
        elif url.startswith("postgresql://") and not url.startswith("postgresql+"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        return url

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
