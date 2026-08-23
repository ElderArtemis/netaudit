from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    String, Integer, DateTime, ForeignKey, Text, Float, Enum, Index, JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database import Base


class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING_MASSCAN = "running_masscan"
    RUNNING_NMAP = "running_nmap"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    target_cidr: Mapped[str] = mapped_column(String(255))  # admite varias separadas por coma
    ports: Mapped[str] = mapped_column(String(512), default="1-65535")
    masscan_rate: Mapped[int] = mapped_column(Integer, default=10000)
    nmap_scripts: Mapped[str] = mapped_column(String(512), default="vuln,auth,default")
    status: Mapped[ScanStatus] = mapped_column(
        Enum(
            ScanStatus,
            name="scan_status",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=ScanStatus.PENDING,
    )
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    masscan_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    hosts: Mapped[list["Host"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_accuracy: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="up")

    scan: Mapped["Scan"] = relationship(back_populates="hosts")
    ports: Mapped[list["Port"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_hosts_scan_ip", "scan_id", "ip", unique=True),)


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(String(512), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)

    host: Mapped["Host"] = relationship(back_populates="ports")

    __table_args__ = (
        Index("ix_ports_host_port_proto", "host_id", "port", "protocol", unique=True),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    script_id: Mapped[str] = mapped_column(String(255))  # ej. ssl-poodle, http-vuln-cve2017-5638
    severity: Mapped[str] = mapped_column(String(20), default="info")  # critical/high/medium/low/info
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(512))
    output: Mapped[str | None] = mapped_column(Text, nullable=True)

    host: Mapped["Host"] = relationship(back_populates="vulnerabilities")