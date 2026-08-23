"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-28 12:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Crear el ENUM de forma idempotente con el dialecto Postgres
    scan_status_create = postgresql.ENUM(
        "pending", "running_masscan", "running_nmap",
        "completed", "failed", "cancelled",
        name="scan_status",
    )
    scan_status_create.create(op.get_bind(), checkfirst=True)

    # Para usar el ENUM en columnas, declaramos uno nuevo con create_type=False
    # para que SQLAlchemy NO intente recrearlo automáticamente al crear la tabla.
    scan_status = postgresql.ENUM(
        "pending", "running_masscan", "running_nmap",
        "completed", "failed", "cancelled",
        name="scan_status",
        create_type=False,
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("target_cidr", sa.String(255), nullable=False),
        sa.Column("ports", sa.String(512), nullable=False, server_default="1-65535"),
        sa.Column("masscan_rate", sa.Integer, nullable=False, server_default="10000"),
        sa.Column("nmap_scripts", sa.String(512), nullable=False, server_default="vuln,auth,default"),
        sa.Column("status", scan_status, nullable=False, server_default="pending"),
        sa.Column("progress", sa.Float, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text),
        sa.Column("masscan_output", sa.JSON),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("scan_id", sa.Integer, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("mac_address", sa.String(17)),
        sa.Column("vendor", sa.String(255)),
        sa.Column("os_name", sa.String(255)),
        sa.Column("os_accuracy", sa.Integer),
        sa.Column("state", sa.String(20), nullable=False, server_default="up"),
    )
    op.create_index("ix_hosts_ip", "hosts", ["ip"])
    op.create_index("ix_hosts_scan_ip", "hosts", ["scan_id", "ip"], unique=True)

    op.create_table(
        "ports",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("host_id", sa.Integer, sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(10), nullable=False, server_default="tcp"),
        sa.Column("state", sa.String(20), nullable=False, server_default="open"),
        sa.Column("service", sa.String(255)),
        sa.Column("product", sa.String(255)),
        sa.Column("version", sa.String(255)),
        sa.Column("extra_info", sa.String(512)),
        sa.Column("banner", sa.Text),
    )
    op.create_index(
        "ix_ports_host_port_proto", "ports",
        ["host_id", "port", "protocol"], unique=True,
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("host_id", sa.Integer, sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer),
        sa.Column("script_id", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("cve", sa.String(50)),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("output", sa.Text),
    )
    op.create_index("ix_vulnerabilities_cve", "vulnerabilities", ["cve"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_cve", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index("ix_ports_host_port_proto", table_name="ports")
    op.drop_index("ix_hosts_scan_ip", table_name="hosts")
    op.drop_index("ix_hosts_ip", table_name="hosts")
    op.drop_table("hosts")
    op.drop_table("scans")
    postgresql.ENUM(name="scan_status").drop(op.get_bind(), checkfirst=True)
