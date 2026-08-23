"""Exporta un escaneo completo a PDF profesional usando ReportLab."""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import TYPE_CHECKING

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

if TYPE_CHECKING:
    from app.models import Scan


# Paleta consistente con la estética dark terminal pero adaptada a impresión
ACCENT = colors.HexColor("#1f7a5e")
ACCENT_SOFT = colors.HexColor("#e8f3ef")
TEXT = colors.HexColor("#1a1a1a")
TEXT_DIM = colors.HexColor("#6b6b6b")
BORDER = colors.HexColor("#d0d4d2")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#c62828"),
    "high": colors.HexColor("#e65100"),
    "medium": colors.HexColor("#f9a825"),
    "low": colors.HexColor("#1565c0"),
    "info": colors.HexColor("#757575"),
}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"],
            fontName="Helvetica-Bold", fontSize=22, leading=26,
            textColor=ACCENT, alignment=TA_LEFT, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"],
            fontName="Helvetica", fontSize=10, leading=13,
            textColor=TEXT_DIM, spaceAfter=18,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"],
            fontName="Helvetica-Bold", fontSize=14, leading=18,
            textColor=ACCENT, spaceBefore=14, spaceAfter=8,
        ),
        "h3": ParagraphStyle(
            "h3", parent=base["Heading3"],
            fontName="Helvetica-Bold", fontSize=11, leading=14,
            textColor=TEXT, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontName="Helvetica", fontSize=9, leading=12, textColor=TEXT,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Code"],
            fontName="Courier", fontSize=8, leading=10, textColor=TEXT,
        ),
        "small": ParagraphStyle(
            "small", parent=base["Normal"],
            fontName="Helvetica", fontSize=8, leading=10, textColor=TEXT_DIM,
        ),
        "footer": ParagraphStyle(
            "footer", parent=base["Normal"],
            fontName="Helvetica", fontSize=8, leading=10,
            textColor=TEXT_DIM, alignment=TA_CENTER,
        ),
    }


def _header_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(TEXT_DIM)
    # Pie de página
    canvas.drawCentredString(
        A4[0] / 2, 1.2 * cm,
        f"NetAudit · Confidencial · página {doc.page}",
    )
    # Cabecera fina
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(2 * cm, A4[1] - 1.5 * cm, A4[0] - 2 * cm, A4[1] - 1.5 * cm)
    canvas.drawString(2 * cm, A4[1] - 1.2 * cm, "NetAudit")
    canvas.drawRightString(
        A4[0] - 2 * cm, A4[1] - 1.2 * cm,
        datetime.now().strftime("%Y-%m-%d %H:%M"),
    )
    canvas.restoreState()


def _truncate(text: str | None, length: int = 80) -> str:
    if not text:
        return "-"
    text = " ".join(text.split())
    return text if len(text) <= length else text[: length - 1] + "…"


def render_scan_pdf(scan: "Scan") -> bytes:
    """Genera un PDF con el detalle completo del escaneo y devuelve sus bytes."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"NetAudit · {scan.name}",
        author="NetAudit",
    )
    s = _styles()
    story: list = []

    # ---- Portada / cabecera ----
    story.append(Paragraph(f"Auditoría de red · {scan.name}", s["title"]))
    finished = (
        scan.finished_at.strftime("%Y-%m-%d %H:%M:%S")
        if scan.finished_at else "en curso"
    )
    started = (
        scan.started_at.strftime("%Y-%m-%d %H:%M:%S")
        if scan.started_at else "-"
    )
    story.append(Paragraph(
        f"Scan #{scan.id} · creado {scan.created_at.strftime('%Y-%m-%d %H:%M')} · "
        f"finalizado {finished}",
        s["subtitle"],
    ))

    # ---- Parámetros ----
    story.append(Paragraph("Parámetros del escaneo", s["h2"]))
    params_data = [
        ["Campo", "Valor"],
        ["Rango objetivo", scan.target_cidr],
        ["Puertos", scan.ports],
        ["Tasa Masscan", f"{scan.masscan_rate} pps"],
        ["Scripts NSE", scan.nmap_scripts],
        ["Estado final", scan.status.value if hasattr(scan.status, "value") else str(scan.status)],
        ["Inicio", started],
        ["Fin", finished],
    ]
    params_table = Table(params_data, colWidths=[5 * cm, 12 * cm])
    params_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ACCENT_SOFT]),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(params_table)

    # ---- Resumen ejecutivo ----
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_ports = 0
    for h in scan.hosts:
        total_ports += len(h.ports)
        for v in h.vulnerabilities:
            summary[v.severity] = summary.get(v.severity, 0) + 1
    total_vulns = sum(summary.values())

    story.append(Paragraph("Resumen ejecutivo", s["h2"]))
    summary_data = [
        ["Hosts", "Puertos", "Crítica", "Alta", "Media", "Baja", "Info"],
        [
            str(len(scan.hosts)),
            str(total_ports),
            str(summary["critical"]),
            str(summary["high"]),
            str(summary["medium"]),
            str(summary["low"]),
            str(summary["info"]),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[2.4 * cm] * 7)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
        # Colorear los números de severidad
        ("TEXTCOLOR", (2, 1), (2, 1), SEVERITY_COLORS["critical"]),
        ("TEXTCOLOR", (3, 1), (3, 1), SEVERITY_COLORS["high"]),
        ("TEXTCOLOR", (4, 1), (4, 1), SEVERITY_COLORS["medium"]),
        ("TEXTCOLOR", (5, 1), (5, 1), SEVERITY_COLORS["low"]),
        ("TEXTCOLOR", (6, 1), (6, 1), SEVERITY_COLORS["info"]),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(
        f"Se han descubierto {len(scan.hosts)} hosts con {total_ports} puertos abiertos "
        f"y se han identificado {total_vulns} hallazgos de seguridad en total.",
        s["body"],
    ))

    # ---- Hallazgos críticos primero (sección destacada) ----
    critical_findings = [
        (h, v)
        for h in scan.hosts
        for v in h.vulnerabilities
        if v.severity in ("critical", "high")
    ]
    if critical_findings:
        story.append(PageBreak())
        story.append(Paragraph("Hallazgos prioritarios (crítico / alto)", s["h2"]))

        rows = [["Sev.", "Host", "Puerto", "CVE", "Script", "Detalle"]]
        for host, vuln in critical_findings:
            rows.append([
                vuln.severity.upper(),
                host.ip,
                str(vuln.port) if vuln.port else "-",
                vuln.cve or "-",
                vuln.script_id,
                Paragraph(_truncate(vuln.title, 90), s["body"]),
            ])
        critical_table = Table(
            rows,
            colWidths=[1.6 * cm, 2.8 * cm, 1.4 * cm, 2.4 * cm, 3.2 * cm, 5.6 * cm],
            repeatRows=1,
        )
        ts = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
        for i, (_host, vuln) in enumerate(critical_findings, start=1):
            ts.add("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[vuln.severity])
            ts.add("FONTNAME", (0, i), (0, i), "Helvetica-Bold")
        critical_table.setStyle(ts)
        story.append(critical_table)

    # ---- Detalle por host ----
    story.append(PageBreak())
    story.append(Paragraph("Detalle por host", s["h2"]))

    for host in sorted(scan.hosts, key=lambda h: tuple(int(x) for x in h.ip.split(".") if x.isdigit()) or (0,)):
        story.append(Paragraph(
            f"{host.ip}"
            + (f" · {host.hostname}" if host.hostname else "")
            + (f" · {host.os_name} ({host.os_accuracy}%)" if host.os_name else ""),
            s["h3"],
        ))
        meta_bits = []
        if host.vendor:
            meta_bits.append(f"vendor: {host.vendor}")
        if host.mac_address:
            meta_bits.append(f"MAC: {host.mac_address}")
        meta_bits.append(f"{len(host.ports)} puertos · {len(host.vulnerabilities)} hallazgos")
        story.append(Paragraph(" · ".join(meta_bits), s["small"]))

        if host.ports:
            ports_rows = [["Puerto", "Proto", "Servicio", "Producto", "Versión"]]
            for p in sorted(host.ports, key=lambda x: x.port):
                ports_rows.append([
                    str(p.port), p.protocol,
                    p.service or "-", p.product or "-",
                    _truncate(p.version, 30),
                ])
            ports_table = Table(
                ports_rows,
                colWidths=[1.8 * cm, 1.6 * cm, 3.2 * cm, 5.0 * cm, 5.4 * cm],
                repeatRows=1,
            )
            ports_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_SOFT),
                ("TEXTCOLOR", (0, 0), (-1, 0), TEXT),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(Spacer(1, 0.15 * cm))
            story.append(ports_table)

        if host.vulnerabilities:
            vuln_rows = [["Sev.", "Puerto", "CVE", "Script", "Título"]]
            ordered_sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for v in sorted(host.vulnerabilities, key=lambda x: ordered_sev.get(x.severity, 9)):
                vuln_rows.append([
                    v.severity.upper(),
                    str(v.port) if v.port else "-",
                    v.cve or "-",
                    _truncate(v.script_id, 26),
                    Paragraph(_truncate(v.title, 80), s["body"]),
                ])
            vuln_table = Table(
                vuln_rows,
                colWidths=[1.6 * cm, 1.4 * cm, 2.4 * cm, 3.6 * cm, 8.0 * cm],
                repeatRows=1,
            )
            vts = TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_SOFT),
                ("TEXTCOLOR", (0, 0), (-1, 0), TEXT),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
            for i, v in enumerate(
                sorted(host.vulnerabilities, key=lambda x: ordered_sev.get(x.severity, 9)),
                start=1,
            ):
                vts.add("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[v.severity])
                vts.add("FONTNAME", (0, i), (0, i), "Helvetica-Bold")
            vuln_table.setStyle(vts)
            story.append(Spacer(1, 0.15 * cm))
            story.append(vuln_table)

        story.append(Spacer(1, 0.3 * cm))

    # ---- Aviso legal ----
    story.append(PageBreak())
    story.append(Paragraph("Aviso legal y alcance", s["h2"]))
    story.append(Paragraph(
        "Este informe se ha generado mediante un escaneo activo autorizado contra el rango "
        "indicado. Los hallazgos se basan en respuestas observadas en el momento del escaneo "
        "y pueden contener falsos positivos derivados de scripts NSE; cada hallazgo crítico "
        "debería validarse manualmente antes de iniciar acciones correctivas.",
        s["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "El uso de NetAudit fuera de redes propias o sin autorización por escrito puede "
        "constituir un delito tipificado en el artículo 197 bis del Código Penal español.",
        s["body"],
    ))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
