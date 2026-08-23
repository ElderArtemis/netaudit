"""Wrapper async de nmap con parseo seguro de XML (defusedxml) y extracción
de servicios, OS y vulnerabilidades NSE (vuln, auth, default).
"""
import asyncio
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from defusedxml import ElementTree as ET


# Mapeo de severidad de scripts NSE comunes
SEVERITY_MAP = {
    "VULNERABLE": "high",
    "LIKELY VULNERABLE": "high",
    "EXPLOITABLE": "critical",
    "ssl-poodle": "medium",
    "ssl-heartbleed": "critical",
    "smb-vuln-ms17-010": "critical",
    "ssl-ccs-injection": "high",
    "smb-vuln-ms08-067": "critical",
    "rdp-vuln-ms12-020": "high",
    "http-shellshock": "critical",
    "http-vuln-cve2017-5638": "critical",
    "ssl-dh-params": "medium",
    "vulners": "high",
}


@dataclass
class NmapPort:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    banner: str | None = None


@dataclass
class NmapVuln:
    script_id: str
    title: str
    severity: str = "info"
    cve: str | None = None
    output: str | None = None
    port: int | None = None


@dataclass
class NmapHost:
    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    state: str = "up"
    os_name: str | None = None
    os_accuracy: int | None = None
    ports: list[NmapPort] = field(default_factory=list)
    vulnerabilities: list[NmapVuln] = field(default_factory=list)


class NmapError(RuntimeError):
    pass


class Nmap:
    def __init__(self, binary: str = "nmap") -> None:
        self.binary = shutil.which(binary) or binary

    async def scan_targeted(
        self,
        targets: dict[str, list[int]],
        scripts: str = "vuln,auth,default",
        timing: int = 4,
    ) -> list[NmapHost]:
        """
        Recibe el resultado de masscan ({ip: [puertos]}) y lanza nmap
        únicamente sobre esas IPs+puertos con scripts NSE.
        """
        if not targets:
            return []

        # Construye lista única de puertos para optimizar (-p)
        all_ports = sorted({p for ports in targets.values() for p in ports})
        if not all_ports:
            return []

        ports_arg = ",".join(str(p) for p in all_ports)
        ip_list = list(targets.keys())

        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = [
            self.binary,
            "-sV",         # detección de servicios y versiones
            "-O",          # detección de SO
            "--osscan-guess",
            "-Pn",         # asume hosts up (masscan ya validó)
            "-n",          # sin DNS reverso (más rápido)
            f"-T{timing}",
            "-p", ports_arg,
            "--script", scripts,
            "--script-timeout", "120s",
            "--host-timeout", "15m",
            "-oX", xml_path,
            *ip_list,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode not in (0, 1):  # nmap usa 0 ó 1 según hosts encontrados
            Path(xml_path).unlink(missing_ok=True)
            raise NmapError(
                f"nmap falló (rc={proc.returncode}): {stderr.decode(errors='ignore')}"
            )

        try:
            hosts = self._parse_xml(xml_path)
        finally:
            Path(xml_path).unlink(missing_ok=True)
        return hosts

    # --------------------- parsing ---------------------

    def _parse_xml(self, path: str) -> list[NmapHost]:
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise NmapError(f"XML de nmap inválido: {e}")
        root = tree.getroot()
        results: list[NmapHost] = []

        for host_el in root.findall("host"):
            host = self._parse_host(host_el)
            if host:
                results.append(host)
        return results

    def _parse_host(self, host_el) -> NmapHost | None:
        # Estado
        status_el = host_el.find("status")
        state = status_el.get("state", "down") if status_el is not None else "down"

        # Direcciones (IPv4 + MAC)
        ip = None
        mac = None
        vendor = None
        for addr in host_el.findall("address"):
            atype = addr.get("addrtype")
            if atype in ("ipv4", "ipv6") and ip is None:
                ip = addr.get("addr")
            elif atype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        if ip is None:
            return None

        # Hostname
        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        host = NmapHost(
            ip=ip, hostname=hostname, mac_address=mac, vendor=vendor, state=state
        )

        # OS
        os_el = host_el.find("os")
        if os_el is not None:
            best = None
            best_acc = -1
            for match in os_el.findall("osmatch"):
                acc = int(match.get("accuracy", "0"))
                if acc > best_acc:
                    best_acc = acc
                    best = match.get("name")
            if best is not None:
                host.os_name = best
                host.os_accuracy = best_acc if best_acc >= 0 else None

        # Puertos
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                np = self._parse_port(port_el)
                if np:
                    host.ports.append(np)
                    # Scripts NSE asociados a un puerto concreto
                    for script_el in port_el.findall("script"):
                        vuln = self._parse_script(script_el, port=np.port)
                        if vuln:
                            host.vulnerabilities.append(vuln)

        # Hostscripts (NSE a nivel de host, no de puerto)
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                vuln = self._parse_script(script_el, port=None)
                if vuln:
                    host.vulnerabilities.append(vuln)

        return host

    def _parse_port(self, port_el) -> NmapPort | None:
        portid = port_el.get("portid")
        protocol = port_el.get("protocol", "tcp")
        if portid is None:
            return None
        state_el = port_el.find("state")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"

        np = NmapPort(port=int(portid), protocol=protocol, state=state)

        service_el = port_el.find("service")
        if service_el is not None:
            np.service = service_el.get("name")
            np.product = service_el.get("product")
            np.version = service_el.get("version")
            np.extra_info = service_el.get("extrainfo")
            cpe_parts = [
                cpe.text for cpe in service_el.findall("cpe") if cpe.text
            ]
            if cpe_parts:
                np.banner = " | ".join(cpe_parts)
        return np

    def _parse_script(self, script_el, port: int | None) -> NmapVuln | None:
        sid = script_el.get("id", "unknown")
        output = script_el.get("output", "") or ""

        # Filtra scripts puramente informativos (default) sin contenido relevante
        if not output.strip():
            return None

        # Heurística de severidad
        severity = "info"
        upper = output.upper()
        for marker in ("EXPLOITABLE",):
            if marker in upper:
                severity = "critical"
                break
        else:
            if "VULNERABLE" in upper:
                severity = "high"
            elif sid in SEVERITY_MAP:
                severity = SEVERITY_MAP[sid]

        # Extracción de CVE
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", output)
        cve = cve_match.group(0) if cve_match else None

        # Título corto: primera línea del output
        first_line = next((ln.strip() for ln in output.splitlines() if ln.strip()), sid)
        title = (first_line[:500]) if first_line else sid

        return NmapVuln(
            script_id=sid,
            title=title,
            severity=severity,
            cve=cve,
            output=output,
            port=port,
        )
