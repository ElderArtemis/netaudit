"""Wrapper async de masscan. Ejecuta el binario y parsea su salida JSON."""
import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import AsyncIterator


class MasscanError(RuntimeError):
    pass


class Masscan:
    """Lanza masscan y devuelve un dict {ip: [ports...]} con resultados."""

    def __init__(self, binary: str = "masscan") -> None:
        self.binary = shutil.which(binary) or binary
        if not Path(self.binary).exists() and self.binary == binary:
            raise MasscanError(f"binario masscan no encontrado en PATH")

    async def scan(
        self,
        targets: str,
        ports: str = "1-65535",
        rate: int = 10000,
        extra_args: list[str] | None = None,
    ) -> tuple[dict[str, list[int]], str]:
        """
        Ejecuta masscan contra los `targets` (CIDR o IPs separadas por coma).
        Devuelve ({ip: [puertos]}, stderr_log).
        """
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tmp:
            output_path = tmp.name

        cmd = [
            self.binary,
            "-p", ports,
            "--rate", str(rate),
            "-oJ", output_path,
            "--wait", "3",
        ]
        if extra_args:
            cmd.extend(extra_args)
        # Permite múltiples targets separados por coma
        cmd.extend(t.strip() for t in targets.split(","))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        stderr_text = stderr.decode(errors="ignore")

        if proc.returncode != 0:
            raise MasscanError(f"masscan falló (rc={proc.returncode}): {stderr_text}")

        result = self._parse_output(output_path)
        Path(output_path).unlink(missing_ok=True)
        return result, stderr_text

    @staticmethod
    def _parse_output(path: str) -> dict[str, list[int]]:
        """Masscan emite un array JSON con elementos {ip, ports:[{port,proto,...}]}."""
        result: dict[str, list[int]] = {}
        try:
            content = Path(path).read_text().strip()
        except FileNotFoundError:
            return result
        if not content or content == "[]":
            return result
        # masscan a veces deja una coma final antes del cierre
        content = content.rstrip(", \n")
        if not content.endswith("]"):
            content = content + "]"
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Fallback: parsear línea a línea (formato grepable)
            return result

        for entry in data:
            ip = entry.get("ip")
            if not ip:
                continue
            for p in entry.get("ports", []):
                port = p.get("port")
                if port is not None:
                    result.setdefault(ip, []).append(int(port))
        # Deduplicar y ordenar
        for ip in result:
            result[ip] = sorted(set(result[ip]))
        return result

    @staticmethod
    async def stream_progress(proc: asyncio.subprocess.Process) -> AsyncIterator[str]:
        """Itera líneas de stderr para reportar progreso (rate, ETA)."""
        if proc.stderr is None:
            return
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            yield line.decode(errors="ignore").strip()
