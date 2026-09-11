"""Tool Service - Command output formatting and display"""

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table


class ToolService:
    """
    Formats and displays command output from various pentesting tools.

    Extracted from T100AIEngine to isolate presentation concerns:
    - nmap, gobuster, nikto, sqlmap, hydra output formatters
    - Generic output display
    - Finding parsing from command results
    """

    def __init__(self, console: Console):
        self._console = console

    def display_command_output(self, cmd: str, output: str, error: str, returncode: int) -> None:
        """Dispatches to the appropriate formatter based on command type."""
        cmd_lower = cmd.lower()
        if "nmap" in cmd_lower:
            self.display_nmap_output(output, error, returncode)
        elif "dirb" in cmd_lower or "gobuster" in cmd_lower:
            self.display_dir_fuzz_output(output, error, returncode)
        elif "nikto" in cmd_lower:
            self.display_nikto_output(output, error, returncode)
        elif "whatweb" in cmd_lower or "wappalyzer" in cmd_lower:
            self.display_tech_output(output, error, returncode)
        elif "sqlmap" in cmd_lower:
            self.display_sqlmap_output(output, error, returncode)
        elif "hydra" in cmd_lower:
            self.display_hydra_output(output, error, returncode)
        else:
            self.display_generic_output(output, error, returncode)

    def display_nmap_output(self, output: str, error: str, returncode: int) -> None:
        if "PORT" in output and "STATE" in output:
            table = Table(title="Resultados del Escaneo", border_style="#00D4FF")
            table.add_column("Puerto", style="#00FF88")
            table.add_column("Estado", style="#00D4FF")
            table.add_column("Servicio", style="#FFD60A")
            table.add_column("Version", style="#8B949E")
            for line in output.split("\n"):
                line = line.strip()
                if "/" in line and any(s in line.upper() for s in ["OPEN", "CLOSED", "FILTERED"]):
                    parts = [p for p in line.split() if p]
                    if len(parts) >= 3:
                        state_color = "#00FF88" if "open" in parts[1].lower() else "#FF3366"
                        table.add_row(parts[0], f"[{state_color}]{parts[1]}[/]", parts[2], " ".join(parts[3:]))
            if table.row_count > 0:
                self._console.print(table)
                self._console.print(f"[dim]Puertos abiertos encontrados: {table.row_count}[/]")
            else:
                self.display_generic_output(output, error, returncode)
        else:
            self.display_generic_output(output, error, returncode)

    def display_dir_fuzz_output(self, output: str, error: str, returncode: int) -> None:
        table = Table(title="Directorios/Archivos Encontrados", border_style="#00D4FF")
        table.add_column("URL", style="#00FF88")
        table.add_column("Codigo", style="#FFD60A")
        table.add_column("Tamano", style="#8B949E")
        found_count = 0
        for line in output.split("\n"):
            if "+ http" in line or "200" in line or "301" in line or "403" in line:
                parts = line.split()
                for p in parts:
                    if p.startswith("http"):
                        url = p.rstrip("/")
                        code = next((x for x in parts if x.isdigit() and len(x) == 3), "-")
                        size = next((x for x in parts if x.isdigit() and len(x) > 3), "-")
                        table.add_row(url, code, size)
                        found_count += 1
                        break
        if found_count > 0:
            self._console.print(table)
            self._console.print(f"[dim]Recursos encontrados: {found_count}[/]")
        else:
            self.display_generic_output(output, error, returncode)

    def display_nikto_output(self, output: str, error: str, returncode: int) -> None:
        table = Table(title="Vulnerabilidades Web (Nikto)", border_style="#FF6B35")
        table.add_column("Severidad", style="#FFD60A")
        table.add_column("Descripcion", style="#E8E8E8")
        table.add_column("URL", style="#00D4FF")
        vuln_count = 0
        for line in output.split("\n"):
            if "+ " in line and any(x in line for x in ["OSVDB", "CVE", "WARNING", "INFO"]):
                parts = line[2:].split(" - ", 1)
                if len(parts) >= 2:
                    table.add_row(parts[0].strip()[:10], parts[1].strip()[:80], "")
                    vuln_count += 1
        if vuln_count > 0:
            self._console.print(table)
            self._console.print(f"[yellow]Vulnerabilidades potenciales: {vuln_count}[/]")
        else:
            self.display_generic_output(output, error, returncode)

    def display_tech_output(self, output: str, error: str, returncode: int) -> None:
        table = Table(title="Tecnologias Detectadas", border_style="#00D4FF")
        table.add_column("Tecnologia", style="#00FF88")
        table.add_column("Version/Info", style="#8B949E")
        table.add_column("Tipo", style="#FFD60A")
        tech_count = 0
        for line in output.split("\n"):
            line = line.strip()
            if line and not line.startswith("-") and "[" not in line[:5]:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    table.add_row(parts[0].strip(), parts[1].strip()[:40], "Web")
                    tech_count += 1
        if tech_count > 0:
            self._console.print(table)
            self._console.print(f"[dim]Tecnologias identificadas: {tech_count}[/]")
        else:
            self.display_generic_output(output, error, returncode)

    def display_sqlmap_output(self, output: str, error: str, returncode: int) -> None:
        if any(x in output.lower() for x in ["vulnerable", "injection", "parameter"]):
            self._console.print(Panel.fit(
                "[bold #FF3366]POSIBLE INYECCION SQL DETECTADA[/]\n\n"
                f"[#E8E8E8]{output[:500]}...",
                border_style="#FF3366",
                title="SQLMap Alert"
            ))
        else:
            self.display_generic_output(output, error, returncode)

    def display_hydra_output(self, output: str, error: str, returncode: int) -> None:
        if "login:" in output and "password:" in output:
            self._console.print(Panel.fit(
                "[bold #FF3366]CREDENCIALES ENCONTRADAS[/]\n\n"
                f"[#00FF88]{output}[/]",
                border_style="#FF3366",
                title="Hydra Alert"
            ))
        else:
            self.display_generic_output(output, error, returncode)

    def display_generic_output(self, output: str, error: str, returncode: int) -> None:
        if output:
            syntax = Syntax(output[:3000], "text", theme="monokai", line_numbers=True)
            self._console.print(Panel(syntax, title="Output", border_style="#00D4FF"))
        if error:
            self._console.print(Panel(f"[#FF3366]{error[:500]}[/]", title="Error", border_style="#FF3366"))
        self._console.print(f"[dim]Exit code: {returncode}[/]")

    def parse_command_results(self, cmd: str, output: str, error: str, returncode: int) -> list[dict]:
        """Parse command results and return potential findings data."""
        findings = []
        cmd_lower = cmd.lower()
        if "nmap" in cmd_lower and "open" in output.lower():
            for line in output.split("\n"):
                line = line.strip()
                if "open" in line.lower() and "/" in line:
                    if any(x in line.lower() for x in ["ftp", "telnet", "rsh", "rexec"]):
                        findings.append({
                            "type": "info",
                            "severity": "MED",
                            "title": f"Servicio inseguro: {line.split()[2] if len(line.split()) > 2 else 'desconocido'}",
                            "detail": line
                        })
                    elif any(x in line.lower() for x in ["mysql", "postgresql", "mongodb", "redis"]):
                        findings.append({
                            "type": "info",
                            "severity": "MED",
                            "title": f"Base de datos expuesta: {line.split()[2] if len(line.split()) > 2 else 'desconocido'}",
                            "detail": line
                        })
        return findings

    def display_findings_summary(self, findings: list[dict]) -> None:
        if not findings:
            return
        self._console.print()
        self._console.print(Panel.fit(
            "[bold #FFD60A]Posibles Hallazgos Detectados[/]\n\n" +
            "\n".join(f"[{f['severity']}] {f['title']}" for f in findings),
            border_style="#FFD60A"
        ))
