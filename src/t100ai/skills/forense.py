"""Forense Skill - Forensic Analysis Techniques"""
import platform
import shutil
import subprocess
import time

import structlog

from t100ai.skills.base import BaseSkill, RiskLevel, SkillResult

logger = structlog.get_logger()

class ForenseSkill(BaseSkill):
    name = "forense"
    description = "Forensic analysis techniques"
    category = "forense"
    risk_level = RiskLevel.PASSIVE

    def __init__(self):
        super().__init__()
        self.tools = ["forense.memory_acquire","forense.memory_analyze","forense.disk_acquire","forense.log_analysis","forense.ioc_extract","forense.yara_scan","forense.timeline_create"]
        self.workflows = ["incident_response","memory_forensics"]

    def get_available_actions(self):
        return ["memory_acquire","memory_analyze","disk_acquire","log_analysis","ioc_extract","yara_scan","timeline_create"]

    async def validate_params(self, action, params):
        if action in ("memory_analyze","yara_scan"):
            return "path" in params or "target" in params
        if action == "disk_acquire":
            return "device" in params or "target" in params
        return True

    async def execute(self, action, params):
        start = time.time()
        m = {"memory_acquire":self._mem_acquire,"memory_analyze":self._mem_analyze,"disk_acquire":self._disk_acquire,"log_analysis":self._log_analysis,"ioc_extract":self._ioc_extract,"yara_scan":self._yara_scan,"timeline_create":self._timeline}
        fn = m.get(action)
        return await fn(params, start) if fn else SkillResult(success=False, error=f"Accion desconocida: {action}")

    async def _mem_acquire(self, p, s):
        findings, out_parts = [], []
        if platform.system() == "Linux":
            for name, cmd in [("avml",["avml","/tmp/memory.dump"]),("LiME",["insmod","/tmp/lime.ko","path=/tmp/memory.dump","format=raw"])]:
                if shutil.which(name):
                    try:
                        r = subprocess.run(cmd,capture_output=True,text=True,timeout=600)
                        out_parts.append(r.stdout+r.stderr)
                        if r.returncode == 0:
                            findings.append({"type":"memory_acquired","tool":name})
                    except Exception as e:
                        out_parts.append(f"{name} error: {e}")
        else:
            if shutil.which("DumpIt.exe"):
                try:
                    r = subprocess.run(["DumpIt.exe","/quiet","/f","/o","C:\\temp\\memory.dmp"],capture_output=True,text=True,timeout=600)
                    out_parts.append(r.stdout+r.stderr)
                    if r.returncode == 0:
                        findings.append({"type":"memory_acquired","tool":"DumpIt"})
                except Exception:
                    pass
        if not findings:
            findings.append({"type":"memory_acquire","value":"No memory acquisition tools available"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _mem_analyze(self, p, s):
        path = p.get("path",p.get("target",""))
        if not path:
            return SkillResult(success=False,error="Memory dump path required",execution_time=time.time()-s)
        if not shutil.which("volatility") and not shutil.which("vol"):
            return SkillResult(success=False,error="Volatility not installed",execution_time=time.time()-s)
        tool = "vol" if shutil.which("vol") else "volatility"
        findings, out_parts = [], []
        for plugin in ["windows.pslist.PsList","windows.netscan.NetScan","windows.registry.hivelist.HiveList","windows.filescan.FileScan"]:
            cmd = [tool,"-f",path,plugin]
            try:
                r = subprocess.run(cmd,capture_output=True,text=True,timeout=300)
                out_parts.append(f"=== {plugin} ===\n{r.stdout}")
                if r.returncode == 0:
                    for line in r.stdout.split("\n")[:20]:
                        if line.strip():
                            findings.append({"type":"volatility_result","plugin":plugin,"detail":line.strip()[:200]})
            except Exception as e:
                out_parts.append(f"{plugin} error: {e}")
        if not findings:
            findings.append({"type":"memory_analysis","value":"No results from volatility"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _disk_acquire(self, p, s):
        device = p.get("device",p.get("target",""))
        if not device:
            return SkillResult(success=False,error="Device or target required",execution_time=time.time()-s)
        output = p.get("output","/tmp/disk_image.dd")
        findings, out_parts = [], []
        for name, cmd in [("dc3dd",["dc3dd","if="+device,"of="+output,"hash=sha256"]),("dd",["dd",f"if={device}",f"of={output}","bs=4M","status=progress"])]:
            if shutil.which(name):
                try:
                    r = subprocess.run(cmd,capture_output=True,text=True,timeout=3600)
                    out_parts.append(r.stdout+r.stderr)
                    if r.returncode == 0:
                        findings.append({"type":"disk_acquired","tool":name,"output":output})
                except Exception as e:
                    out_parts.append(f"{name} error: {e}")
        if not findings:
            findings.append({"type":"disk_acquire","value":"No disk imaging tools available"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _log_analysis(self, p, s):
        findings, out_parts = [], []
        if platform.system() == "Windows":
            for log_name in ["Security","System","Application"]:
                cmd = ["powershell","-Command",f"Get-WinEvent -LogName {log_name} -MaxEvents 50 -ErrorAction SilentlyContinue | Format-Table TimeCreated,Id,Message -AutoSize"]
                try:
                    r = subprocess.run(cmd,capture_output=True,text=True,timeout=60)
                    out_parts.append(f"=== {log_name} ===\n{r.stdout}")
                    for line in r.stdout.split("\n"):
                        if any(k in line.lower() for k in ["failed","error","denied","unauthorized","malicious"]):
                            findings.append({"type":"suspicious_log","log":log_name,"detail":line.strip()[:200]})
                except Exception:
                    pass
        else:
            for log_file in ["/var/log/auth.log","/var/log/syslog","/var/log/secure","/var/log/kern.log"]:
                if subprocess.run(["test","-f",log_file]).returncode == 0:
                    try:
                        r = subprocess.run(["tail","-100",log_file],capture_output=True,text=True,timeout=30)
                        out_parts.append(f"=== {log_file} ===\n{r.stdout}")
                        for line in r.stdout.split("\n"):
                            if any(k in line.lower() for k in ["failed","error","denied","unauthorized","segfault","overflow"]):
                                findings.append({"type":"suspicious_log","log":log_file,"detail":line.strip()[:200]})
                    except Exception:
                        pass
        if not findings:
            findings.append({"type":"log_analysis","value":"No suspicious log entries found"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _ioc_extract(self, p, s):
        path = p.get("path",p.get("target",""))
        if not path:
            return SkillResult(success=False,error="File or directory path required",execution_time=time.time()-s)
        findings, out_parts = [], []
        if shutil.which("strings"):
            try:
                r = subprocess.run(["strings",path],capture_output=True,text=True,timeout=60)
                text = r.stdout
                import re
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",text)
                domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info)\b",text)
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",text)
                urls = re.findall(r"https?://[^\s\"'<>()]+",text)
                if ips:
                    findings.append({"type":"ioc_ip","count":len(set(ips)),"samples":list(set(ips))[:10]})
                if domains:
                    findings.append({"type":"ioc_domain","count":len(set(domains)),"samples":list(set(domains))[:10]})
                if emails:
                    findings.append({"type":"ioc_email","count":len(set(emails)),"samples":list(set(emails))[:10]})
                if urls:
                    findings.append({"type":"ioc_url","count":len(set(urls)),"samples":list(set(urls))[:10]})
                out_parts.append(f"Strings analysis: {len(ips)} IPs, {len(domains)} domains, {len(emails)} emails, {len(urls)} URLs")
            except Exception as e:
                out_parts.append(f"strings error: {e}")
        if not findings:
            findings.append({"type":"ioc_extract","value":"No IOCs found"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)

    async def _yara_scan(self, p, s):
        path = p.get("path",p.get("target",""))
        rules = p.get("rules","")
        if not path:
            return SkillResult(success=False,error="Path required",execution_time=time.time()-s)
        if not shutil.which("yara"):
            return SkillResult(success=False,error="yara not installed",execution_time=time.time()-s)
        cmd = ["yara","-r",rules,path] if rules else ["yara","-r","/usr/share/yara/rules/",path]
        try:
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=300)
            findings = [{"type":"yara_match","rule":line.split()[0],"file":" ".join(line.split()[1:])} for line in r.stdout.split("\n") if line.strip()]
            return SkillResult(success=r.returncode==0,output=r.stdout+r.stderr,findings=findings or [{"type":"yara","value":"No matches"}],execution_time=time.time()-s)
        except Exception as e:
            return SkillResult(success=False,error=str(e),execution_time=time.time()-s)

    async def _timeline(self, p, s):
        path = p.get("path",p.get("target","."))
        findings, out_parts = [], []
        try:
            cmd = ["find",path,"-type","f","-printf","%T+ %p\n"] if platform.system() != "Windows" else ["powershell","-Command","Get-ChildItem -Recurse -File | Select-Object LastWriteTime,FullName | Sort-Object LastWriteTime -Descending | Select-Object -First 100"]
            r = subprocess.run(cmd,capture_output=True,text=True,timeout=120)
            out_parts.append(r.stdout[:5000])
            for line in r.stdout.split("\n")[:50]:
                if line.strip():
                    findings.append({"type":"timeline_entry","detail":line.strip()[:200]})
        except Exception as e:
            out_parts.append(f"Timeline error: {e}")
        if not findings:
            findings.append({"type":"timeline","value":"No timeline data"})
        return SkillResult(success=True,output="\n".join(out_parts),findings=findings,execution_time=time.time()-s)
