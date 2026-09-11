"""Tests for professional analysis modules."""

from t100ai.analysis.attack_graph import AttackGraph
from t100ai.analysis.chain_of_custody import ChainOfCustody
from t100ai.analysis.cvss_scorer import CVSSv4Metrics, CVSSv4Scorer
from t100ai.analysis.finding_cluster import Finding, FindingCluster
from t100ai.analysis.ioc_manager import IoCManager
from t100ai.analysis.kill_chain import KillChainMapper
from t100ai.analysis.purple_team import PurpleTeamEngine, SigmaRule
from t100ai.analysis.risk_prioritizer import RiskFactors, RiskPrioritizer
from t100ai.compliance.frameworks import ComplianceMapper
from t100ai.core.engagement import EngagementManager


class TestChainOfCustody:
    def test_creation(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-001")
        assert coc._engagement_id == "ENG-001"

    def test_add_evidence(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-002")
        evidence = coc.add_evidence("nmap_scan", "nmap", "22/tcp open ssh", target="10.0.0.1")
        assert evidence.id == "EV-000001"
        assert evidence.evidence_type == "nmap_scan"
        assert len(evidence.content_hash) == 64  # SHA-256 hex
        assert len(evidence.signature) == 64
        assert evidence.previous_hash == "genesis"

    def test_chain_linking(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-003")
        e1 = coc.add_evidence("scan", "nmap", "output1")
        e2 = coc.add_evidence("scan", "nmap", "output2")
        assert e2.previous_hash == e1.signature

    def test_verify_intact(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-004")
        coc.add_evidence("scan", "nmap", "output1")
        coc.add_evidence("scan", "nmap", "output2")
        valid, msg = coc.verify()
        assert valid is True
        assert "intact" in msg.lower()

    def test_verify_empty(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-005")
        valid, msg = coc.verify()
        assert valid is True
        assert "empty" in msg.lower()

    def test_export_json(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-006")
        coc.add_evidence("scan", "nmap", "output1")
        exported = coc.export_chain("json")
        assert "EV-000001" in exported
        assert "content_hash" in exported

    def test_export_text(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-007")
        coc.add_evidence("scan", "nmap", "output1")
        exported = coc.export_chain("text")
        assert "EV-000001" in exported

    def test_get_chain(self):
        coc = ChainOfCustody(secret="test-secret", engagement_id="ENG-008")
        coc.add_evidence("scan", "nmap", "output1")
        coc.add_evidence("scan", "nmap", "output2")
        chain = coc.get_chain()
        assert len(chain) == 2


class TestCVSSv4Scorer:
    def test_critical_score(self):
        scorer = CVSSv4Scorer()
        metrics = CVSSv4Metrics(
            attack_vector="N", attack_complexity="L",
            vuln_confidentiality="H", vuln_integrity="H", vuln_availability="H",
        )
        result = scorer.score(metrics)
        assert result["score"] >= 9.0
        assert result["severity"] == "CRITICAL"

    def test_low_score(self):
        scorer = CVSSv4Scorer()
        metrics = CVSSv4Metrics(
            attack_vector="L", attack_complexity="H",
            vuln_confidentiality="L", vuln_integrity="N", vuln_availability="N",
        )
        result = scorer.score(metrics)
        assert result["score"] < 4.0
        assert result["severity"] in ("LOW", "NONE")

    def test_vector_string(self):
        scorer = CVSSv4Scorer()
        metrics = CVSSv4Metrics()
        result = scorer.score(metrics)
        assert result["vector"].startswith("CVSS:4.0/")

    def test_auto_score_sqli(self):
        scorer = CVSSv4Scorer()
        finding = {"title": "SQL Injection", "description": "SQL injection in login form"}
        result = scorer.auto_score(finding)
        assert result["score"] > 0
        assert result["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_auto_score_xss(self):
        scorer = CVSSv4Scorer()
        finding = {"title": "XSS", "description": "Reflected cross-site scripting"}
        result = scorer.auto_score(finding)
        assert result["score"] > 0

    def test_auto_score_rce(self):
        scorer = CVSSv4Scorer()
        finding = {"title": "RCE", "description": "Remote code execution via command injection"}
        result = scorer.auto_score(finding)
        assert result["score"] > 5.0


class TestAttackGraph:
    def test_creation(self):
        g = AttackGraph()
        assert g.get_stats()["nodes"] == 0

    def test_add_nodes_and_edges(self):
        g = AttackGraph()
        g.add_node("host1", "host", "Web Server", os="linux")
        g.add_node("vuln1", "vuln", "CVE-2024-1234", cvss=9.8)
        g.add_edge("host1", "vuln1", "exploit", 9.8, "T1190")
        stats = g.get_stats()
        assert stats["nodes"] == 2
        assert stats["edges"] == 1

    def test_find_attack_paths(self):
        g = AttackGraph()
        g.add_node("entry", "host", "Entry Point")
        g.add_node("web", "host", "Web Server")
        g.add_node("db", "host", "Database")
        g.add_node("crown", "host", "Crown Jewel")
        g.add_edge("entry", "web", "exploit", 8.0)
        g.add_edge("web", "db", "lateral", 7.0)
        g.add_edge("db", "crown", "escalate", 9.0)
        paths = g.find_attack_paths("entry", "crown")
        assert len(paths) >= 1
        assert paths[0][0] == "entry"
        assert paths[0][-1] == "crown"

    def test_shortest_path(self):
        g = AttackGraph()
        g.add_node("a", "host", "A")
        g.add_node("b", "host", "B")
        g.add_node("c", "host", "C")
        g.add_edge("a", "b", "exploit", 5.0)
        g.add_edge("b", "c", "exploit", 5.0)
        g.add_edge("a", "c", "direct", 8.0)
        path = g.find_shortest_path("a", "c")
        assert path is not None
        assert len(path) == 2  # a -> c direct

    def test_critical_nodes(self):
        g = AttackGraph()
        g.add_node("host1", "host", "Web Server")
        g.add_node("host2", "host", "DB Server")
        g.add_edge("host1", "host2", "lateral", 8.0)
        critical = g.get_critical_nodes()
        assert len(critical) >= 1

    def test_export_dot(self):
        g = AttackGraph()
        g.add_node("a", "host", "A")
        g.add_node("b", "vuln", "B")
        g.add_edge("a", "b", "exploit", 5.0)
        dot = g.export_dot()
        assert "digraph" in dot
        assert "a" in dot
        assert "b" in dot


class TestFindingCluster:
    def test_creation(self):
        fc = FindingCluster()
        assert fc.get_stats()["total_findings"] == 0

    def test_add_finding(self):
        fc = FindingCluster()
        fc.add_finding(Finding(id="F1", title="SQLi", severity="HIGH", category="injection", target="10.0.0.1"))
        assert fc.get_stats()["total_findings"] == 1

    def test_cluster_similar(self):
        fc = FindingCluster()
        fc.add_finding(Finding(id="F1", title="SQL Injection in login", severity="HIGH", category="injection", target="10.0.0.1"))
        fc.add_finding(Finding(id="F2", title="SQL Injection in login form", severity="HIGH", category="injection", target="10.0.0.1"))
        fc.add_finding(Finding(id="F3", title="SQL Injection in search page", severity="HIGH", category="injection", target="10.0.0.1"))
        fc.add_finding(Finding(id="F4", title="XSS in profile", severity="MED", category="xss", target="10.0.0.1"))
        clusters = fc.cluster()
        assert len(clusters) >= 1

    def test_cluster_empty(self):
        fc = FindingCluster()
        clusters = fc.cluster()
        assert clusters == []

    def test_stats(self):
        fc = FindingCluster()
        fc.add_finding(Finding(id="F1", title="Test", severity="HIGH", category="test", target="10.0.0.1", cvss=7.5))
        stats = fc.get_stats()
        assert stats["total_findings"] == 1
        assert stats["by_severity"]["HIGH"] == 1


class TestRiskPrioritizer:
    def test_critical_risk(self):
        rp = RiskPrioritizer()
        factors = RiskFactors(
            cvss_score=9.8, exploitability=0.9, business_impact=0.9,
            exposure=0.9, asset_value=0.9, active_exploit=True,
        )
        result = rp.calculate_risk(factors)
        assert result["score"] >= 0.9
        assert "P0" in result["priority"]

    def test_low_risk(self):
        rp = RiskPrioritizer()
        factors = RiskFactors(
            cvss_score=2.0, exploitability=0.2, business_impact=0.2,
            exposure=0.2, asset_value=0.2,
        )
        result = rp.calculate_risk(factors)
        assert result["score"] < 0.5

    def test_prioritize_list(self):
        rp = RiskPrioritizer()
        findings = [
            {"title": "Low finding", "cvss": 2.0, "exploitability": 0.2, "business_impact": 0.2, "exposure": 0.2, "asset_value": 0.2},
            {"title": "High finding", "cvss": 9.0, "exploitability": 0.8, "business_impact": 0.8, "exposure": 0.8, "asset_value": 0.8},
        ]
        prioritized = rp.prioritize(findings)
        assert prioritized[0]["title"] == "High finding"
        assert prioritized[1]["title"] == "Low finding"


class TestComplianceMapper:
    def test_creation(self):
        cm = ComplianceMapper()
        assert cm.get_compliance_report() == {}

    def test_map_access_finding(self):
        cm = ComplianceMapper()
        mappings = cm.map_finding("F1", "access_control", "Weak authentication")
        assert len(mappings) >= 2
        assert any(m.framework == "ISO27001" for m in mappings)
        assert any(m.framework == "PCI_DSS" for m in mappings)

    def test_map_vuln_finding(self):
        cm = ComplianceMapper()
        mappings = cm.map_finding("F2", "vulnerability", "CVE-2024-1234 found")
        assert len(mappings) >= 2

    def test_map_encrypt_finding(self):
        cm = ComplianceMapper()
        mappings = cm.map_finding("F3", "encryption", "Weak TLS cipher")
        assert len(mappings) >= 2
        assert any(m.framework == "PCI_DSS" for m in mappings)

    def test_compliance_report(self):
        cm = ComplianceMapper()
        cm.map_finding("F1", "access_control", "Weak auth")
        cm.map_finding("F2", "vulnerability", "CVE found")
        report = cm.get_compliance_report()
        assert "ISO27001" in report
        assert "NIST_CSF" in report
        assert "PCI_DSS" in report


class TestIoCManager:
    def test_creation(self):
        ioc = IoCManager()
        assert ioc.get_stats()["total"] == 0

    def test_add_ioc(self):
        ioc = IoCManager()
        indicator = ioc.add_ioc("10.0.0.1", "ip", "C2 Server", severity="HIGH")
        assert indicator.value == "10.0.0.1"
        assert indicator.ioc_type == "ip"
        assert ioc.get_stats()["total"] == 1

    def test_search(self):
        ioc = IoCManager()
        ioc.add_ioc("10.0.0.1", "ip", "C2 Server")
        ioc.add_ioc("evil.com", "domain", "Malware domain")
        results = ioc.search("10.0.0")
        assert len(results) == 1
        assert results[0].value == "10.0.0.1"

    def test_extract_from_text(self):
        ioc = IoCManager()
        text = "Connection from 192.168.1.100 to malware.evil.com detected"
        extracted = ioc.extract_iocs_from_text(text)
        assert len(extracted) >= 2

    def test_get_by_type(self):
        ioc = IoCManager()
        ioc.add_ioc("10.0.0.1", "ip", "Server 1")
        ioc.add_ioc("10.0.0.2", "ip", "Server 2")
        ioc.add_ioc("evil.com", "domain", "Malware")
        ips = ioc.get_by_type("ip")
        assert len(ips) == 2

    def test_mark_false_positive(self):
        ioc = IoCManager()
        ioc.add_ioc("10.0.0.1", "ip", "False positive")
        ioc.mark_false_positive("10.0.0.1")
        results = ioc.search("10.0.0")
        assert len(results) == 0

    def test_get_high_confidence(self):
        ioc = IoCManager()
        ioc.add_ioc("10.0.0.1", "ip", "High confidence", confidence=0.9)
        ioc.add_ioc("10.0.0.2", "ip", "Low confidence", confidence=0.3)
        high = ioc.get_high_confidence(0.8)
        assert len(high) == 1

    def test_export_stix(self):
        ioc = IoCManager()
        ioc.add_ioc("10.0.0.1", "ip", "Test")
        stix = ioc.export_stix()
        assert stix["type"] == "bundle"
        assert len(stix["objects"]) >= 1

    def test_stats(self):
        ioc = IoCManager()
        ioc.add_ioc("10.0.0.1", "ip", "Test", severity="HIGH")
        ioc.add_ioc("evil.com", "domain", "Test", severity="MED")
        stats = ioc.get_stats()
        assert stats["total"] == 2
        assert stats["by_type"]["ip"] == 1
        assert stats["by_type"]["domain"] == 1


class TestKillChainMapper:
    def test_creation(self):
        km = KillChainMapper()
        chain = km.get_kill_chain()
        assert len(chain) == 7

    def test_map_finding(self):
        km = KillChainMapper()
        phase = km.map_finding("F1", "nmap", "Port scan")
        assert phase == "reconnaissance"

    def test_map_exploitation(self):
        km = KillChainMapper()
        phase = km.map_finding("F2", "sqli", "SQL injection")
        assert phase == "exploitation"

    def test_map_installation(self):
        km = KillChainMapper()
        phase = km.map_finding("F3", "backdoor", "Webshell installed")
        assert phase == "installation"

    def test_coverage(self):
        km = KillChainMapper()
        km.map_finding("F1", "nmap")
        km.map_finding("F2", "sqli")
        coverage = km.get_coverage()
        assert coverage["covered_phases"] >= 2
        assert coverage["coverage_pct"] > 0

    def test_uncovered_phases(self):
        km = KillChainMapper()
        km.map_finding("F1", "nmap")
        uncovered = km.get_uncovered_phases()
        assert len(uncovered) == 6


class TestPurpleTeamEngine:
    def test_creation(self):
        engine = PurpleTeamEngine()
        assert engine is not None

    def test_generate_sqli_rule(self):
        engine = PurpleTeamEngine()
        rule = engine.generate_sigma_rule("sqli", "SQL injection in login")
        assert isinstance(rule, SigmaRule)
        assert "SQL" in rule.title
        yaml_output = rule.to_yaml()
        assert "title:" in yaml_output
        assert "detection:" in yaml_output

    def test_generate_xss_rule(self):
        engine = PurpleTeamEngine()
        rule = engine.generate_sigma_rule("xss", "Reflected XSS")
        assert isinstance(rule, SigmaRule)
        assert rule.level == "medium"

    def test_generate_brute_force_rule(self):
        engine = PurpleTeamEngine()
        rule = engine.generate_sigma_rule("brute_force", "SSH brute force")
        assert isinstance(rule, SigmaRule)
        assert rule.level == "medium"

    def test_generate_generic_rule(self):
        engine = PurpleTeamEngine()
        rule = engine.generate_sigma_rule("unknown_type", "Some finding")
        assert isinstance(rule, SigmaRule)
        assert "unknown_type" in rule.title

    def test_generate_all_rules(self):
        engine = PurpleTeamEngine()
        findings = [
            {"type": "sqli", "description": "SQL injection"},
            {"type": "xss", "description": "XSS"},
            {"type": "brute_force", "description": "Brute force"},
        ]
        rules = engine.generate_all_rules(findings)
        assert len(rules) == 3
        assert all(isinstance(r, SigmaRule) for r in rules)


class TestEngagementManager:
    def test_creation(self):
        mgr = EngagementManager()
        assert mgr.get_stats()["total_engagements"] == 0

    def test_create_engagement(self):
        mgr = EngagementManager()
        eng = mgr.create_engagement("Acme Corp", "pentest", scope=["10.0.0.0/24"])
        assert eng.client_name == "Acme Corp"
        assert eng.engagement_type == "pentest"
        assert eng.status == "planned"
        assert eng.id.startswith("ENG-")

    def test_get_engagement(self):
        mgr = EngagementManager()
        eng = mgr.create_engagement("Test Corp", "audit")
        retrieved = mgr.get_engagement(eng.id)
        assert retrieved is not None
        assert retrieved.client_name == "Test Corp"

    def test_list_engagements(self):
        mgr = EngagementManager()
        mgr.create_engagement("Client A", "pentest")
        mgr.create_engagement("Client B", "red-team")
        all_engs = mgr.list_engagements()
        assert len(all_engs) == 2

    def test_list_by_status(self):
        mgr = EngagementManager()
        mgr.create_engagement("Client A", "pentest")
        planned = mgr.list_engagements(status="planned")
        assert len(planned) == 1

    def test_list_by_client(self):
        mgr = EngagementManager()
        mgr.create_engagement("Acme Corp", "pentest")
        mgr.create_engagement("Beta Inc", "audit")
        results = mgr.list_engagements(client="acme")
        assert len(results) == 1
        assert results[0].client_name == "Acme Corp"

    def test_start_engagement(self):
        mgr = EngagementManager()
        eng = mgr.create_engagement("Test", "pentest")
        assert mgr.start_engagement(eng.id) is True
        assert mgr.get_engagement(eng.id).status == "active"

    def test_pause_engagement(self):
        mgr = EngagementManager()
        eng = mgr.create_engagement("Test", "pentest")
        mgr.start_engagement(eng.id)
        assert mgr.pause_engagement(eng.id) is True
        assert mgr.get_engagement(eng.id).status == "paused"

    def test_complete_engagement(self):
        mgr = EngagementManager()
        eng = mgr.create_engagement("Test", "pentest")
        mgr.start_engagement(eng.id)
        assert mgr.complete_engagement(eng.id) is True
        assert mgr.get_engagement(eng.id).status == "completed"

    def test_add_finding(self):
        mgr = EngagementManager()
        eng = mgr.create_engagement("Test", "pentest")
        mgr.add_finding(eng.id, "CRIT")
        mgr.add_finding(eng.id, "HIGH")
        mgr.add_finding(eng.id, "MED")
        updated = mgr.get_engagement(eng.id)
        assert updated.findings_count == 3
        assert updated.critical_findings == 1
        assert updated.high_findings == 1

    def test_engagement_report(self):
        mgr = EngagementManager()
        eng = mgr.create_engagement("Test", "pentest", scope=["10.0.0.1"])
        mgr.start_engagement(eng.id)
        mgr.add_finding(eng.id, "CRIT")
        report = mgr.get_engagement_report(eng.id)
        assert report is not None
        assert report["summary"]["total_findings"] == 1
        assert report["summary"]["critical"] == 1
        assert report["summary"]["risk_level"] == "CRITICAL"

    def test_stats(self):
        mgr = EngagementManager()
        mgr.create_engagement("Client A", "pentest")
        mgr.create_engagement("Client B", "red-team")
        stats = mgr.get_stats()
        assert stats["total_engagements"] == 2
        assert stats["unique_clients"] == 2
        assert stats["by_status"].get("planned", 0) == 2
