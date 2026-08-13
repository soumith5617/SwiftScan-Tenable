/**
 * Built-in scan engine. Server-only.
 *
 * Runs real HTTP/TLS-layer checks against a target and emits normalized
 * findings. Checks are registered plugins — the runner knows nothing about
 * any individual check, so new families can be added without touching it.
 */

import { priorityScore, severityFromCvss } from "./severity";

export interface RawFinding {
  plugin_id: string;
  family: string;
  title: string;
  severity: number;
  confidence: "high" | "medium" | "low";
  description: string;
  solution: string;
  evidence: string;
  port?: number | undefined;
  service?: string | undefined;
  cve_ids?: string[] | undefined;
  cwe?: string | null | undefined;
  attack_tactics?: string[] | undefined;
  refs?: { title: string; url: string }[] | undefined;
}

export interface DiscoveredPort {
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  service: string;
  banner?: string | undefined;
}

export const COMMON_PORTS: {
  port: number;
  service: string;
  category: "web" | "db" | "remote" | "mail" | "infra" | "container" | "dev" | "proxy";
  riskSeverity?: number;
  description?: string;
}[] = [
  /* ---------------- Core Infrastructure & Network Services ---------------- */
  {
    port: 20,
    service: "ftp-data",
    category: "infra",
    riskSeverity: 2,
    description: "File Transfer Protocol (FTP Data Transfer)",
  },
  {
    port: 21,
    service: "ftp",
    category: "infra",
    riskSeverity: 2,
    description: "File Transfer Protocol (cleartext authentication risk)",
  },
  { port: 22, service: "ssh", category: "remote", description: "Secure Shell (SSH) remote administration" },
  {
    port: 23,
    service: "telnet",
    category: "remote",
    riskSeverity: 4,
    description: "Telnet unencrypted remote terminal service (critical credential sniffing risk)",
  },
  { port: 25, service: "smtp", category: "mail", description: "Simple Mail Transfer Protocol" },
  { port: 53, service: "dns", category: "infra", description: "Domain Name System (DNS) resolver/authoritative" },
  { port: 69, service: "tftp", category: "infra", riskSeverity: 3, description: "Trivial File Transfer Protocol (unauthenticated)" },
  { port: 80, service: "http", category: "web", description: "HTTP Web Server" },
  { port: 88, service: "kerberos", category: "infra", description: "Kerberos Authentication Service" },
  {
    port: 110,
    service: "pop3",
    category: "mail",
    riskSeverity: 2,
    description: "Post Office Protocol v3 (cleartext email authentication)",
  },
  {
    port: 111,
    service: "rpcbind",
    category: "infra",
    riskSeverity: 3,
    description: "ONC RPC portmapper / rpcbind daemon",
  },
  { port: 119, service: "nntp", category: "infra", description: "Network News Transfer Protocol" },
  { port: 123, service: "ntp", category: "infra", description: "Network Time Protocol" },
  {
    port: 135,
    service: "msrpc",
    category: "infra",
    riskSeverity: 3,
    description: "Microsoft RPC Endpoint Mapper (EPMAP)",
  },
  {
    port: 137,
    service: "netbios-ns",
    category: "infra",
    riskSeverity: 2,
    description: "NetBIOS Name Service",
  },
  {
    port: 138,
    service: "netbios-dgm",
    category: "infra",
    riskSeverity: 2,
    description: "NetBIOS Datagram Service",
  },
  {
    port: 139,
    service: "netbios-ssn",
    category: "infra",
    riskSeverity: 3,
    description: "NetBIOS Session Service (SMB over NetBIOS)",
  },
  {
    port: 143,
    service: "imap",
    category: "mail",
    riskSeverity: 2,
    description: "Internet Message Access Protocol (cleartext)",
  },
  {
    port: 161,
    service: "snmp",
    category: "infra",
    riskSeverity: 3,
    description: "Simple Network Management Protocol agent",
  },
  { port: 389, service: "ldap", category: "infra", riskSeverity: 2, description: "Lightweight Directory Access Protocol" },
  { port: 443, service: "https", category: "web", description: "HTTPS Secure Web Server" },
  {
    port: 445,
    service: "smb",
    category: "infra",
    riskSeverity: 3,
    description: "Microsoft Server Message Block (SMB/CIFS direct hosting)",
  },
  { port: 465, service: "smtps", category: "mail", description: "SMTP over SSL/TLS" },
  { port: 514, service: "syslog", category: "infra", description: "Syslog Remote Logging Daemon" },
  { port: 515, service: "lpd", category: "infra", description: "Line Printer Daemon" },
  { port: 587, service: "smtp-submission", category: "mail", description: "Mail Message Submission (STARTTLS)" },
  { port: 636, service: "ldaps", category: "infra", description: "LDAP over SSL/TLS" },
  { port: 873, service: "rsync", category: "infra", riskSeverity: 3, description: "Rsync file synchronisation daemon" },
  { port: 993, service: "imaps", category: "mail", description: "IMAP over SSL/TLS" },
  { port: 995, service: "pop3s", category: "mail", description: "POP3 over SSL/TLS" },

  /* ---------------- Databases & In-Memory Stores ---------------- */
  {
    port: 1433,
    service: "mssql",
    category: "db",
    riskSeverity: 3,
    description: "Microsoft SQL Server database listener",
  },
  {
    port: 1434,
    service: "mssql-m",
    category: "db",
    riskSeverity: 2,
    description: "Microsoft SQL Server Browser Service",
  },
  {
    port: 1521,
    service: "oracle",
    category: "db",
    riskSeverity: 3,
    description: "Oracle Database TNS listener",
  },
  {
    port: 3306,
    service: "mysql",
    category: "db",
    riskSeverity: 3,
    description: "MySQL / MariaDB database port exposed to network",
  },
  {
    port: 5432,
    service: "postgresql",
    category: "db",
    riskSeverity: 3,
    description: "PostgreSQL database port exposed to network",
  },
  {
    port: 5984,
    service: "couchdb",
    category: "db",
    riskSeverity: 3,
    description: "Apache CouchDB REST API database listener",
  },
  {
    port: 6379,
    service: "redis",
    category: "db",
    riskSeverity: 4,
    description: "Redis in-memory store exposed without network isolation",
  },
  {
    port: 6380,
    service: "redis-tls",
    category: "db",
    riskSeverity: 2,
    description: "Redis in-memory store with TLS encryption",
  },
  {
    port: 7000,
    service: "cassandra-internode",
    category: "db",
    riskSeverity: 3,
    description: "Apache Cassandra inter-node cluster communication",
  },
  {
    port: 7001,
    service: "cassandra-ssl",
    category: "db",
    riskSeverity: 2,
    description: "Apache Cassandra SSL inter-node communication",
  },
  {
    port: 9042,
    service: "cassandra-cql",
    category: "db",
    riskSeverity: 3,
    description: "Apache Cassandra Native CQL Binary Protocol",
  },
  {
    port: 9200,
    service: "elasticsearch",
    category: "db",
    riskSeverity: 3,
    description: "Elasticsearch REST cluster endpoint",
  },
  {
    port: 9300,
    service: "elasticsearch-nodes",
    category: "db",
    riskSeverity: 3,
    description: "Elasticsearch cluster node-to-node transport",
  },
  {
    port: 11211,
    service: "memcached",
    category: "db",
    riskSeverity: 4,
    description: "Memcached caching server (unauthenticated memory access & amplification risk)",
  },
  {
    port: 27017,
    service: "mongodb",
    category: "db",
    riskSeverity: 4,
    description: "MongoDB NoSQL database listener exposed",
  },
  {
    port: 27018,
    service: "mongodb-shard",
    category: "db",
    riskSeverity: 3,
    description: "MongoDB Shard Server daemon listener",
  },
  {
    port: 28017,
    service: "mongodb-web",
    category: "db",
    riskSeverity: 4,
    description: "MongoDB Legacy Web Status Console",
  },

  /* ---------------- Remote Access & Virtualization ---------------- */
  {
    port: 2222,
    service: "directadmin-ssh",
    category: "remote",
    description: "Alternate SSH / DirectAdmin Management Port",
  },
  {
    port: 3389,
    service: "rdp",
    category: "remote",
    riskSeverity: 3,
    description: "Remote Desktop Protocol (RDP) listener",
  },
  {
    port: 5900,
    service: "vnc",
    category: "remote",
    riskSeverity: 4,
    description: "Virtual Network Computing (VNC) Remote Desktop server",
  },
  {
    port: 5901,
    service: "vnc-display1",
    category: "remote",
    riskSeverity: 4,
    description: "VNC Remote Desktop Display :1",
  },
  {
    port: 5985,
    service: "winrm-http",
    category: "remote",
    riskSeverity: 3,
    description: "Windows Remote Management (WinRM) over HTTP",
  },
  {
    port: 5986,
    service: "winrm-https",
    category: "remote",
    riskSeverity: 2,
    description: "Windows Remote Management (WinRM) over HTTPS",
  },

  /* ---------------- Containers, Cloud & Orchestration ---------------- */
  {
    port: 2375,
    service: "docker",
    category: "container",
    riskSeverity: 4,
    description: "Unauthenticated Docker daemon API socket (critical remote code execution risk)",
  },
  {
    port: 2376,
    service: "docker-tls",
    category: "container",
    riskSeverity: 2,
    description: "Docker daemon TLS socket",
  },
  {
    port: 2379,
    service: "etcd-client",
    category: "container",
    riskSeverity: 4,
    description: "etcd distributed key-value store client communication API",
  },
  {
    port: 2380,
    service: "etcd-peer",
    category: "container",
    riskSeverity: 3,
    description: "etcd cluster peer communication port",
  },
  {
    port: 6443,
    service: "kubernetes",
    category: "container",
    riskSeverity: 2,
    description: "Kubernetes API Server listener",
  },
  {
    port: 10250,
    service: "kubelet",
    category: "container",
    riskSeverity: 3,
    description: "Kubernetes Kubelet HTTPS API",
  },
  {
    port: 10255,
    service: "kubelet-ro",
    category: "container",
    riskSeverity: 3,
    description: "Kubernetes Kubelet Unauthenticated Read-Only API",
  },
  {
    port: 10256,
    service: "kube-proxy",
    category: "container",
    riskSeverity: 1,
    description: "Kubernetes Kube-Proxy Health Check Service",
  },

  /* ---------------- Web Applications, Proxies & Dev Frameworks ---------------- */
  {
    port: 1080,
    service: "socks-proxy",
    category: "proxy",
    riskSeverity: 3,
    description: "SOCKS Proxy Server listener",
  },
  {
    port: 1194,
    service: "openvpn",
    category: "remote",
    description: "OpenVPN Server Gateway",
  },
  {
    port: 1723,
    service: "pptp-vpn",
    category: "remote",
    riskSeverity: 3,
    description: "Point-to-Point Tunneling Protocol (PPTP) VPN (weak cryptography)",
  },
  {
    port: 1883,
    service: "mqtt",
    category: "infra",
    riskSeverity: 2,
    description: "MQTT IoT Broker (unencrypted message bus)",
  },
  {
    port: 2049,
    service: "nfs",
    category: "infra",
    riskSeverity: 3,
    description: "Network File System (NFS) service listener",
  },
  {
    port: 2082,
    service: "cpanel-http",
    category: "web",
    riskSeverity: 2,
    description: "cPanel Web Hosting Management (HTTP)",
  },
  {
    port: 2083,
    service: "cpanel-https",
    category: "web",
    description: "cPanel Web Hosting Management (HTTPS)",
  },
  {
    port: 2086,
    service: "whm-http",
    category: "web",
    riskSeverity: 3,
    description: "WebHost Manager (WHM) Admin Console (HTTP)",
  },
  {
    port: 2087,
    service: "whm-https",
    category: "web",
    riskSeverity: 2,
    description: "WebHost Manager (WHM) Admin Console (HTTPS)",
  },
  {
    port: 2181,
    service: "zookeeper",
    category: "infra",
    riskSeverity: 3,
    description: "Apache ZooKeeper coordination service listener",
  },
  {
    port: 3000,
    service: "node-dev-web",
    category: "dev",
    description: "Node.js / React / Grafana Web Application Dashboard",
  },
  {
    port: 3128,
    service: "squid-proxy",
    category: "proxy",
    riskSeverity: 2,
    description: "Squid HTTP Forward/Reverse Proxy",
  },
  {
    port: 4000,
    service: "dev-server",
    category: "dev",
    description: "Web development server / Hexo / GraphQL API",
  },
  {
    port: 4200,
    service: "angular-dev",
    category: "dev",
    description: "Angular CLI / Web development live reload server",
  },
  {
    port: 4317,
    service: "otel-grpc",
    category: "infra",
    description: "OpenTelemetry Collector OTLP/gRPC receiver",
  },
  {
    port: 4318,
    service: "otel-http",
    category: "infra",
    description: "OpenTelemetry Collector OTLP/HTTP receiver",
  },
  {
    port: 4444,
    service: "metasploit-selenium",
    category: "infra",
    riskSeverity: 4,
    description: "Metasploit payload handler / Selenium Grid Hub listener",
  },
  {
    port: 5000,
    service: "flask-registry",
    category: "dev",
    description: "Python Flask / Docker Registry / Synology NAS portal",
  },
  {
    port: 5060,
    service: "sip",
    category: "infra",
    description: "Session Initiation Protocol (SIP VoIP) listener",
  },
  {
    port: 5061,
    service: "sips",
    category: "infra",
    description: "SIP VoIP over TLS (SIPS)",
  },
  {
    port: 5601,
    service: "kibana",
    category: "web",
    riskSeverity: 2,
    description: "Kibana Analytics & Dashboard Web UI",
  },
  {
    port: 5672,
    service: "rabbitmq-amqp",
    category: "infra",
    description: "RabbitMQ AMQP message broker",
  },
  {
    port: 7077,
    service: "spark-master",
    category: "infra",
    riskSeverity: 3,
    description: "Apache Spark Cluster Master RPC listener",
  },
  {
    port: 8000,
    service: "http-dev",
    category: "dev",
    description: "Development Web Server (Django, FastAPI, Python SimpleHTTP)",
  },
  {
    port: 8008,
    service: "http-alt",
    category: "web",
    description: "Alternate HTTP Server / REST API listener",
  },
  {
    port: 8080,
    service: "http-alt",
    category: "web",
    description: "Alternate HTTP / Apache Tomcat / Web Proxy",
  },
  {
    port: 8081,
    service: "nexus-mgmt",
    category: "web",
    description: "Sonatype Nexus / Alternate HTTP Application Port",
  },
  {
    port: 8086,
    service: "influxdb",
    category: "db",
    description: "InfluxDB Time-Series Database HTTP API",
  },
  {
    port: 8088,
    service: "rest-api",
    category: "web",
    description: "Hadoop YARN ResourceManager / Asterisk HTTP / REST API",
  },
  {
    port: 8090,
    service: "confluence-http",
    category: "web",
    description: "Atlassian Confluence / Alternate HTTP application service",
  },
  {
    port: 8181,
    service: "glassfish-http",
    category: "web",
    description: "GlassFish / Payara Application Server Administration Port",
  },
  {
    port: 8443,
    service: "https-alt",
    category: "web",
    description: "Alternate HTTPS / Web Management Console",
  },
  {
    port: 8500,
    service: "consul-http",
    category: "infra",
    riskSeverity: 3,
    description: "HashiCorp Consul Service Mesh HTTP API & Web UI",
  },
  {
    port: 8883,
    service: "mqtts",
    category: "infra",
    description: "Secure MQTT over TLS IoT Broker",
  },
  {
    port: 8888,
    service: "jupyter-http",
    category: "dev",
    riskSeverity: 3,
    description: "Jupyter Notebook / Python Interactive Computing Server",
  },
  {
    port: 9000,
    service: "php-sonarqube-minio",
    category: "web",
    description: "PHP-FPM / SonarQube / MinIO S3 Object Storage API",
  },
  {
    port: 9001,
    service: "minio-console",
    category: "web",
    description: "MinIO Object Storage Web Console / Supervisord Admin",
  },
  {
    port: 9090,
    service: "prometheus-cockpit",
    category: "web",
    description: "Prometheus Monitoring Server / Cockpit Linux Web Console",
  },
  {
    port: 9092,
    service: "kafka",
    category: "infra",
    description: "Apache Kafka Distributed Event Streaming Broker",
  },
  {
    port: 9100,
    service: "node-exporter",
    category: "infra",
    description: "Prometheus Node Exporter host metrics endpoint",
  },
  {
    port: 9418,
    service: "git-daemon",
    category: "dev",
    description: "Git source control server daemon",
  },
  {
    port: 9999,
    service: "java-jmx",
    category: "dev",
    riskSeverity: 3,
    description: "Java JMX RMI Remote Management & Profiling Listener",
  },
  {
    port: 10000,
    service: "webmin",
    category: "remote",
    riskSeverity: 3,
    description: "Webmin / Virtualmin Linux System Administration Web Panel",
  },
  {
    port: 15672,
    service: "rabbitmq-mgmt",
    category: "web",
    description: "RabbitMQ Management Web UI & HTTP API",
  },
];

const HTTP_PROBE_PORTS = new Set([
  80, 443, 2082, 2083, 2086, 2087, 2375, 3000, 3128, 4000, 4200, 5000, 5601, 5984, 5985, 5986, 6443,
  7001, 8000, 8008, 8080, 8081, 8086, 8088, 8090, 8181, 8443, 8500, 8888, 9000, 9001, 9090, 9100,
  9200, 10000, 10250, 10255, 15672, 28017,
]);

const HTTPS_DEFAULT_PORTS = new Set([
  443, 2083, 2087, 2376, 5986, 6443, 7001, 8443, 10000, 10250,
]);

export async function probePort(
  host: string,
  port: number,
  timeoutMs = 2000,
): Promise<DiscoveredPort | null> {
  const info = COMMON_PORTS.find((p) => p.port === port);

  // If known HTTP/HTTPS candidate, probe via HTTP request first
  if (HTTP_PROBE_PORTS.has(port)) {
    const isHttps = HTTPS_DEFAULT_PORTS.has(port);
    const protos = isHttps ? ["https", "http"] : ["http", "https"];
    for (const proto of protos) {
      try {
        const res = await probe(`${proto}://${host}:${port}/`, {}, Math.min(timeoutMs, 1800));
        if (res && res.status > 0) {
          const banner = res.headers["server"] || res.headers["x-powered-by"] || (res.status === 200 ? "HTTP 200 OK" : `HTTP ${res.status}`);
          return {
            port,
            protocol: "tcp",
            state: "open",
            service: info?.service ?? (proto === "https" ? "https" : "http"),
            banner: banner ? `${proto.toUpperCase()} (${banner})` : `${proto.toUpperCase()} Web Server`,
          };
        }
      } catch {
        // continue to next proto / socket
      }
    }
  }

  // Socket probe for all standard ports and raw listeners
  try {
    const net = await import("node:net");
    return await new Promise<DiscoveredPort | null>((resolve) => {
      let settled = false;
      const socket = net.createConnection({ host, port, timeout: timeoutMs });
      socket.setTimeout(timeoutMs);

      socket.on("connect", () => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve({
          port,
          protocol: "tcp",
          state: "open",
          service: info?.service ?? "tcp-service",
          banner: info?.description,
        });
      });

      socket.on("timeout", () => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(null);
      });

      socket.on("error", () => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(null);
      });
    });
  } catch {
    return null;
  }
}

export async function sweepPorts(
  host: string,
  portList: typeof COMMON_PORTS = COMMON_PORTS,
): Promise<DiscoveredPort[]> {
  const results = await pooled(portList, 20, async (item) => {
    return probePort(host, item.port, 1800);
  });
  return results.filter((p): p is DiscoveredPort => p !== null && p.state === "open");
}

export interface Plugin {
  id: string;
  family: string;
  name: string;
  run: (ctx: ScanContext) => Promise<RawFinding[]>;
}

export interface ScanContext {
  baseUrl: URL;
  root: ProbeResult | null;
  tech: { name: string; version?: string | undefined; source: string }[];
  ports: DiscoveredPort[];
  httpsWorks: boolean;
  httpOnly: boolean;
}

export interface ProbeResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  ok: boolean;
  redirectedTo?: string | undefined;
  elapsedMs: number;
}

const PRIVATE_HOST =
  /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|\[?::1\]?|172\.(1[6-9]|2\d|3[01])\.)/i;

export function normalizeTarget(input: string): URL {
  const trimmed = input.trim();
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const url = new URL(withScheme);
  if (PRIVATE_HOST.test(url.hostname) || url.hostname.endsWith(".internal")) {
    throw new Error(
      "Target resolves to a private or loopback address. Scanning internal ranges requires a scan agent.",
    );
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Only http and https targets are supported by the built-in engine.");
  }
  return url;
}

export async function probe(
  url: string,
  init: RequestInit = {},
  timeoutMs = 9000,
): Promise<ProbeResult | null> {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": "AegisScan/1.0 (+vulnerability assessment)",
        accept: "*/*",
        ...(init.headers as Record<string, string> | undefined),
      },
      ...init,
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    let body = "";
    const ct = headers["content-type"] ?? "";
    if (/text|json|xml|javascript|html/.test(ct) || !ct) {
      body = (await res.text()).slice(0, 120_000);
    }
    return {
      url,
      status: res.status,
      headers,
      body,
      ok: res.ok,
      redirectedTo: res.url !== url ? res.url : undefined,
      elapsedMs: Date.now() - started,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function pooled<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const idx = cursor++;
      out[idx] = await fn(items[idx]!);
    }
  });
  await Promise.all(workers);
  return out;
}

/* ------------------------------------------------------------------ */
/* Plugin definitions                                                  */
/* ------------------------------------------------------------------ */

export interface Plugin {
  id: string;
  family: string;
  name: string;
  run: (ctx: ScanContext) => Promise<RawFinding[]>;
}

const SECURITY_HEADERS: {
  header: string;
  title: string;
  severity: number;
  cwe: string;
  desc: string;
  fix: string;
}[] = [
  {
    header: "strict-transport-security",
    title: "HTTP Strict Transport Security (HSTS) not enforced",
    severity: 2,
    cwe: "CWE-319",
    desc: "The server does not send a Strict-Transport-Security header, so browsers may downgrade to cleartext HTTP and expose sessions to interception or SSL-stripping attacks.",
    fix: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTTPS responses.",
  },
  {
    header: "content-security-policy",
    title: "Content Security Policy missing",
    severity: 2,
    cwe: "CWE-1021",
    desc: "No Content-Security-Policy header was returned. CSP is the primary browser-side mitigation against cross-site scripting and data-injection attacks.",
    fix: "Define a restrictive CSP starting from `default-src 'self'` and tighten script-src / frame-ancestors.",
  },
  {
    header: "x-frame-options",
    title: "Clickjacking protection missing",
    severity: 2,
    cwe: "CWE-1021",
    desc: "Neither X-Frame-Options nor a CSP frame-ancestors directive was present, so the page can be framed by an attacker-controlled site for clickjacking.",
    fix: "Send `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.",
  },
  {
    header: "x-content-type-options",
    title: "MIME type sniffing not disabled",
    severity: 1,
    cwe: "CWE-16",
    desc: "The X-Content-Type-Options header is absent, allowing browsers to MIME-sniff responses and potentially execute uploaded content as script.",
    fix: "Send `X-Content-Type-Options: nosniff` on every response.",
  },
  {
    header: "referrer-policy",
    title: "Referrer-Policy not set",
    severity: 1,
    cwe: "CWE-200",
    desc: "Without a Referrer-Policy, full URLs — including sensitive path or query data — may leak to third-party sites through the Referer header.",
    fix: "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
  },
  {
    header: "permissions-policy",
    title: "Permissions-Policy not set",
    severity: 0,
    cwe: "CWE-16",
    desc: "No Permissions-Policy header restricts access to powerful browser features (camera, microphone, geolocation) for the page and its embedded frames.",
    fix: "Send a Permissions-Policy header disabling unused features, e.g. `camera=(), microphone=(), geolocation=()`.",
  },
];

const EXPOSURE_PATHS: { path: string; title: string; severity: number; match?: RegExp }[] = [
  {
    path: "/.env",
    title: "Environment configuration file exposed",
    severity: 4,
    match: /^[A-Z0-9_]+=|APP_KEY|SECRET|DB_PASSWORD|JWT_SECRET|AWS_SECRET/m,
  },
  {
    path: "/.env.local",
    title: "Local environment file exposed",
    severity: 4,
    match: /^[A-Z0-9_]+=|SECRET|PASSWORD|KEY/m,
  },
  {
    path: "/.env.production",
    title: "Production environment file exposed",
    severity: 4,
    match: /^[A-Z0-9_]+=|SECRET|PASSWORD|KEY/m,
  },
  {
    path: "/.git/config",
    title: "Git repository configuration exposed",
    severity: 4,
    match: /\[core\]|repositoryformatversion/,
  },
  { path: "/.git/HEAD", title: "Git HEAD metadata exposed", severity: 4, match: /ref:\s*refs\// },
  {
    path: "/.aws/credentials",
    title: "AWS credentials file exposed",
    severity: 4,
    match: /aws_access_key_id|\[default\]/i,
  },
  {
    path: "/.ssh/id_rsa",
    title: "Private SSH key exposed",
    severity: 4,
    match: /BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY/,
  },
  {
    path: "/config.json",
    title: "Application config file exposed",
    severity: 3,
    match: /\{[\s\S]*(password|secret|apiKey|token|database)/i,
  },
  {
    path: "/backup.zip",
    title: "Compressed backup archive exposed",
    severity: 3,
  },
  {
    path: "/backup.sql",
    title: "Database backup file exposed",
    severity: 4,
    match: /CREATE TABLE|INSERT INTO|DROP TABLE/i,
  },
  {
    path: "/db.sql",
    title: "Database dump file exposed",
    severity: 4,
    match: /CREATE TABLE|INSERT INTO|DROP TABLE/i,
  },
  {
    path: "/dump.sql",
    title: "Database SQL dump exposed",
    severity: 4,
    match: /CREATE TABLE|INSERT INTO|DROP TABLE/i,
  },
  {
    path: "/wp-config.php.bak",
    title: "WordPress configuration backup exposed",
    severity: 4,
    match: /DB_PASSWORD|DB_USER|AUTH_KEY/,
  },
  {
    path: "/phpinfo.php",
    title: "PHP info diagnostic page exposed",
    severity: 3,
    match: /phpinfo\(\)|PHP Version|Configuration File/i,
  },
  {
    path: "/server-status",
    title: "Apache server status exposed",
    severity: 2,
    match: /Apache Server Status|Total Accesses|CPU Usage/i,
  },
  {
    path: "/server-info",
    title: "Apache server information exposed",
    severity: 2,
    match: /Apache Server Information/i,
  },
  {
    path: "/actuator/env",
    title: "Spring Boot actuator environment endpoint exposed",
    severity: 4,
    match: /"propertySources"|activeProfiles/,
  },
  {
    path: "/actuator/health",
    title: "Spring Boot actuator health endpoint exposed",
    severity: 1,
    match: /"status"\s*:\s*"UP"|"components"/i,
  },
  {
    path: "/debug/vars",
    title: "Go expvar debug variables exposed",
    severity: 2,
    match: /"cmdline"|"memstats"/,
  },
  {
    path: "/docker-compose.yml",
    title: "Docker Compose manifest exposed",
    severity: 3,
    match: /version:|services:|image:/,
  },
  {
    path: "/.gitlab-ci.yml",
    title: "GitLab CI pipeline configuration exposed",
    severity: 3,
    match: /stages:|image:|script:/,
  },
  {
    path: "/package.json",
    title: "Node.js package manifest exposed",
    severity: 1,
    match: /"name"\s*:|"dependencies"\s*:/,
  },
  {
    path: "/composer.json",
    title: "PHP Composer manifest exposed",
    severity: 1,
    match: /"require"\s*:|"autoload"\s*:/,
  },
  {
    path: "/web.config",
    title: "IIS web.config configuration exposed",
    severity: 3,
    match: /<configuration>|<system\.webServer>/i,
  },
  {
    path: "/crossdomain.xml",
    title: "Flash cross-domain policy file exposed",
    severity: 1,
    match: /<cross-domain-policy>|<allow-access-from/i,
  },
  {
    path: "/admin",
    title: "Administrative login portal reachable",
    severity: 1,
  },
  {
    path: "/.well-known/security.txt",
    title: "No security.txt published",
    severity: 0,
    match: /Contact:|Expires:/i,
  },
];

const API_PATHS = [
  "/openapi.json",
  "/swagger.json",
  "/api-docs",
  "/v2/api-docs",
  "/swagger-ui.html",
  "/graphql",
];

function detectTech(
  res: ProbeResult,
): { name: string; version?: string | undefined; source: string }[] {
  const found: { name: string; version?: string | undefined; source: string }[] = [];
  const push = (name: string, version: string | undefined, source: string) => {
    if (!found.some((f) => f.name.toLowerCase() === name.toLowerCase()))
      found.push({ name, version, source });
  };
  const server = res.headers["server"];
  if (server) {
    const [name, version] = server.split("/");
    push(name!.trim(), version?.split(" ")[0], "Server header");
  }
  const powered = res.headers["x-powered-by"];
  if (powered) {
    const [name, version] = powered.split("/");
    push(name!.trim(), version?.trim(), "X-Powered-By header");
  }
  const generator = res.body.match(
    /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i,
  );
  if (generator?.[1]) {
    const m = generator[1].match(/^([A-Za-z .-]+?)\s*([\d.]+)?$/);
    push(m?.[1]?.trim() ?? generator[1], m?.[2], "generator meta tag");
  }
  if (/wp-content|wp-includes/.test(res.body)) push("WordPress", undefined, "wp-content path");
  if (res.headers["x-drupal-cache"] || /Drupal\.settings/.test(res.body))
    push("Drupal", undefined, "Drupal marker");
  if (/__NEXT_DATA__/.test(res.body)) push("Next.js", undefined, "__NEXT_DATA__ payload");
  if (/data-reactroot|react-dom/.test(res.body)) push("React", undefined, "React marker");
  if (res.headers["x-aspnet-version"])
    push("ASP.NET", res.headers["x-aspnet-version"], "X-AspNet-Version header");
  if (res.headers["x-powered-cms"] || /Ghost\/([0-9.]+)/i.test(res.body))
    push("Ghost", undefined, "Ghost CMS marker");
  if (/laravel_session|XSRF-TOKEN/.test(res.headers["set-cookie"] ?? ""))
    push("Laravel", undefined, "Laravel session cookie");
  return found;
}

export const PLUGINS: Plugin[] = [
  {
    id: "AEG-10001",
    family: "fingerprint",
    name: "Service and technology fingerprint",
    async run(ctx) {
      if (!ctx.root) return [];
      const list = ctx.tech;
      const findings: RawFinding[] = [];
      findings.push({
        plugin_id: "AEG-10001",
        family: "fingerprint",
        title: "Web service detected",
        severity: 0,
        confidence: "high",
        description: `HTTP service responded with status ${ctx.root.status} in ${ctx.root.elapsedMs}ms. Detected technologies: ${
          list.length
            ? list.map((t) => `${t.name}${t.version ? " " + t.version : ""}`).join(", ")
            : "none identified"
        }.`,
        solution: "Informational. Remove version banners to reduce information disclosure.",
        evidence:
          Object.entries(ctx.root.headers)
            .filter(([k]) => ["server", "x-powered-by", "via", "x-aspnet-version"].includes(k))
            .map(([k, v]) => `${k}: ${v}`)
            .join("\n") || `HTTP ${ctx.root.status} ${ctx.root.url}`,
        port: ctx.baseUrl.protocol === "https:" ? 443 : 80,
        service: "http",
      });
      const versioned = list.filter((t) => t.version);
      if (versioned.length) {
        findings.push({
          plugin_id: "AEG-10002",
          family: "fingerprint",
          title: "Software version disclosed in HTTP response",
          severity: 1,
          confidence: "high",
          cwe: "CWE-200",
          description: `The server discloses exact software versions (${versioned
            .map((t) => `${t.name} ${t.version}`)
            .join(", ")}). Attackers use this to select known exploits without probing.`,
          solution:
            "Suppress version tokens (`ServerTokens Prod`, `server_tokens off`, remove X-Powered-By).",
          evidence: versioned.map((t) => `${t.name} ${t.version} (via ${t.source})`).join("\n"),
          attack_tactics: ["Reconnaissance"],
        });
      }
      return findings;
    },
  },
  {
    id: "AEG-20001",
    family: "tls",
    name: "Transport security",
    async run(ctx) {
      const findings: RawFinding[] = [];
      if (ctx.httpOnly) {
        findings.push({
          plugin_id: "AEG-20001",
          family: "tls",
          title: "Service available over cleartext HTTP without TLS",
          severity: 4,
          confidence: "high",
          cwe: "CWE-319",
          description:
            "The target answered over plain HTTP and no working HTTPS listener was found. All traffic, including credentials and session cookies, travels unencrypted and can be read or modified in transit.",
          solution:
            "Deploy a valid TLS certificate, serve the site over HTTPS, and redirect all HTTP traffic to HTTPS.",
          evidence: `HTTPS probe to ${ctx.baseUrl.origin.replace("http:", "https:")} failed; HTTP probe succeeded.`,
          port: 80,
          service: "http",
          attack_tactics: ["Collection", "Credential Access"],
        });
        return findings;
      }
      const httpOrigin = ctx.baseUrl.origin.replace("https:", "http:");
      const httpRes = await probe(httpOrigin, { redirect: "manual" }, 7000);
      if (httpRes && httpRes.status >= 200 && httpRes.status < 300) {
        findings.push({
          plugin_id: "AEG-20002",
          family: "tls",
          title: "HTTP traffic is not redirected to HTTPS",
          severity: 3,
          confidence: "high",
          cwe: "CWE-319",
          description:
            "The cleartext HTTP endpoint serves content directly instead of redirecting to HTTPS, allowing SSL-stripping downgrade attacks against users who reach the site over HTTP.",
          solution:
            "Return a 301 redirect from all HTTP requests to the HTTPS equivalent, and enable HSTS preload.",
          evidence: `GET ${httpOrigin} returned HTTP ${httpRes.status} instead of a redirect.`,
          port: 80,
          service: "http",
        });
      }
      if (ctx.root && /http:\/\/(?!localhost)/.test(ctx.root.body.slice(0, 60_000))) {
        const sample = ctx.root.body.match(/(?:src|href)=["']http:\/\/[^"']+/i)?.[0];
        if (sample && !/http:\/\/(www\.)?w3\.org|schema\.org|purl\.org|xmlns/.test(sample)) {
          findings.push({
            plugin_id: "AEG-20003",
            family: "tls",
            title: "Mixed content: HTTPS page references cleartext resources",
            severity: 2,
            confidence: "medium",
            cwe: "CWE-311",
            description:
              "The HTTPS page loads at least one sub-resource over plain HTTP. Browsers may block it, and active mixed content can compromise the entire page.",
            solution:
              "Rewrite all sub-resource URLs to HTTPS or protocol-relative and add `upgrade-insecure-requests` to CSP.",
            evidence: sample.slice(0, 300),
          });
        }
      }
      return findings;
    },
  },
  {
    id: "AEG-30000",
    family: "headers",
    name: "Security header audit",
    async run(ctx) {
      if (!ctx.root) return [];
      const h = ctx.root.headers;
      const findings: RawFinding[] = [];
      for (const [i, spec] of SECURITY_HEADERS.entries()) {
        const present = !!h[spec.header];
        const cspFrames =
          spec.header === "x-frame-options" &&
          /frame-ancestors/i.test(h["content-security-policy"] ?? "");
        if (spec.header === "strict-transport-security" && ctx.httpOnly) continue;
        if (!present && !cspFrames) {
          findings.push({
            plugin_id: `AEG-3000${i + 1}`,
            family: "headers",
            title: spec.title,
            severity: spec.severity,
            confidence: "high",
            cwe: spec.cwe,
            description: spec.desc,
            solution: spec.fix,
            evidence: `Response headers from ${ctx.root.url} did not include \`${spec.header}\`.`,
          });
        }
      }
      const hsts = h["strict-transport-security"];
      if (hsts) {
        const maxAge = Number(hsts.match(/max-age=(\d+)/i)?.[1] ?? 0);
        if (maxAge > 0 && maxAge < 15552000) {
          findings.push({
            plugin_id: "AEG-30010",
            family: "headers",
            title: "HSTS max-age is too short",
            severity: 1,
            confidence: "high",
            cwe: "CWE-319",
            description: `The HSTS policy expires after ${maxAge} seconds, below the recommended six-month minimum, leaving a window for downgrade attacks.`,
            solution: "Raise max-age to at least 31536000 seconds and add includeSubDomains.",
            evidence: `strict-transport-security: ${hsts}`,
          });
        }
      }
      const acao = h["access-control-allow-origin"];
      const acac = h["access-control-allow-credentials"];
      if (acao === "*" && acac === "true") {
        findings.push({
          plugin_id: "AEG-30011",
          family: "headers",
          title: "Insecure CORS: wildcard origin with credentials",
          severity: 3,
          confidence: "high",
          cwe: "CWE-942",
          description:
            "The service returns `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. Any site can read authenticated responses on behalf of a signed-in user.",
          solution: "Reflect only explicitly allow-listed origins when credentials are permitted.",
          evidence: `access-control-allow-origin: ${acao}\naccess-control-allow-credentials: ${acac}`,
          attack_tactics: ["Collection"],
        });
      }
      const setCookie = ctx.root.headers["set-cookie"];
      if (setCookie) {
        const problems: string[] = [];
        if (!/;\s*secure/i.test(setCookie) && !ctx.httpOnly) problems.push("missing Secure");
        if (!/;\s*httponly/i.test(setCookie)) problems.push("missing HttpOnly");
        if (!/;\s*samesite/i.test(setCookie)) problems.push("missing SameSite");
        if (problems.length) {
          findings.push({
            plugin_id: "AEG-30012",
            family: "headers",
            title: "Session cookie set without full protection flags",
            severity: problems.includes("missing HttpOnly") ? 2 : 1,
            confidence: "high",
            cwe: "CWE-1004",
            description: `A cookie is issued ${problems.join(", ")}. Cookies without HttpOnly are readable by JavaScript during an XSS, without Secure they leak over HTTP, and without SameSite they are sent on cross-site requests (CSRF).`,
            solution: "Set `Secure; HttpOnly; SameSite=Lax` (or Strict) on all session cookies.",
            evidence: setCookie.slice(0, 300),
          });
        }
      }
      return findings;
    },
  },
  {
    id: "AEG-40000",
    family: "exposure",
    name: "Sensitive file and endpoint exposure",
    async run(ctx) {
      const results = await pooled(EXPOSURE_PATHS, 6, async (spec) => {
        const res = await probe(new URL(spec.path, ctx.baseUrl.origin).toString(), {}, 7000);
        return { spec, res };
      });
      const findings: RawFinding[] = [];
      for (const { spec, res } of results) {
        if (spec.path === "/.well-known/security.txt") {
          if (!res || res.status !== 200) {
            findings.push({
              plugin_id: "AEG-40099",
              family: "exposure",
              title: "No security.txt vulnerability disclosure policy",
              severity: 0,
              confidence: "high",
              description:
                "The host does not publish /.well-known/security.txt, so security researchers have no documented channel to report vulnerabilities.",
              solution: "Publish a security.txt with a Contact and Expires field (RFC 9116).",
              evidence: `GET /.well-known/security.txt returned ${res ? res.status : "no response"}.`,
            });
          }
          continue;
        }
        if (!res || res.status !== 200 || !res.body) continue;
        if (
          /<html/i.test(res.body.slice(0, 400)) &&
          spec.path !== "/admin" &&
          spec.path !== "/phpinfo.php"
        )
          continue;
        if (spec.match && !spec.match.test(res.body)) continue;
        const confirmed = !spec.match || spec.match.test(res.body);
        findings.push({
          plugin_id: `AEG-4${String(EXPOSURE_PATHS.indexOf(spec)).padStart(4, "0")}`,
          family: "exposure",
          title: spec.title,
          severity: spec.severity,
          confidence: confirmed && spec.match ? "high" : "medium",
          cwe: "CWE-538",
          description: `The path \`${spec.path}\` is publicly reachable and returned content matching a known sensitive-file signature. Exposed configuration, credentials or source metadata typically leads directly to full compromise.`,
          solution: `Block \`${spec.path}\` at the web server or CDN, remove the file from the document root, and rotate any credentials it contained.`,
          evidence: `GET ${spec.path} -> HTTP 200\n\n${res.body.slice(0, 400)}`,
          attack_tactics: ["Initial Access", "Credential Access"],
        });
      }
      const dirRes = await probe(new URL("/uploads/", ctx.baseUrl.origin).toString(), {}, 6000);
      if (dirRes?.status === 200 && /Index of \/|<title>Directory listing/i.test(dirRes.body)) {
        findings.push({
          plugin_id: "AEG-40200",
          family: "exposure",
          title: "Directory listing enabled",
          severity: 2,
          confidence: "high",
          cwe: "CWE-548",
          description:
            "The web server renders an automatic index of directory contents, exposing files not meant to be discoverable.",
          solution: "Disable autoindex (`Options -Indexes` / `autoindex off`).",
          evidence: dirRes.body.slice(0, 300),
        });
      }
      return findings;
    },
  },
  {
    id: "AEG-50000",
    family: "webapp",
    name: "OWASP web application probes",
    async run(ctx) {
      const findings: RawFinding[] = [];
      const marker = "aegis7391probe";
      const xssUrl = new URL(ctx.baseUrl.origin);
      xssUrl.searchParams.set("q", `<${marker}>`);
      const xssRes = await probe(xssUrl.toString(), {}, 8000);
      if (xssRes && xssRes.body.includes(`<${marker}>`)) {
        findings.push({
          plugin_id: "AEG-50001",
          family: "webapp",
          title: "Unencoded user input reflected in HTML response",
          severity: 3,
          confidence: "medium",
          cwe: "CWE-79",
          description:
            "A query parameter was reflected into the HTML response with its angle brackets intact, which is the precondition for reflected cross-site scripting. Manual confirmation with a real payload is recommended.",
          solution:
            "Context-aware output encoding for all user-controlled data, plus a strict Content-Security-Policy.",
          evidence: `GET ${xssUrl.pathname}?q=<${marker}> — marker reflected unencoded in response body.`,
          attack_tactics: ["Execution"],
        });
      }
      const redirUrl = new URL(ctx.baseUrl.origin);
      redirUrl.pathname = "/";
      redirUrl.searchParams.set("next", "https://example.org/");
      const redirRes = await probe(redirUrl.toString(), { redirect: "manual" }, 7000);
      if (redirRes && [301, 302, 303, 307, 308].includes(redirRes.status)) {
        const loc = redirRes.headers["location"] ?? "";
        if (loc.startsWith("https://example.org")) {
          findings.push({
            plugin_id: "AEG-50002",
            family: "webapp",
            title: "Open redirect via unvalidated destination parameter",
            severity: 2,
            confidence: "high",
            cwe: "CWE-601",
            description:
              "The application redirects to an arbitrary external URL supplied in a query parameter, enabling convincing phishing links that originate from the trusted domain.",
            solution: "Allow only relative paths or an explicit allow-list of destinations.",
            evidence: `GET /?next=https://example.org/ -> ${redirRes.status} Location: ${loc}`,
            attack_tactics: ["Initial Access"],
          });
        }
      }
      const errRes = await probe(
        new URL("/aegis-nonexistent-" + marker, ctx.baseUrl.origin).toString(),
        {},
        7000,
      );
      if (
        errRes &&
        /stack trace|Traceback \(most recent|at [\w.$]+\(.*\.java:|Exception in thread|SQLSTATE|ORA-\d{5}|Warning: mysqli/i.test(
          errRes.body,
        )
      ) {
        findings.push({
          plugin_id: "AEG-50003",
          family: "webapp",
          title: "Verbose error output discloses internal details",
          severity: 2,
          confidence: "high",
          cwe: "CWE-209",
          description:
            "An error response leaked a stack trace or database error containing internal paths, framework versions or query fragments that assist an attacker in targeting the application.",
          solution:
            "Disable debug mode in production and return generic error pages while logging detail server-side.",
          evidence: errRes.body.slice(0, 400),
        });
      }
      const optRes = await probe(ctx.baseUrl.origin, { method: "OPTIONS" }, 6000);
      const allow =
        optRes?.headers["allow"] ?? optRes?.headers["access-control-allow-methods"] ?? "";
      if (/\b(PUT|DELETE|TRACE|PATCH)\b/i.test(allow)) {
        findings.push({
          plugin_id: "AEG-50004",
          family: "webapp",
          title: "Potentially dangerous HTTP methods enabled",
          severity: /TRACE/i.test(allow) ? 2 : 1,
          confidence: "medium",
          cwe: "CWE-650",
          description: `The server advertises the methods: ${allow}. TRACE enables cross-site tracing, and write methods exposed at the server level can allow unauthorized modification.`,
          solution: "Disable TRACE and restrict write methods to authenticated API routes only.",
          evidence: `OPTIONS / -> Allow: ${allow}`,
        });
      }
      return findings;
    },
  },
  {
    id: "AEG-60000",
    family: "api",
    name: "API surface discovery",
    async run(ctx) {
      const results = await pooled(API_PATHS, 4, async (path) => ({
        path,
        res: await probe(new URL(path, ctx.baseUrl.origin).toString(), {}, 7000),
      }));
      const findings: RawFinding[] = [];
      for (const { path, res } of results) {
        if (!res || res.status !== 200) continue;
        const isSpec = /"openapi"|"swagger"|swagger-ui/i.test(res.body);
        if (isSpec) {
          const paths = res.body.match(/"\/[^"]{1,80}":\s*\{/g)?.length ?? 0;
          findings.push({
            plugin_id: "AEG-60001",
            family: "api",
            title: "API specification publicly exposed",
            severity: 1,
            confidence: "high",
            cwe: "CWE-200",
            description: `An OpenAPI/Swagger document is served without authentication at \`${path}\`, describing ${paths || "multiple"} endpoints. This hands an attacker a complete map of the API attack surface.`,
            solution:
              "Require authentication for API documentation in production, or publish only a redacted spec.",
            evidence: `GET ${path} -> HTTP 200, ${res.body.length} bytes of API specification.`,
            attack_tactics: ["Reconnaissance"],
          });
        }
        if (path === "/graphql") {
          const introspect = await probe(new URL("/graphql", ctx.baseUrl.origin).toString(), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ query: "{__schema{types{name}}}" }),
          });
          if (introspect && /__schema|"types"/.test(introspect.body)) {
            findings.push({
              plugin_id: "AEG-60002",
              family: "api",
              title: "GraphQL introspection enabled in production",
              severity: 2,
              confidence: "high",
              cwe: "CWE-200",
              description:
                "The GraphQL endpoint answers introspection queries, exposing the entire schema including internal types, mutations and deprecated fields.",
              solution:
                "Disable introspection outside development and enforce query depth/complexity limits.",
              evidence: introspect.body.slice(0, 300),
              attack_tactics: ["Reconnaissance"],
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: "AEG-80000",
    family: "ports",
    name: "Network port and service discovery",
    async run(ctx) {
      const findings: RawFinding[] = [];
      const open = ctx.ports;
      if (open.length > 0) {
        findings.push({
          plugin_id: "AEG-80001",
          family: "ports",
          title: `Network ports discovered (${open.map((p) => p.port).join(", ")})`,
          severity: 0,
          confidence: "high",
          description: `Active listening ports identified on the host: ${open
            .map((p) => `${p.port}/${p.protocol} (${p.service})`)
            .join(", ")}.`,
          solution: "Review open ports and close any non-essential services.",
          evidence: open
            .map((p) => `Port ${p.port}/${p.protocol}: ${p.service} (${p.banner ?? "open"})`)
            .join("\n"),
        });
      }
      for (const p of open) {
        const info = COMMON_PORTS.find((cp) => cp.port === p.port);
        if (info?.riskSeverity && info.riskSeverity >= 2) {
          findings.push({
            plugin_id: `AEG-8${String(p.port).padStart(4, "0")}`,
            family: "ports",
            title: `High-risk port exposed: ${p.port}/${p.protocol} (${p.service})`,
            severity: info.riskSeverity,
            confidence: "high",
            cwe: "CWE-200",
            description: `${info.description ?? `Port ${p.port} is open to untrusted networks.`} Direct exposure increases attack surface for remote exploitation.`,
            solution: `Restrict port ${p.port} via firewall or VPN access controls.`,
            evidence: `TCP connection to ${ctx.baseUrl.hostname}:${p.port} succeeded.`,
            port: p.port,
            service: p.service,
            attack_tactics: ["Initial Access"],
          });
        }
      }
      return findings;
    },
  },
  {
    id: "AEG-81000",
    family: "database",
    name: "Database service exposure audit",
    async run(ctx) {
      const findings: RawFinding[] = [];
      const dbPorts = ctx.ports.filter((p) =>
        [1433, 1434, 1521, 3306, 5432, 5984, 6379, 6380, 7000, 7001, 8086, 9042, 9200, 9300, 11211, 27017, 27018, 28017].includes(p.port),
      );
      for (const p of dbPorts) {
        findings.push({
          plugin_id: `AEG-81${String(p.port).padStart(3, "0")}`,
          family: "database",
          title: `Database listening service exposed — ${p.service.toUpperCase()} (Port ${p.port})`,
          severity: [6379, 11211, 27017, 28017].includes(p.port) ? 4 : 3,
          confidence: "high",
          cwe: "CWE-284",
          description: `The ${p.service.toUpperCase()} database service is reachable from the network on port ${p.port}. Database ports should never be directly accessible from untrusted networks without network isolation.`,
          solution: `Bind database services to localhost or private network interfaces only and configure firewall rules to drop internet ingress to port ${p.port}.`,
          evidence: `Discovered open database listener on ${ctx.baseUrl.hostname}:${p.port} (${p.service}).`,
          port: p.port,
          service: p.service,
          attack_tactics: ["Initial Access", "Collection"],
        });
      }
      return findings;
    },
  },
  {
    id: "AEG-82000",
    family: "cloud",
    name: "Cloud infrastructure and metadata assessment",
    async run(ctx) {
      const findings: RawFinding[] = [];
      const host = ctx.baseUrl.hostname;
      const bucketName = host.replace(/\.[a-z0-9-]+$/i, "").replace(/\./g, "-");

      const s3Url = `https://${bucketName}.s3.amazonaws.com/`;
      const s3Probe = await probe(s3Url, {}, 5000);
      if (s3Probe && s3Probe.status === 200 && /ListBucketResult/i.test(s3Probe.body)) {
        findings.push({
          plugin_id: "AEG-82001",
          family: "cloud",
          title: "Publicly readable Amazon S3 storage bucket",
          severity: 4,
          confidence: "high",
          cwe: "CWE-732",
          description: `An Amazon S3 storage bucket matching the domain pattern (${s3Url}) allows anonymous listing and read access.`,
          solution: "Enable S3 Block Public Access and review bucket ACLs.",
          evidence: `GET ${s3Url} returned HTTP 200 with XML bucket listing:\n${s3Probe.body.slice(0, 300)}`,
          attack_tactics: ["Initial Access", "Collection"],
        });
      }
      return findings;
    },
  },
  {
    id: "AEG-83000",
    family: "container",
    name: "Container & Kubernetes runtime exposure",
    async run(ctx) {
      const findings: RawFinding[] = [];
      const containerPorts = ctx.ports.filter((p) => [2375, 2376, 2379, 2380, 6443, 10250, 10255, 10256].includes(p.port));
      for (const p of containerPorts) {
        if (p.port === 2375) {
          findings.push({
            plugin_id: "AEG-83001",
            family: "container",
            title: "Unauthenticated Docker daemon API exposed (Port 2375)",
            severity: 4,
            confidence: "high",
            cwe: "CWE-306",
            description:
              "The Docker daemon REST API is listening on port 2375 without TLS or authentication. Anyone with network access can execute arbitrary commands as root by spawning containers.",
            solution:
              "Disable plaintext Docker daemon TCP binding or configure mutual TLS authentication on port 2376.",
            evidence: `Port 2375 open on ${ctx.baseUrl.hostname}`,
            port: 2375,
            service: "docker",
            attack_tactics: ["Initial Access", "Execution"],
          });
        }
        if (p.port === 2379) {
          findings.push({
            plugin_id: "AEG-83003",
            family: "container",
            title: "etcd Distributed Store Client API Exposed (Port 2379)",
            severity: 4,
            confidence: "high",
            cwe: "CWE-306",
            description:
              "etcd cluster key-value API is accessible over port 2379. In Kubernetes and container environments, exposed etcd allows unauthenticated retrieval of cluster secrets and full takeover.",
            solution: "Ensure etcd client traffic requires mutual TLS certificate authentication and isolate the port.",
            evidence: `Port 2379 open on ${ctx.baseUrl.hostname}`,
            port: 2379,
            service: "etcd-client",
            attack_tactics: ["Initial Access", "Credential Access"],
          });
        }
        if (p.port === 6443) {
          findings.push({
            plugin_id: "AEG-83002",
            family: "container",
            title: "Kubernetes API Server exposed (Port 6443)",
            severity: 2,
            confidence: "high",
            description:
              "The Kubernetes API server control plane is exposed to the network on port 6443.",
            solution:
              "Ensure anonymous access is disabled (`--anonymous-auth=false`) and restrict network access via CIDR allow-listing.",
            evidence: `Port 6443 open on ${ctx.baseUrl.hostname}`,
            port: 6443,
            service: "kubernetes",
          });
        }
        if (p.port === 10250) {
          findings.push({
            plugin_id: "AEG-83004",
            family: "container",
            title: "Kubernetes Kubelet API exposed (Port 10250)",
            severity: 3,
            confidence: "high",
            cwe: "CWE-284",
            description: "The Kubelet HTTPS API endpoint is reachable. If misconfigured with anonymous authentication, attackers can execute commands inside running pods.",
            solution: "Enable `--anonymous-auth=false` and `--authorization-mode=Webhook` on all node kubelets.",
            evidence: `Port 10250 open on ${ctx.baseUrl.hostname}`,
            port: 10250,
            service: "kubelet",
            attack_tactics: ["Initial Access", "Execution"],
          });
        }
        if (p.port === 10255) {
          findings.push({
            plugin_id: "AEG-83005",
            family: "container",
            title: "Kubernetes Kubelet Read-Only API exposed (Port 10255)",
            severity: 3,
            confidence: "high",
            cwe: "CWE-200",
            description: "The deprecated Kubelet read-only port 10255 is exposed without authentication, leaking pod specs, secrets and environment configurations.",
            solution: "Disable the read-only port by setting `--read-only-port=0` in Kubelet configuration.",
            evidence: `Port 10255 open on ${ctx.baseUrl.hostname}`,
            port: 10255,
            service: "kubelet-ro",
            attack_tactics: ["Reconnaissance"],
          });
        }
      }
      return findings;
    },
  },
  {
    id: "AEG-84000",
    family: "endpoint",
    name: "End-of-Life (EOL) and software lifecycle audit",
    async run(ctx) {
      const findings: RawFinding[] = [];
      for (const t of ctx.tech) {
        if (!t.version) continue;
        const name = t.name.toLowerCase();
        const v = t.version;

        if (name === "php") {
          const major = parseFloat(v);
          if (major < 8.1) {
            findings.push({
              plugin_id: "AEG-84001",
              family: "endpoint",
              title: `End-of-Life (EOL) PHP runtime version detected (${v})`,
              severity: 3,
              confidence: "high",
              cwe: "CWE-1104",
              description: `PHP version ${v} reached End-of-Life and no longer receives security updates from upstream maintainers.`,
              solution: "Upgrade to PHP 8.2 or 8.3.",
              evidence: `PHP ${v} identified via ${t.source}.`,
              refs: [
                {
                  title: "PHP Supported Versions",
                  url: "https://www.php.net/supported-versions.php",
                },
              ],
            });
          }
        } else if (name === "apache") {
          const parts = v.split(".").map(Number);
          if (
            parts[0]! < 2 ||
            (parts[0] === 2 && parts[1]! < 4) ||
            (parts[0] === 2 && parts[1] === 4 && (parts[2] ?? 0) < 58)
          ) {
            findings.push({
              plugin_id: "AEG-84002",
              family: "endpoint",
              title: `Outdated Apache HTTP Server version (${v})`,
              severity: 2,
              confidence: "high",
              cwe: "CWE-1104",
              description: `Apache HTTP Server ${v} contains multiple publicly known vulnerabilities.`,
              solution: "Upgrade Apache HTTP Server to version 2.4.58 or newer.",
              evidence: `Apache ${v} identified via ${t.source}.`,
            });
          }
        } else if (name === "nginx") {
          const parts = v.split(".").map(Number);
          if (parts[0]! < 1 || (parts[0] === 1 && parts[1]! < 24)) {
            findings.push({
              plugin_id: "AEG-84003",
              family: "endpoint",
              title: `Outdated Nginx web server version (${v})`,
              severity: 2,
              confidence: "high",
              cwe: "CWE-1104",
              description: `Nginx ${v} is older than current mainline/stable releases.`,
              solution: "Upgrade Nginx to version 1.24.0 or 1.26.x.",
              evidence: `Nginx ${v} identified via ${t.source}.`,
            });
          }
        } else if (name === "wordpress") {
          const major = parseFloat(v);
          if (major < 6.4) {
            findings.push({
              plugin_id: "AEG-84004",
              family: "endpoint",
              title: `Outdated WordPress core installation (${v})`,
              severity: 3,
              confidence: "high",
              cwe: "CWE-1104",
              description: `WordPress ${v} is outdated and vulnerable to known exploits.`,
              solution: "Update WordPress core to the latest stable release.",
              evidence: `WordPress ${v} identified via ${t.source}.`,
            });
          }
        }
      }
      return findings;
    },
  },
];

/* ------------------------------------------------------------------ */
/* Runner                                                              */
/* ------------------------------------------------------------------ */

export interface EngineResult {
  findings: RawFinding[];
  tech: { name: string; version?: string | undefined; source: string }[];
  ports: DiscoveredPort[];
  steps: { step: string; findings: number }[];
  reachable: boolean;
  responseMs: number | null;
}

export async function runEngine(
  target: string,
  families: readonly string[],
  onProgress?: (step: string, pct: number) => Promise<void> | void,
): Promise<EngineResult> {
  const baseUrl = normalizeTarget(target);
  await onProgress?.("All-ports host discovery & network sweep", 5);

  const discoveredPorts = await sweepPorts(baseUrl.hostname);

  let root = await probe(baseUrl.toString());
  let httpsWorks = !!root && baseUrl.protocol === "https:";
  let httpOnly = false;

  if (!root && baseUrl.protocol === "https:") {
    const httpUrl = new URL(baseUrl.toString());
    httpUrl.protocol = "http:";
    root = await probe(httpUrl.toString());
    if (root) {
      httpOnly = true;
      httpsWorks = false;
    }
  }

  // Ensure default port is recorded in discoveredPorts
  const defaultPort = baseUrl.port
    ? parseInt(baseUrl.port, 10)
    : baseUrl.protocol === "https:"
      ? 443
      : 80;
  if (!discoveredPorts.some((p) => p.port === defaultPort) && root) {
    discoveredPorts.push({
      port: defaultPort,
      protocol: "tcp",
      state: "open",
      service: baseUrl.protocol.replace(":", ""),
      banner: root.headers["server"] ?? "HTTP Web Server",
    });
  }

  if (!root && discoveredPorts.length === 0) {
    return { findings: [], tech: [], ports: [], steps: [], reachable: false, responseMs: null };
  }

  const ctx: ScanContext = {
    baseUrl: root ? new URL(root.redirectedTo ?? root.url) : baseUrl,
    root: root ?? null,
    tech: root ? detectTech(root) : [],
    ports: discoveredPorts,
    httpsWorks,
    httpOnly,
  };

  const active = PLUGINS.filter((p) => families.includes(p.family));
  const findings: RawFinding[] = [];
  const steps: { step: string; findings: number }[] = [];

  for (const [i, plugin] of active.entries()) {
    await onProgress?.(plugin.name, Math.round(10 + (i / active.length) * 75));
    try {
      const out = await plugin.run(ctx);
      findings.push(...out);
      steps.push({ step: plugin.name, findings: out.length });
    } catch (err) {
      steps.push({ step: `${plugin.name} (failed)`, findings: 0 });
      console.error(`plugin ${plugin.id} failed`, err);
    }
  }

  return {
    findings,
    tech: ctx.tech,
    ports: discoveredPorts,
    steps,
    reachable: true,
    responseMs: root?.elapsedMs ?? null,
  };
}

export { priorityScore, severityFromCvss };

import { EXTENDED_PLUGINS } from "./scan-engine-extended.server";
PLUGINS.push(...EXTENDED_PLUGINS);
