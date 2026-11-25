"""Service names guessed from a port NUMBER alone.

When nmap is not available (Light recon profile, or a worker image without it)
a port scan only knows that a TCP port accepted a connection. Naming what is
listening there from the number is still useful to a reader, but it is a
GUESS: anything can listen on any port, and a "3306" that is not MySQL is
perfectly possible. Callers must store these with confidence "port_guess" and
show them as unverified; they must never be reported as a detected service or
used as evidence for a finding.

The names follow nmap-services / IANA conventions where one exists, so a
later nmap result for the same port reads the same way.
"""

from __future__ import annotations

# The confidence label stored next to a name that came from here.
CONFIDENCE = "port_guess"

# port -> (service name, note). The note says what is conventionally there and,
# where it matters to a security reader, why an open port is worth a look.
COMMON_PORTS: dict[int, tuple[str, str]] = {
    21: ("ftp", "File Transfer Protocol; clear text unless FTPS"),
    22: ("ssh", "Secure Shell remote login"),
    23: ("telnet", "Telnet remote login; clear text"),
    25: ("smtp", "Mail transfer between servers"),
    53: ("domain", "DNS"),
    80: ("http", "Web (clear text)"),
    110: ("pop3", "Mail retrieval (clear text unless STARTTLS)"),
    111: ("rpcbind", "ONC RPC port mapper"),
    135: ("msrpc", "Microsoft RPC endpoint mapper"),
    139: ("netbios-ssn", "NetBIOS session service"),
    143: ("imap", "Mail retrieval (clear text unless STARTTLS)"),
    389: ("ldap", "Directory service (clear text unless StartTLS)"),
    443: ("https", "Web over TLS"),
    445: ("microsoft-ds", "SMB file sharing"),
    465: ("smtps", "Mail submission over TLS"),
    587: ("submission", "Mail submission"),
    636: ("ldaps", "Directory service over TLS"),
    993: ("imaps", "IMAP over TLS"),
    995: ("pop3s", "POP3 over TLS"),
    1433: ("ms-sql", "Microsoft SQL Server database"),
    1521: ("oracle", "Oracle database listener"),
    2049: ("nfs", "Network File System"),
    2375: ("docker", "Docker daemon API, unencrypted"),
    2376: ("docker-tls", "Docker daemon API over TLS"),
    3000: ("http", "Common development web server port"),
    3306: ("mysql", "MySQL / MariaDB database"),
    3389: ("ms-wbt-server", "Windows Remote Desktop"),
    5000: ("http", "Common web application port"),
    5432: ("postgresql", "PostgreSQL database"),
    5672: ("amqp", "RabbitMQ / AMQP message broker"),
    5900: ("vnc", "VNC remote desktop"),
    5984: ("couchdb", "CouchDB database HTTP API"),
    6379: ("redis", "Redis datastore; no login by default"),
    8000: ("http", "Common alternative web port"),
    8080: ("http-proxy", "Alternative web / proxy port"),
    8443: ("https-alt", "Alternative web over TLS"),
    8888: ("http", "Common alternative web port"),
    9000: ("http", "Common web / admin port"),
    9090: ("http", "Common web / admin port (e.g. Prometheus)"),
    9200: ("elasticsearch", "Elasticsearch HTTP API"),
    11211: ("memcached", "Memcached cache; no login by default"),
    27017: ("mongodb", "MongoDB database"),
}


def guess(port: int) -> str | None:
    """The service name conventionally used on TCP ``port``, or None when the
    port is not in the table. A guess from the number only: see the module
    docstring."""
    entry = COMMON_PORTS.get(port)
    return entry[0] if entry else None


def guess_note(port: int) -> str | None:
    """The short note that goes with ``guess(port)``, or None."""
    entry = COMMON_PORTS.get(port)
    return entry[1] if entry else None
