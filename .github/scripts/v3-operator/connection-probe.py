#!/usr/bin/env python3
"""Keep one TLS connection alive through a local mixed proxy."""
import argparse
import datetime
import http.client
import json
import secrets
import socket
import ssl
import sys
import time
import re


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run(port, count, interval, request_sha256, deadline_unix):
    connection = socket.create_connection(("127.0.0.1", port), timeout=12)
    connection.sendall(b"CONNECT httpbingo.org:443 HTTP/1.1\r\nHost: httpbingo.org:443\r\n\r\n")
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        byte = connection.recv(1)
        if not byte or len(header) > 4096:
            raise ValueError("CONNECT refused")
        header.extend(byte)
    if header.split(b"\r\n", 1)[0].split()[1] != b"200":
        raise ValueError("CONNECT refused")
    connection_id = secrets.token_hex(16)
    with ssl.create_default_context().wrap_socket(connection, server_hostname="httpbingo.org") as tls:
        for number in range(1, count + 1):
            tls.sendall(b"GET /status/200 HTTP/1.1\r\nHost: httpbingo.org\r\nUser-Agent: sbxr-qualification\r\nConnection: keep-alive\r\n\r\n")
            response = http.client.HTTPResponse(tls)
            response.begin()
            response.read()
            if response.status != 200 or response.will_close:
                raise ValueError("traffic failed or connection closed")
            response.close()
            print(json.dumps({"check": number, "connection_id": connection_id,
                              "request_sha256": request_sha256,
                              "same_connection": True,
                              "schema": "sbxr-v3-connection-probe-v1", "time": now()},
                             separators=(",", ":")), flush=True)
            if number != count:
                time.sleep(interval)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--deadline-unix", type=int, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.proxy_port <= 65535 or not 2 <= args.count <= 3600 or not 0.1 <= args.interval <= 60 or not re.fullmatch(r"[0-9a-f]{64}", args.request_sha256) or time.time() + (args.count - 1) * args.interval + 20 > args.deadline_unix:
        parser.error("unsafe probe bound")
    run(args.proxy_port, args.count, args.interval, args.request_sha256, args.deadline_unix)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        print('{"traffic_failed":true}', file=sys.stderr, flush=True)
        raise SystemExit(1)
