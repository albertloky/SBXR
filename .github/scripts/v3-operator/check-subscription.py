#!/usr/bin/env python3
"""Check the protected subscription link from the outside Mac without retaining it."""
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.parse

SUBSCRIPTION_PORT = 8443
SUBSCRIPTION_PATH = re.compile(r"/s/[A-Za-z0-9_-]{43}")

class SafeFailure(Exception):
    pass

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-key")
        result[key] = value
    return result

def require(stage, condition):
    if not condition:
        raise SafeFailure(stage)

def fields_match(artifact, config):
    try:
        text = artifact.decode("utf-8")
        if not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
            return False
        node = urllib.parse.urlsplit(text[:-1]); pairs = urllib.parse.parse_qsl(node.query, strict_parsing=True); values = dict(pairs)
        if len(config["outbounds"]) != 1: return False
        proxy = config["outbounds"][0]; tls = proxy["tls"]; reality = tls["reality"]; utls = tls["utls"]
        expected = {"encryption":"none","flow":"xtls-rprx-vision","security":"reality","sni":tls["server_name"],"fp":"chrome","pbk":reality["public_key"],"sid":reality["short_id"],"type":"tcp"}
        return proxy["type"] == "vless" and proxy["server_port"] == 443 and proxy["flow"] == "xtls-rprx-vision" and tls["enabled"] is True and reality["enabled"] is True and utls["enabled"] is True and utls["fingerprint"] == "chrome" and node.scheme == "vless" and node.hostname == proxy["server"] and node.port == 443 and node.username == proxy["uuid"] and node.password is None and node.path == "" and len(pairs) == len(expected) and len(values) == len(expected) and values == expected and urllib.parse.unquote(node.fragment) == f"SBXR Proxy ({proxy['server']})"
    except (AttributeError, KeyError, TypeError, UnicodeError, ValueError):
        return False

def check(data):
    try:
        link_text = data["link"]; link = urllib.parse.urlsplit(link_text); host = link.hostname
        require("link-shape", link.scheme == "https" and link.port == 8443 and link.username is None and link.password is None and not link.query and not link.fragment and SUBSCRIPTION_PATH.fullmatch(link.path) is not None and str(ipaddress.IPv4Address(host)) == host)
    except SafeFailure: raise
    except Exception: raise SafeFailure("link-shape") from None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(12)
    try:
        sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex("en0")); sock.connect((host, 8443))
    except Exception: sock.close(); raise SafeFailure("tcp-connect") from None
    try: tls = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    except Exception: sock.close(); raise SafeFailure("tls-trust") from None
    with tls:
        try:
            tls.sendall(f"GET {link.path} HTTP/1.1\r\nHost: {link.netloc}\r\nConnection: close\r\n\r\n".encode("ascii")); response = http.client.HTTPResponse(tls); response.begin(); body = response.read(65537)
            require("http-status", len(body) <= 65536 and response.status == 200)
        except SafeFailure: raise
        except Exception: raise SafeFailure("http-status") from None
        require("artifact-fields", fields_match(body, data["configuration"]))
        try:
            require("certificate-hash", hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() == data["certificate_der_sha256"])
        except SafeFailure: raise
        except Exception: raise SafeFailure("certificate-hash") from None
    return {"artifact_fields_and_name":True,"expected_status":True,"link_sha256":hashlib.sha256(link_text.encode()).hexdigest(),"schema":"sbxr-v3-subscription-check-v1","trusted_outside_tls":True}

if __name__ == "__main__":
    try:
        body = sys.stdin.buffer.read(1_000_001)
        if len(body) > 1_000_000: raise SafeFailure("input-bound")
        print(json.dumps(check(json.loads(body, object_pairs_hook=unique)), separators=(",", ":")))
    except SafeFailure as failure: print(json.dumps({"subscription_check_failed":True,"stage":str(failure)}, separators=(",", ":"))); raise SystemExit(1)
    except Exception: print('{"subscription_check_failed":true,"stage":"link-shape"}'); raise SystemExit(1)
