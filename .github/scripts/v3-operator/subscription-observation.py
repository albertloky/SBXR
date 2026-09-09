#!/usr/bin/env python3
"""Assemble protected subscription input from pipes, never argv or environment."""
import json
import os
import re
import sys

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration key")
        result[key] = value
    return result

def bounded(descriptor, limit):
    body = bytearray()
    while len(body) <= limit:
        block = os.read(descriptor, min(65536, limit + 1 - len(body)))
        if not block: break
        body.extend(block)
    if len(body) > limit:
        raise ValueError("protected input exceeded bound")
    return bytes(body)

def assemble(link_body, certificate_body, configuration_body):
    link = link_body.decode("ascii")
    certificate = certificate_body.decode("ascii")
    configuration = json.loads(configuration_body, object_pairs_hook=unique)
    if re.fullmatch(r"https://[0-9.]+:8443/s/[A-Za-z0-9_-]{43}", link) is None or re.fullmatch(r"[0-9a-f]{64}", certificate) is None or not isinstance(configuration, dict):
        raise ValueError("protected observation input")
    return {"certificate_der_sha256":certificate,"configuration":configuration,"link":link}

def main():
    document = assemble(bounded(3, 4096), bounded(4, 64), bounded(0, 65536))
    json.dump(document, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")

if __name__ == "__main__":
    try: main()
    except Exception:
        print('{"subscription_observation_failed":true}', file=sys.stderr)
        raise SystemExit(1)
