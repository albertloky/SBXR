#!/usr/bin/env python3
"""Retain a typed HTTP diagnostic without copying the verifier's raw bytes."""

import json
import os
import stat
import sys
from pathlib import Path

STAGES = (
    "latest_metadata", "tagged_metadata", "native_attestations", "attestation_bundle",
    "release_index", "release_archive", "other_release_asset",
)
DESTINATIONS = (
    None, "github_api", "attestation_storage", "github_release_cdn", "other_github_content", "other",
)
KEYS = {
    "stage", "destination", "redirect_count", "http_status", "rate_limit_exhausted", "retry_after_present",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def bounded_integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def valid_receipt(value):
    return (
        type(value) is dict
        and value.keys() == KEYS
        and value["stage"] in STAGES
        and value["destination"] in DESTINATIONS
        and bounded_integer(value["redirect_count"], 0, 4)
        and (value["http_status"] is None or bounded_integer(value["http_status"], 100, 599))
        and (value["rate_limit_exhausted"] is None or type(value["rate_limit_exhausted"]) is bool)
        and type(value["retry_after_present"]) is bool
    )


def retain(source, destination):
    try:
        if not stat.S_ISREG(source.lstat().st_mode):
            return "invalid"
        with source.open("rb") as stream:
            raw = stream.read(1025)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unknown"
    if len(raw) > 1024:
        return "invalid"
    try:
        receipt = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        return "invalid"
    if not valid_receipt(receipt):
        return "invalid"
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(receipt, separators=(",", ":")) + "\n")
    except OSError:
        return "write-failed"
    return "recorded"


if __name__ == "__main__":
    print(retain(Path(sys.argv[1]), Path(sys.argv[2])))
