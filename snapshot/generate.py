#!/usr/bin/env python3
"""Deprecated: frozen PAP snapshot generation is disabled."""

import sys


def main():
    print(
        "ERROR: snapshot generation is disabled.",
        file=sys.stderr,
    )
    print(
        "The PAP v0.1 snapshot is frozen. "
        "Use tools/verify_snapshot.py for integrity verification.",
        file=sys.stderr,
    )
    print(
        "Snapshot updates require an explicit owner decision "
        "and a controlled update process.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
