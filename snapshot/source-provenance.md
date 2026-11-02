# Snapshot Provenance

## Source

Repository: agent-federation/contract-builder

Commit:
c6ee64416c91ab56f9d8270114c8f8a8b9d2f608

PAP version: 0.1

## Purpose

This repository contains a frozen specification and conformance
material snapshot for an independent PAP verifier implementation.

It is intended to support Gate 3 interoperability validation.

## Included materials

See `manifest.json` for the exact file inventory and checksums.

## Excluded materials

The snapshot intentionally excludes:

- The first verifier implementation source.
- The first verifier implementation tests.
- Implementation reports.
- Runtime and package-manager configuration.
- First implementation PR discussions and review comments.

These exclusions preserve implementation independence.

## Authority

The RFC is the normative specification.
Other documents and fixtures provide supporting decisions,
clarifications and conformance examples.

## Integrity

File-level SHA-256 checksums are provided in `SHA256SUMS`.

## Local adaptation history

The corpus README at `pap/fixtures/pap-v0.1/README.md` was adapted in this
repository after the source snapshot was imported. The adaptation is recorded
in these commits:

- `b4d5851` (chore: fixed README): replaced instructions tied to the original
  TypeScript conformance harness with language-neutral guidance for independent
  implementations. The harness-specific command and implementation details
  were removed; the README now states that each independent implementation
  supplies its own test harness.
- `f34351b` (chore: fixed README): changed the `cases.json` description from a
  reference to the original TypeScript test consumer to a language-neutral
  description of the case index and expected outcomes.

These commits changed only the corpus README. They did not modify the normative
RFC, schemas, fixture package contents, or expected case outcomes. The adapted
README is included in the snapshot manifest by its current byte size and SHA-256
checksum. This local documentation adaptation is not a change to PAP normative
requirements.
