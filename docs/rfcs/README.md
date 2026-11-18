# RFCs

This directory records the design decisions behind the reusable security
workflows and the scanners they run: what each scanner checks, when it runs,
what fails a pull request, and why. Open an issue or comment on an RFC's pull
request to discuss it.

## Index

- [RFC0002: Trivy Container Image Scanning](./RFC0002-Trivy-Image-Scanning.md)

## When to write an RFC

Write an RFC when a change:

- adds a scanner or a new target for an existing one;
- changes which changes trigger a scan, or which findings fail a run;
- runs code from the scanned repository, or changes what a pull request from
  another repository can do.

## Format

Name the file `RFC0003-Some-Short-Title.md` and link it in the index above.
Start it with the title and three header lines:

```markdown
# RFC0003: Some Short Title

**Author:** Full Name
**Date:** 2026-11-13
**Status:** Draft
```

`Status` is one of Draft, Implemented or Obsolete.

Use the sections that apply: Overview, Motivation, Goals, Non-goals, Proposed
Design, Trust Boundaries, Alternatives Considered, Implementation Plan,
Acceptance Criteria, Open Questions and Revision History. End each alternative
with whether it was rejected and why.
