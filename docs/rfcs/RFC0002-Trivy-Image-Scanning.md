# RFC0002: Trivy Container Image Scanning

**Author:** Ciprian Goea
**Date:** 2026-11-16
**Status:** Draft

______________________________________________________________________

## Overview

This RFC proposes building the container images a repository defines and
scanning them with [Trivy](https://trivy.dev/), alongside the filesystem scan
this repository already runs. The implementation is in
[#56](https://github.com/ROCm/rocm-security-gh/pull/56).

______________________________________________________________________

## Motivation

A ROCm image's vulnerabilities come mostly from the packages its `RUN` steps
install. The filesystem scan checks the Dockerfile for misconfigurations, but
it cannot see those packages.

Building an image is also the first time the baseline runs code from the
scanned repository, so the trust rules must be settled before the feature
ships.

______________________________________________________________________

## Goals

- Scan the container images a repository builds, as the pull request would
  build them.
- Rebuild an image only when one of its inputs changes.
- Let a repository build an image the way its own CI does.
- Keep existing callers unchanged until they opt in.
- Never run a pull request's commands directly on the runner when the pull
  request comes from another repository.

## Non-goals

- Scanning images published to a registry.
- Detecting a new upstream base image behind an unchanged tag in changed mode.
- Caching image builds between runs.

______________________________________________________________________

## Proposed Design

### Image targets

A caller selects targets with a new `trivy_scan_type` input: `filesystem` (the
default), `image`, or `filesystem,image`. Images are listed in a new
`trivy_images` input:

```yaml
trivy_scan_type: filesystem,image
trivy_images: |
  - dockerfile: docker/Dockerfile.ubuntu
  - dockerfile: docker/Dockerfile.dev
    name: rocm-dev
    build_commands: |
      ./tools/generate-docker-context.sh
      docker build --file "$SCANNER_TRIVY_DOCKERFILE" --tag "$SCANNER_TRIVY_IMAGE" .
```

Each entry needs a repository-relative `dockerfile`. `name` defaults to a slug
of the Dockerfile path, and `image`, the local tag, defaults to
`security-scan/<name>:ci`.

### Image build

On a pull request the image that matters is the one the pull request would
produce, and it is not in any registry yet. Each image is built in the job and
then scanned with `trivy image`. The default build is
`docker build --file <dockerfile> --tag <image> .` from the repository root.

An entry's `build_commands` replace that build. They run in bash from the
repository root with `SCANNER_TRIVY_IMAGE` and `SCANNER_TRIVY_DOCKERFILE` set,
and must leave `SCANNER_TRIVY_IMAGE` in the local Docker image store. This lets
an image that needs generated context, build arguments or a wrapper script be
built exactly as its own CI builds it.

Each image gets its own matrix leg and check run, `trivy-image-<name>`, so
builds run in parallel with each other and with the filesystem scan, and a
failure names its image. Image legs get a 90-minute timeout, and
`timeout_minutes` raises it as it does for any other leg.

### Gating

An image scan fails on any finding at or above `severity_threshold`. Image
findings belong to packages in the built image, not to files in the change, so
the filesystem scan's changed-directory rule does not apply. The pinned binary,
default scanners, environment and config handling used by the filesystem scan
apply unchanged.

### Change detection

In changed mode an image is built and scanned only when the event changed one
of its inputs:

- its Dockerfile;
- the repository-root `.dockerignore` or `<Dockerfile>.dockerignore`;
- Trivy's config or ignore file;
- a path the Dockerfile reads from the build context: the local sources of
  `COPY` and `ADD`, and the bind mounts of `RUN --mount`. A directory or glob
  source covers everything below it.

The Dockerfile is parsed for this. The parser handles the JSON and plain forms
of `COPY` and `ADD`, line continuations with the `# escape=` directive, and
heredocs. It ignores `COPY --from=` stage copies and `ADD` from URLs or Git
remotes. A source the parser cannot map to paths, such as one containing a
variable, counts as the whole repository. An entry with `build_commands`
chooses its own build context, so any change rebuilds it.

`scan_mode: all` builds and scans every image.

______________________________________________________________________

## Trust Boundaries

### Code from the scanned repository

The filesystem scan and the other scanners read the scanned repository but
never run its code. An image build runs it: the Dockerfile's `RUN` steps, and
any `build_commands`.

### Pull requests from other repositories

`build_commands` run directly on the runner. On a pull request from another
repository, an image with `build_commands` is skipped with a warning, and push
and scheduled runs scan it.

A pull request counts as coming from another repository when its head
repository differs from the base repository, or when its head repository has
been deleted. The check covers both `pull_request` and `pull_request_target`
events.

The default `docker build` still runs for those pull requests. It runs the
pull request's `RUN` steps inside build containers rather than as commands on
the runner.

______________________________________________________________________

## Alternatives Considered

### Pull published images from a registry

A pull request's image is not published, so the registry image is the previous
release rather than the change.

Rejected. Monitoring published images can be done by a scheduled job outside
this workflow.

### Rely on the filesystem scan of the Dockerfile

The filesystem scan already checks Dockerfiles for misconfigurations. It cannot
see the packages that `RUN` steps install, which hold most of an image's
vulnerabilities.

Rejected. It does not cover what image scanning is for.

### Apply the changed-directory gating to image findings

Image findings name packages and layers inside the image, not repository
files, so there is nothing to compare with the changed directories.

Rejected. An image scan gates on every finding.

### Rebuild every image on every change

Image builds can take tens of minutes, and most changes do not touch an image.

Rejected. The check would be too slow to require.

### Rebuild only when the Dockerfile changes

A change to a script or requirements file that the Dockerfile copies changes
the image without touching the Dockerfile.

Rejected in favor of parsing the Dockerfile's build-context inputs.

### Build all images in one job

One slow or failing build would hold up or hide the others, and the check run
would not say which image failed.

Rejected in favor of one leg per image.

### Run `build_commands` before `docker build`

Callers whose build needs arguments, a different context or a wrapper script
would have to work around the default build.

Rejected. `build_commands` replace the build.

______________________________________________________________________

## Implementation Plan

1. Add `trivy_scan_type` and `trivy_images`, with one matrix leg per image.
1. Build images in the job, with `build_commands` replacing the default build.
1. Detect image input changes by parsing the Dockerfile.
1. Skip images with `build_commands` on pull requests from other repositories.
1. Document the inputs in the README.

All five steps are in #56.

______________________________________________________________________

## Acceptance Criteria

- Existing callers are unchanged: `trivy_scan_type` defaults to `filesystem`.
- Each listed image runs as its own `trivy-image-<name>` check.
- In changed mode, an image is built only when one of its inputs changed.
- An image scan fails on any finding at or above the threshold.
- An image with `build_commands` never builds on a pull request from another
  repository.
- `python -m pytest security_scanners` covers target planning
  (`trivy_targets_test.py`), Dockerfile parsing (`DockerfileSourcesTest`,
  `DockerfileChangedTest`), image builds and scans (`BuildTrivyImageTest`,
  `RunTrivyImageTest`) and the untrusted pull request check
  (`UntrustedPullRequestTest`, `MainTest`).

______________________________________________________________________

## Open Questions

- Should the default `docker build` also be skipped on pull requests from other
  repositories, per entry or per workflow, for callers that do not want those
  `RUN` steps to execute?
- A new upstream base image behind an unchanged `FROM` tag is not detected in
  changed mode. Is relying on pinned base images and scheduled `scan_mode: all`
  runs enough, or should changed mode resolve the base image digest?
- Should image builds use a cache keyed by the image's inputs, and how would
  one pull request's layers be kept out of another's build?

______________________________________________________________________

## Revision History

- 2026-11-16: Initial draft (Ciprian Goea)
