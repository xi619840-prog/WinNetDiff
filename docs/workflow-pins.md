# Workflow dependency pins

Direct Action references were resolved with the GitHub Git refs API against the official `github.com/actions/...` repositories on 2026-10-25. The workflow uses immutable commit SHAs rather than floating tags.

| Official repository | Resolved tag | Commit |
|---|---|---|
| `actions/checkout` | v7 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python` | v7 | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` |
| `actions/upload-artifact` | v7 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `actions/download-artifact` | v7 | `37930b1c2abaa49bbe596cd826c3c89aef350131` |
| `actions/attest` | v4 | `1e69f48acb82d1966a394da916b4c1698aa569d6` |

CI defaults to `contents: read`, uses `pull_request` rather than privileged fork execution, and disables persisted checkout credentials. Only the separate attestation job receives attestation/OIDC permission for provenance; the separate draft-release job receives contents-write permission. A repository-controlled `release` environment should require owner review. Configure that setting in GitHub before using tags to trigger releases.

A draft requires an explicitly selected workflow_dispatch input and the release environment; tags alone never create a draft. The reviewed version/source-digest gate precedes build and upload.

The provenance action may use internal/transitive dependencies. A direct SHA pin is not a claim that every dependency is locked or that an artifact is safe. Review Action source and upstream security changes when updating pins. GitHub's [secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use) describes the related controls.
