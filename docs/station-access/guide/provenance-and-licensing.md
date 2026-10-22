# Provenance and licensing

## What a reader can prove from a Station page

Zog exposes provenance where users encounter software, while retaining the evidence boundary for every claim. Source identity, license review, patch visibility and immutable launched-software identity are separate fields. A document existing in the repository, an archive notice bundle or a downloaded tarball is not by itself proof that **every** license or patch was reviewed.

## Generations: exact bound observations

Administrator Generation Detail is reached from a complete root-filesystem archive observation, bound to the exact mirror UUID, observation snapshot UUID, collection and rootfs digest. It rejects source archives and wrong-generation/superseded observation bindings. The page validates the artifact-bound notice bundle against that same digest and generation before deriving package source/license coverage.

Complete source evidence requires a SHA-256 and reviewed public upstream origin. License evidence requires expressions and declared/reviewed status for the recorded package components and exceptions, with no unresolved issues. Missing or invalid notice evidence yields **Unknown** package/coverage counts rather than invented zero totals. See [Generation provenance](../GENERATION-PROVENANCE.md).

## Patches and Source & license encounters

Generation package cards display Source & license from validated evidence. Patch state distinguishes a recorded positive patch count, a recorded zero count and unknown/not-integrated evidence. In the source contract, artifact-bound notices did not contain canonical patch rows, so the UI deliberately rendered **Patch evidence unavailable** rather than assuming no patches. A future build-record/build-trace join must respect the canonical snapshot and cannot infer patch rationale from an archive notice alone.

Application cards similarly must not pretend a runtime rootfs's license is the application's separate license. Until the controller supplies authoritative application-source/license identity, their correct state is unavailable, not a fabricated link. See [provenance encounters](../PROVENANCE-ENCOUNTERS.md).

## Workspaces: historical launched state

Workspace provenance uses immutable runtime history: exact runtime/application identities, desktop/client role and the generation recorded at launch. Changing a current application declaration or generation selection cannot rewrite the history. Matching rootfs archive observations resolve to a unique digest or explicitly report unresolved/conflicting/unknown evidence. Ordinary Workspace owners see the runtime evidence they are authorized to access, while administrative archive locators and Generation Detail remain protected.

See [Workspace provenance](../WORKSPACE-PROVENANCE.md) and [application-software detail](../APPLICATION-SOFTWARE.md).

## Frontend notices and packaging

The frontend build retains independently reviewed third-party notice evidence, exact reviewed package bytes and a generated notice-linked bundle. Build-time dependencies are not automatically browser-runtime modules; conversely, an outer package's permissive license is not license proof for embedded vendor code. Changing frontend dependencies or emitted modules requires renewed review.

Immutable application artifacts retain their own notices and source references. The build must not export private credentials, and runtime access to an immutable notice is not evidence of license-completeness certification. See [frontend license review](../FRONTEND-LICENSE-REVIEW.md).

### Exact sources and verification limits

- [Generation source/license completeness](../GENERATION-PROVENANCE.md)
- [Source, license and patch states](../PROVENANCE-ENCOUNTERS.md)
- [Workspace runtime history and resolution](../WORKSPACE-PROVENANCE.md)
- [Application software inspection](../APPLICATION-SOFTWARE.md)
- [Frontend notices and build review](../FRONTEND-LICENSE-REVIEW.md)

This chapter integrates the current source contracts for readers but does not claim a deployed runtime's evidence is complete without observing that deployed runtime.
