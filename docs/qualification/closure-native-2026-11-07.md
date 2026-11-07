# Native closure tooling qualification

Issue #9's tooling and offline regressions were adopted in #11, merged at
`98e7598c816a07fe81fa928d2fa3a35cfc6b4c02`. The remaining native provisioning
regression now lives in tests_native, with its original source path and SHA-256
in provenance.json. Historical auth tests are provenance; runtime provisioning
belongs to this repository.

The offline source and verified archive suites each pass 140 cases without skips.
The separate native source and verified archive runs each pass the transferred
integration case, creating independent disposable Keycloak realms. The fixture
uses a digest-pinned Keycloak 26.5 image, the local Unix Docker socket, random
credentials, ephemeral loopback HTTP and container/anonymous-volume cleanup.

The native case checks disabled clients reject token issuance, repeated setup is
idempotent, only selected human and AI subjects gain the closure role/audience,
protected service identities cannot become operators, and default-role/group
escalation is refused. The immutable identity consumer at
`5aeff3d2c00568f39ca6e8b75c7e63883d3a510b` validates the selected signed tokens
and rejects the unselected human. Actual realm API calls prove the reader can
read but cannot disable/logout/delete, while the worker can act on the fixture
user; neither credential can administer clients or become a closure operator.

Only disposable fixtures are activated. No deployed realm, production provider,
existing credentials, tag or release is changed. Native acceptance does not
establish deployed closure activation. The runtime contract is unchanged; the
candidate archive digest is refreshed for its added qualification files.
