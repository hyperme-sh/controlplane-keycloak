# Broker patch canary contract

Owner: `hyperme-sh/controlplane-keycloak#39`. Infra #1967 owns production
adapter registration and deployment bindings. Billing remains disabled. This
package neither deploys a process nor activates a client or provider.

`keycloak/canary_contract.py` validates inputs collected by the authenticated
Infra owner adapter. It checks exact serving revisions, bounded observation age,
issuer and endpoint continuity, code/PKCE plus refresh support, and retention of
all baseline signing keys without key-ID reuse for different key material.
The adapter must establish serving revision and routing from trusted deployment
metadata; a candidate's self-report is insufficient. Missing inputs fail closed.
Do not persist tokens, passwords, private keys, raw claims or session identifiers
in reports. Results contain only revision/key fingerprints and boolean outcomes.

The declared public clients are `controlplane-frontend` and `s3rch-web`. Each
has a separate bounded code/PKCE login and refresh case. Consumer verification
must check signature, algorithm, issuer and expiration before calling
`session_continuity`; that function additionally requires the declared client,
subject and unchanged session. Client configuration must prohibit direct grants,
implicit grants, service accounts, broad scope and wildcard callbacks.

Realm compatibility is conservative: declared client contracts and all realm
fields except display metadata must remain equal. Unknown realm fields are not
silently accepted. Engine/database upgrades require their own qualified schema
baseline and safe recovery plan; this contract cannot prove a database downgrade
safe. Never restore an old realm export over the live signing/session store.

Infra's durable rollout journal and resource claim must surround each handoff.
Before starting the desired process, the adapter must freshly verify the old
writer is fenced, no unexpected writer exists, signing and sessions retain the
same owner store, and the current schema supports the requested revision. After
an interrupted start, inspect actual writers and verify the desired process;
do not start another writer. Recovery reverses source/destination and repeats
the same checks. An unavailable fence or unsafe schema blocks both progression
and automatic rollback. No traffic split is permitted for this single writer.

## Qualification and limits

Offline tests use explicit dictionary doubles for deployment observations and
claims; they do not verify cryptographic signatures or establish deployed
readiness. The existing CI-only disposable Keycloak fixture runs real code/PKCE
login, cryptographically verified access tokens, refresh and wrong-client
refusal for both declared clients. It applies a compatible realm metadata patch,
reverts it, then stops and restarts the same private container and confirms
signing keys and refresh sessions survive the fenced process interruption.
Its persistence is disposable H2, not production PostgreSQL. Its revision labels
are fixture labels, not a claim of two deployed binaries. This qualifies the
owner protocol against the current pinned engine; engine skew and production
PostgreSQL schema changes require separate measured qualification.

The existing `keycloak-native` Infra nightly registration runs
`scripts/check-native.sh`, which discovers these cases in source and extracted
archives. PR CI runs the same scoped disposable broker check automatically.
Agents must not run or dispatch it by hand. Only unit/contract tests run locally.

Remaining Infra #1967 bindings: authenticated candidate/baseline attribution,
declared synthetic identity and credential custody, production PostgreSQL schema
qualification, durable writer fencing, private adapter entrypoint, measured
observation thresholds and scheduled owner registration. Missing bindings are
unavailable coverage. No live accounts, fixtures, traffic or production switches
are changed by this slice.
