# SOC Platform Security Architecture

## 1. Zero-Trust Ingestion & Data Diode Enforcement
This platform is designed to operate strictly behind a unidirectional network data diode.
- **Read-Only Access:** The ingestion layer (`tail_to_redpanda.py`) exclusively reads local metadata logs via `tail -F`. It possesses absolutely no capability to transmit network packets back to the monitored environment.
- **No Decryption:** TLS inspection is explicitly forbidden. Threat inference relies entirely on unencrypted metadata (JA3 fingerprints, SNI, byte distributions).
- **Strict Validations:** All incoming logs are sanitized via `jsonschema`. Malformed payloads are synchronously dumped to `dead_letter_events`, preventing buffer overflows or injection attacks against the ML pipelines.

## 2. ML & Correlation Hardening
Machine Learning models in Python represent a significant attack surface (e.g., Pickle deserialization, OOM crashes).
- **Graceful Fallbacks:** If a Torch artifact fails cryptographic hash verification or platform constraints (ARM64 incompatibility), the pipeline defaults to a deterministic Mock ML classifier rather than crashing.
- **Bounded State:** The `IncidentCorrelator` explicitly limits its tracking dictionary to `max_tracked_ips=5000` with periodic LRU eviction and 5-minute time horizons. This prevents algorithmic complexity (CWE-400) attacks where an adversary spams millions of spoofed IPs to exhaust SOC memory.

## 3. Container Isolation
- **Non-Root Execution:** The provided `Dockerfile` explicitly creates and enforces `USER soc_user (UID:1000)`.
- **Minimal Surface:** The image strips unnecessary package managers (`apt-get` cache cleared).
- **Network Segmentation:** Redpanda brokers require split internal/external listeners to ensure isolated container-to-container backend networks vs. frontend dashboard interactions.

## 4. Subprocess Execution Guardrails
The platform does not rely on active response scripts. There is exactly one subprocess call (`tail -F` in ingestion), which uses safe argument vectors (`['tail', '-F', file_path]`) explicitly preventing shell interpolation or command injection (CWE-78).

---

# Security posture

The section above describes design intent. This section is a running,
honest account of what's actually *verified*, how, and what still needs
real infrastructure this project doesn't have — replacing gaps that were
previously only disclosed in commit messages / PR discussion with a
durable pointer any reviewer will actually find.

## Verifying a model artifact's provenance

Every CI run on `main` ([workflow](.github/workflows/ci.yml)) signs each
tracked model file (`models/*.pt`) using **cosign's keyless mode**: the
runner exchanges its GitHub Actions OIDC token for a short-lived
certificate from the public Sigstore Fulcio CA, signs the blob, and the
signature + certificate + a public Rekor transparency-log entry are
bundled into `models/<name>.pt.cosign.bundle`. That bundle is verified
again in the same job and uploaded as part of the `security-reports`
build artifact — it is not committed to the repository (it's a
per-build attestation, not a static file).

To independently verify a specific run's signature yourself:

1. Download `models/*.cosign.bundle` from that run's `security-reports`
   artifact (Actions tab → the run → Artifacts).
2. Install [cosign](https://github.com/sigstore/cosign).
3. Run:

   ```bash
   cosign verify-blob \
     --bundle cnn_dga.pt.cosign.bundle \
     --certificate-identity-regexp "^https://github\.com/chakri192/NeuralSOC/\.github/workflows/ci\.yml@.*$" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     models/cnn_dga.pt
   ```

A successful verification proves that exact file's bytes were produced
and attested by this repository's own CI workflow, on a specific commit
— independent of any secret this project would otherwise have had to
provision and protect.

This replaced an earlier, secret-conditional `cosign verify-blob` step
that never actually ran (no key was ever configured) and a stale
`models/cnn_dga.pt.sig` file left over from before real signing existed,
which was a plain SHA-256 hex digest, not a signature.

## Test coverage

Real coverage as of the last local measurement: **72%** across
`api/`, `inference/`, `shared/`, `ingest/` (132 tests, including a real
Kafka-message → DB → authenticated-API integration suite in
`tests/integration/`). CI's `--cov-fail-under` gate tracks this, set
with a margin below the local number rather than pinned exactly to it.

`api/kafka_sink.py`'s `run_sink()` consumer loop and
`inference/stream_processor_faust.py`'s `process_traffic` agent — both
previously only exercised end-to-end via `tests/test_load.py`'s real
burst test, with no branch-level unit coverage of their own — are now
driven directly: `run_sink()` via a fake `KafkaConsumer` whose `poll()`
sends the test process a real `SIGINT` once its scripted messages are
exhausted (the loop has no other externally-settable stop condition);
`process_traffic` via Faust's `Agent.fun`, which reaches the original
undecorated async function so it can be called with a fake async
stream, no live Faust app or broker required.

The thinnest remaining area is `shared/data_access.py`'s polling-loop
internals beyond the config-loading and health-flagging paths already
covered.

## Dependency scanning

A one-time `pip-audit` sweep brought the full dependency tree to zero
known vulnerabilities. [Dependabot](.github/dependabot.yml) now runs
weekly against both the `pip` and `github-actions` ecosystems so that
state doesn't silently rot the next time a new CVE is disclosed against
something already pinned here.

## K8s manifest validation and live enforcement

Every manifest in `k8s/*.yaml` is checked with
[`kubeconform`](.github/workflows/ci.yml) on every CI run
(`-ignore-missing-schemas` skips CRDs with no public schema — Cilium
`CiliumNetworkPolicy`, Kyverno `ClusterPolicy`, Prometheus
`ServiceMonitor`). This confirms every manifest is structurally valid
Kubernetes YAML; it does not by itself confirm runtime enforcement.

Runtime enforcement of the two highest-stakes manifests has been
verified directly against a real local cluster (`kind` + Cilium as the
CNI, matching this repo's `CiliumNetworkPolicy` usage, + Kyverno
installed via its official Helm chart) — not just schema-checked:

- **`k8s/network-policies.yaml`**: from a pod labeled
  `app: tsoc-stream-processor` with the real policy applied, a raw TCP
  connection to `169.254.169.254:443` (the cloud-metadata range this
  policy's `except` clause excludes — the exact class of bug the
  original audit found, where a "deny" policy was actually an unrestricted
  allow rule to this range) timed out — silently dropped at the CNI layer
  — while the same pod reached `1.1.1.1:443` (a real public IP, *not* in
  any excluded range) successfully, from the same node, same code path,
  moments apart. Default-deny was confirmed separately: an unlabeled pod
  could not reach a plain target pod at all, and only a pod labeled to
  match `ingress-nginx` (in a namespace labeled accordingly) could reach
  the `tsoc-api`-labeled pod's port 8000 — an unlabeled pod could not.
- **`k8s/kyverno-verify.yaml`**: applying a pod with a mutable image tag
  and no `imagePullPolicy: Always` into the `tsoc` namespace was rejected
  by the admission webhook with both rules' exact validation messages
  (`require-digest-pin`, `require-signed-images`). The identical pod spec
  applied to `kube-system` was allowed — confirming the namespace-scoping
  fix actually prevents the cluster-wide outage the original,
  cluster-wide version of this policy would have caused (CoreDNS,
  ingress-nginx, cert-manager, and the CNI itself all run unpinned,
  non-`Always` images there). A pod using a real digest reference and
  `imagePullPolicy: Always` in `tsoc` was allowed.

This was a one-time interactive verification (the cluster is not
persisted — spinning up kind+Cilium+Kyverno on every CI run would be
slow and is not currently wired in), reproducible with: `kind create
cluster` (CNI disabled) → `cilium install` → apply
`network-policies.yaml` + `cilium-identity-policy.yaml` → `helm install
kyverno` → apply `kyverno-verify.yaml` → the connectivity/admission
tests described above.

## Internal TLS (no public domain required)

`k8s/ingress.yaml` previously pointed at `letsencrypt-prod` for
`api.tsoc.local` — a hostname that was never going to pass ACME
validation, since it isn't a real, publicly-resolvable domain. Rather
than requiring one, `k8s/cert-manager-internal-ca.yaml` sets up a
cluster-local CA (a one-time self-signed bootstrap issuer signs a root
CA certificate; a second `ClusterIssuer` of kind `ca` issues real
workload certificates from that root), and the ingress now references
that issuer instead. This is the architecturally correct choice here,
not a fallback: this platform sits behind a data diode and is never
meant to be internet-facing, so a publicly-trusted certificate is the
wrong tool regardless of whether a public domain is available.

Verified against a real cert-manager installation (Helm chart, a fresh
`kind` cluster): the bootstrap issuer, root CA certificate, and workload
issuer all reached `Ready`, and a real `Certificate` requested for
`api.tsoc.local` was issued — `kubectl get secret ... | openssl x509
-noout -issuer -ext subjectAltName` shows `issuer=CN=tsoc-internal-ca`
and `DNS:api.tsoc.local`, a genuine, cluster-trusted X.509 certificate.

## Secret rotation

- `TSOC_JWT_SECRET` and `REDIS_PASSWORD`: rotate every 90 days via Vault
  (see [README](README.md#security-hardening-post-audit-remediation)).
  `TSOC_JWT_SECRET` must be ≥32 bytes (RFC 7518 §3.2 minimum for HS256);
  PyJWT raises `InsecureKeyLengthWarning` if it's shorter.
- DLQ overflow: if a local-disk DLQ fallback exceeds its configured max
  size, alert on-call and rotate manually.

## Genuinely out of scope here

- **A genuinely offline/air-gapped signing key**, as opposed to the
  keyless Sigstore flow above (which depends on reaching the public
  Fulcio/Rekor services from the CI runner or verifier). `scripts/sign_manifest.py`
  documents this alternative and correctly refuses to run without a real
  persistent key rather than fabricate one.
- **A persistent, CI-integrated live cluster.** The NetworkPolicy/Kyverno
  enforcement described above was verified interactively against a real
  local cluster, not asserted from schema validation alone — but that
  cluster isn't kept running or wired into CI, so a manifest change after
  this was written isn't automatically re-verified at that level (schema
  validation via `kubeconform` still runs on every push).
