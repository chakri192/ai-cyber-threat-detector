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

Real coverage as of the last local measurement: **66%** across
`api/`, `inference/`, `shared/`, `ingest/` (118 tests). CI's
`--cov-fail-under` gate tracks this, set with a margin below the local
number rather than pinned exactly to it. The thinnest remaining areas:

- `api/kafka_sink.py`'s `run_sink()` consumer loop itself (the
  validate-before-ORM logic it calls, `process_batch`, is directly
  tested — the outer poll/commit/backoff loop is only reachable through
  a live Kafka consumer).
- `inference/stream_processor_faust.py`'s `process_traffic` agent body
  — the core detection pipeline is exercised end-to-end by
  `tests/test_load.py` against a real (fakeredis-backed) correlator, but
  not unit-tested branch-by-branch inside the Faust agent itself.
- `shared/data_access.py`'s polling loop internals beyond the
  config-loading and health-flagging paths already covered.

## Dependency scanning

A one-time `pip-audit` sweep brought the full dependency tree to zero
known vulnerabilities. [Dependabot](.github/dependabot.yml) now runs
weekly against both the `pip` and `github-actions` ecosystems so that
state doesn't silently rot the next time a new CVE is disclosed against
something already pinned here.

## K8s manifest validation

Every manifest in `k8s/*.yaml` is checked with
[`kubeconform`](.github/workflows/ci.yml) on every CI run
(`-ignore-missing-schemas` skips CRDs with no public schema — Cilium
`CiliumNetworkPolicy`, Kyverno `ClusterPolicy`, Prometheus
`ServiceMonitor`). This confirms every manifest is structurally valid
Kubernetes YAML; it does not confirm runtime enforcement (see below).

## Secret rotation

- `TSOC_JWT_SECRET` and `REDIS_PASSWORD`: rotate every 90 days via Vault
  (see [README](README.md#security-hardening-post-audit-remediation)).
  `TSOC_JWT_SECRET` must be ≥32 bytes (RFC 7518 §3.2 minimum for HS256);
  PyJWT raises `InsecureKeyLengthWarning` if it's shorter.
- DLQ overflow: if a local-disk DLQ fallback exceeds its configured max
  size, alert on-call and rotate manually.

## Genuinely out of scope here

These require real infrastructure this sandbox/CI environment doesn't
have, and are not claimed as verified:

- **Live cluster enforcement.** `kubeconform` proves every manifest is
  schema-valid; it cannot prove a `NetworkPolicy` actually blocks the
  traffic it claims to at runtime, or that Kyverno's `ClusterPolicy`
  actually rejects an unsigned image on a real admission request. That
  needs a live Kubernetes cluster with Cilium/Kyverno installed.
- **Real TLS certificate issuance** for any of the `*.tsoc.local`
  hostnames referenced in configuration — those are placeholders for a
  real domain and a real CA (or ACME) this project doesn't own.
- **A genuinely offline/air-gapped signing key**, as opposed to the
  keyless Sigstore flow above (which depends on reaching the public
  Fulcio/Rekor services from the CI runner). `scripts/sign_manifest.py`
  documents this alternative and correctly refuses to run without a real
  persistent key rather than fabricate one.
