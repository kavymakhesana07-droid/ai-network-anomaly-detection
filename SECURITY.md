# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email:** security@anomaly-detection.example.com

**PGP Key:** Available at https://github.com/kavymakhesana07-droid.gpg

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Severity | Initial Response | Fix Target |
|----------|------------------|------------|
| Critical | 24 hours         | 72 hours   |
| High     | 48 hours         | 1 week     |
| Medium   | 1 week           | 2 weeks    |
| Low      | 2 weeks          | 1 month    |

## Security Measures

### Code Security
- Static analysis (Bandit, Semgrep) in CI
- Dependency scanning (Dependabot + Grype) in CI
- Secret scanning (GitLeaks, TruffleHog) in CI
- SAST/DAST in CI pipeline
- SBOM generation (Syft) for every release

### Container Security
- Non-root containers (UID 10001)
- Read-only root filesystem
- Dropped capabilities (ALL dropped, minimal added)
- No secrets in images
- Distroless/base images where possible

### Runtime Security
- Network policies (default deny)
- Pod security standards (restricted)
- Runtime monitoring (Falco)
- Admission control (Kyverno/OPA)

### Secrets Management
- No secrets in code/images
- External Secrets Operator + Vault/SealedSecrets
- Rotation policies for all secrets
- Audit logging for secret access

### Supply Chain
- SLSA Level 3 target
- Signed images (Cosign + Rekor)
- SBOM for every release (Syft)
- Verified dependencies (Sigstore/fulcio)

## Vulnerability Disclosure

We follow Coordinated Vulnerability Disclosure (CVD):
1. Reporter submits vulnerability
2. We acknowledge within 24h
3. We investigate and develop fix
4. We coordinate disclosure timeline
3. We publish advisory after fix

## Bug Bounty

Currently no formal bug bounty program. Responsible disclosure acknowledged in:
- Security Hall of Fame (README)
- Release notes
- Annual security report

## Contact

**Security Team:** security@anomaly-detection.example.com
**PGP:** https://github.com/kavymakhesana07-droid.gpg