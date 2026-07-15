# Security Policy

## Supported Versions

Agentio is based on Istio 1.29.x. Security fixes are applied to the latest
release branch. Older branches are not actively maintained.

| Version | Supported |
|---------|-----------|
| 1.29.x  | ✅ Yes    |
| < 1.29  | ❌ No     |

## Reporting a Vulnerability

If you discover a security vulnerability in agentio, **please do not file a
public GitHub issue**.

Instead, report it privately via one of the following channels:

- **GitHub Security Advisory**: Open a private vulnerability report at
  https://github.com/openkruise/agentio/security/advisories/new
- **Email**: Send a detailed report to `security@openkruise.io`

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if applicable)
- Any suggested mitigations or fixes

We aim to acknowledge receipt within **3 business days** and provide an
initial assessment within **10 business days**.

## Upstream (Istio) Vulnerabilities

Agentio inherits code from Istio. Vulnerabilities in upstream Istio that
affect agentio should also be reported to the
[Istio Security Working Group](https://istio.io/about/security-vulnerabilities/).
We monitor Istio security bulletins and apply relevant patches to agentio
as they become available.

## Security Bulletins

Security advisories for agentio are published via
[GitHub Security Advisories](https://github.com/openkruise/agentio/security/advisories).
