# agentio

---

<img src="logo/agentio.png" alt="agentio logo" width="250">

---

Agentio is a traffic security control system for agents, sandboxes, and other untrusted or compromise-prone workloads.

Built on a modified Istio foundation, agentio extends service mesh capabilities to agent traffic governance, which provides:

- **Zero Trust Security** — no implicit trust for any agent or workload; every request is authenticated, authorized, and policy-checked.
- **Traffic Control** — fine-grained governance over Inbound/Outbound traffic, enabling precise access control and policy enforcement.
- **Observability** — Provides metrics, distributed tracing, and access logging for all agent traffic, enabling real-time monitoring, auditing, and security analysis.

## Why Not Just Istio?

Istio was designed for a world of trusted microservices — where the challenge is routing, resilience, and observability across known, well-behaved services. Its policies are largely server-side oriented: services expose endpoints, and the mesh governs how traffic flows *between* them.

Agent workloads break this assumption. An agent may execute arbitrary code, call unpredictable external services, or be compromised entirely — the risk isn't just *between* services, but *at the agent itself*. What matters most is not how traffic flows between two trusted parties, but whether the agent's inbound and outbound traffic can be trusted at all.

Agentio is built on Istio, but shifts the center of gravity from the server to the client — from governing service-to-service communication, to governing what a single, potentially untrusted agent sends and receives. It's a different question, and it demands a different design.
