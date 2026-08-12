# [feature request] Support lazy webhook-backed inputs in EPE

> Draft only. This file is intended to be copied into a GitHub issue after review.

**What would you like to be added**:

EPE currently supports static inputs such as inline values and ConfigMaps. Add a webhook-backed input source so policies can obtain request-time data from an external service.

Webhook inputs should be loaded lazily with the following behavior:

- A webhook is called only after a profile and one of its rules match the request, and only when that matched rule references the corresponding input.
- Inputs referenced only by unmatched rules are not loaded.
- Reusing the same input during one policy evaluation should not cause repeated webhook calls.
- Webhook calls should not outlive request processing, and policy authors should be able to choose whether retrieval failures block or bypass evaluation.
- Existing inline and ConfigMap inputs keep their current behavior.

For example, a matched rule that uses external risk data should trigger its webhook input. A rule that does not match or does not use that data should not.

Policies should be able to use data returned by the webhook in existing EPE expressions and templates.

Generic inputs are not intended to store or return credentials. The capability should avoid disclosing raw request bodies, sandbox tokens, authorization headers, or other secrets to input webhooks.

The exact API shape, webhook protocol, and internal engine implementation are out of scope for this issue and can be discussed separately.

**Why is this needed**:

Inline and ConfigMap inputs are suitable for static configuration, but they cannot provide current external context such as risk scores, tenant state, or authorization metadata.

Calling every configured webhook eagerly would add latency, load, and a new failure dependency to requests that do not use the data. Lazy loading makes dynamic inputs practical while preserving the current behavior for policies that do not reference them.
