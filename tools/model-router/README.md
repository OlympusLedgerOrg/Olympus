# Local model router

Recommend a cost-aware execution path without sending repository content to a hosted service:

```powershell
node tools/model-router/route.mjs "trace callers of the authentication middleware"
```

The router asks local Ollama when available. Hard-coded repository rules always route cryptography, authentication, authorization, proofs, SMT, migrations, ledger, secrets, and security work to Codex with high reasoning; Claude is suggested as an independent reviewer. If Ollama is unavailable, it falls back to those rules.

This prints a recommendation only. It does not authenticate providers, select a paid model, or spend subscription/API credits.
