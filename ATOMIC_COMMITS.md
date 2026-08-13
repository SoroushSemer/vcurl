# vcurl Atomic Commit Log

This repository was constructed using **Conventional Commits** in a sequence of small, focused atomic commits.

| Commit Hash | Type / Scope | Message & Engineering Focus |
| :--- | :--- | :--- |
| `d081c98` | `test(suite)` | Add unit test coverage for LLM evals, extended SSRF rules, vault resolution, and wizard integrations |
| `94167ee` | `feat(evals)` | Implement LLM security evaluation framework (`vcurl eval`) and 10-point benchmark matrix |
| `d319793` | `feat(video)` | Expand video to 42s social edition, add dedicated metrics slide, and fix UI audit table column gaps |
| `e764f16` | `docs(metrics)`| Add empirical security benchmarks and performance metrics to README and marketing video slides |
| `0efed5d` | `refactor` | Clarify vcurl JIT secret resolution flow, standardize on secrets terminology, and highlight vault connectors UI |
| `c3bc18d` | `refactor` | Replace production API keys terminology with Secrets and Personal Access Tokens |
| `11da581` | `feat(video)` | Update marketing video to 30s duration with Outfit display typography and 5-phase story soundtrack |
| `20dbedb` | `feat(video)` | Add 15-second HyperFrames marketing video composition and keyframe renderer |
| `36056c4` | `docs(readme)`| Clarify Zero-Environment-Leakage security model and out-of-process encrypted vault usage |
| `57070f2` | `test(vault)` | Add unit test coverage for secret isolation and encrypted vault provider |
| `5b47267` | `feat(ui)`    | Update Credential Manager UI to store raw secrets directly into local encrypted vault out of process |
| `8b35178` | `feat(vault)` | Prioritize encrypted local vault and OS Keyring over process environment variables |
| `e81af9a` | `feat(sec)`   | Implement AES-256 Encrypted Local Vault and OS Keyring providers for secret isolation |
| `8523e05` | `docs(readme)`| Update documentation with 1-command setup wizard, Web UI dashboard, pluggable secret providers |
| `f8a4d44` | `test(feat)`  | Add unit test suite for secret providers, audit logging, integrations, and provider chaining |
| `a1ef69c` | `feat(core)`  | Integrate pluggable secret providers, audit logging, and setup/ui commands into vcurl core and CLI |
| `70822b2` | `feat(ui)`    | Add modern local Web UI security dashboard and REST API server |
| `2d683b8` | `feat(integ)` | Implement interactive setup wizard for AI tools (Claude, Codex, Antigravity, LangChain, AutoGen, Cursor) |
| `83ac25c` | `feat(audit)` | Implement real-time outgoing request audit logger and tracker |
| `b84ebb8` | `feat(prov)`  | Add pluggable secret provider interface and cloud integrations (AWS, Vault, GCP, Azure) |
| `38d8938` | `test(suite)` | Add unit test coverage for SSRF rules, vault alias resolution, and response sanitization |
| `95ce16a` | `feat(cli)`   | Add command-line interface and stdin JSON payload support for agent IPC |
| `dbb2f81` | `feat(core)`  | Implement execute_vcurl entry point, payload serialization, and redirect loop safety |
| `00b0e4b` | `feat(sanit)` | Implement response header stripping and body JSON parsing |
| `1249d7f` | `feat(ssrf)`  | Implement URL validation, IP range restrictions, and DNS-pinned connection transport |
| `2dae66e` | `feat(vault)` | Implement credential alias resolution engine and environment vault mapping |
