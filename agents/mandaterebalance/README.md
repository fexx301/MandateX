# mandaterebalance

A BNB Chain seller agent workspace scaffolded by `bag init` (bnbagent-studio).

Milestone 1 implements a deterministic PancakeSwap V3 rebalancing reference
agent. It signs only eligible bounded mandates and submits clearly labelled
simulation-ready or policy-refusal receipts; it does not move LP liquidity yet.
All protocol evidence is pinned to the canonical hash of a target block exactly
two blocks behind the observed BSC head, with RPC chain verification, official
deployment/code checks, pool liquidity evidence, owner-drift checks, post-read
expiry validation, and sanitized fail-closed RPC errors. Two blocks is a
consistency buffer, not finality.

The strict `mandatex.*.v1` evidence and receipt schema is frozen after this
revision. The product remains simulation-only and has not been deployed. Before
liquidity execution is added, ownership and ERC-721 approval must be checked
again immediately before simulation and submission.

The readiness suite now exercises the public A2A card and JSON-RPC boundary on
an ephemeral loopback port as well as the deterministic policy and read-only
BSC testnet snapshot/codec smoke.

- `app/agent/` — the valuable Agent + SOLE on-chain signer (TypeScript, `src/`).
- `.studio/` — secrets (encrypted keystore + .env.local); NEVER commit it.
- `bag dev` — run the agent locally; `bag doctor` — readiness checks.
- `bag deploy --provider aws` — deploy to AWS Bedrock AgentCore (uses the self-rendered `agentcore/` descriptor).

In Claude Code / Cursor, type `/bnbagent-studio` — the skill drives every step.
