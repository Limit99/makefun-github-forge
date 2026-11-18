# makefun-github-forge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Limit99/makefun-github-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Limit99/makefun-github-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone GitHub-compatible git forge in TypeScript, Node standard library only: git smart HTTP (upload-pack protocol v2 with ls-refs, fetch and shallow support, plus v0 fallback; receive-pack v0 with report-status and fast-forward enforcement) over a hand-rolled SHA-1 object store and packfile layer, the REST v3 API (repositories, branches, commits, contents, labels, issues, comments, pull requests with squash merges), the GraphQL v4 API (queries, mutations, introspection, cursor pagination, Relay-style global ids) and an MCP endpoint (server/discover, tools/list, tools/call) — all four surfaces over one in-memory, deterministic store.

## Run it

```sh
node main.ts
# The trial harness provides MAKEFUN_ENV_URL (register/done) and
# MAKEFUN_SHOP_TOKEN (the bearer token every API call presents).
```

---

<sub>Entered on [make.fun](https://make.fun/?ref=0gynx1gq&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
