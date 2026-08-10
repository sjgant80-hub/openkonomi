# openkonomi

**▶ LIVE: https://sjgant80-hub.github.io/openkonomi/**

A personal AI agent built the other way round: it **cannot exceed its grant**, because the grant is
checked before the action rather than after the incident.

## The problem this is a response to

The open agent ecosystem works, and it is also currently a place where researchers found **40,000+
exposed instances** (63% vulnerable, 12,812 remotely exploitable), and where an audit of one skill
marketplace found **341 malicious skills out of 2,857 — 12%** — rising to **824** two weeks later
while the catalogue grew to 10,700.

Look at how those skills actually worked. They were not malicious in their code. They were named
`solana-wallet-tracker`, declared almost nothing, and their **prerequisites** told you to paste a
base64'd remote script into a terminal, which fetched an infostealer and took the keychain, the
browsers, 60+ wallets and the SSH keys.

A skill is a Markdown file an agent is told to follow. **The text is the executable.**

- **Signing does not fix it.** Signing proves authorship, not behaviour — every one of those skills
  could have carried a valid signature.
- **Static analysis did not fix it.** The formal treatment reports a negative result: on their corpus,
  information-flow analysis caught nothing that pattern matching did not.
- **The gap that is left** — named by an audit of the whole defence landscape — is **execution-layer
  enforcement: policy checked at operation time**, absent from most platforms.

## What openkonomi does instead

Two questions, asked by a machine, answered with a refusal rather than a warning:

1. **Does what this text reaches for match what it declared?**
   `skill.mjs` reads a real `SKILL.md` — the same frontmatter the existing ecosystem publishes, so the
   ~10,700 skills already in the world can be read without being rewritten — derives the capabilities
   its text implies, and names every contradiction. Never a score, never a count: the list of what
   does not line up *is* the product, because the one line that matters is the one that pipes a
   remote script into a shell.
2. **Is that inside the grant it would run under?**
   `capability.mjs` is the checkpoint: an object-capability lattice (`none < read < write < admin`
   across filesystem, network, env, shell, skill_invoke, clipboard, browser, database) **and a
   budget**. A refused action is charged nothing. Delegation can only shrink — there is no path by
   which a sub-agent acquires a power its caller lacked.

**The budget is the part the literature keeps leaving out.** "May call the network" and "may call the
network forty thousand times" are different powers. A grant with one open ceiling reports as
UNBOUNDED rather than looking careful.

## Proof

```bash
node capability.test.mjs     # 57 tests
node skill.test.mjs          # 73 tests
```

Mutation-gated with [witness](https://github.com/sjgant80-hub/witness) `@v0.2`, run in CI on every
push:

| kernel | tests | witness | survivors |
|---|---|---|---|
| `capability.mjs` | 57 | 22/24 killed | 0 — 2 reviewed-equivalent, written up in `witness.baseline.json` |
| `skill.mjs` | 73 | 33/34 killed | 0 — 1 reviewed-equivalent, written up in `witness.skill.baseline.json` |

Both baselines carry a stated proof of equivalence, not a shrug.

## Honest scope

This repo is the **verifier**: the two kernels that decide whether a skill may run, and under what.
That is the load-bearing part and it is gated. It is **not the whole agent** — the channel adapters,
the conversation loop and the signed-identity binding are the next organs and are not shipped here.
Said at that strength and no higher.

One practical note learned the hard way: a security tool's fixtures are exactly the strings scanners
are built to find. Test payloads are **assembled at run time from fragments** so a checked-out repo
does not get quarantined by antivirus — the kernel sees the identical string.

MIT.
