// mesh.mjs — WHERE openkonomi JOINS THE ESTATE.
//
// Up to here the grant has been an object in memory. That is enough to stop a hostile proposer inside
// one process, and it is not enough to cross a trust boundary: a receiver has no way to tell a real
// permission from one the caller made up, and an action that already happened leaves no evidence that
// it was ever allowed.
//
// So this wires in the estate's own organs rather than reinventing them:
//
//   · THE-WALLET (organs/wallet.mjs, vendored verbatim) — an Ed25519 identity that IS a capability
//     plus a budget. It turns a grant into something SIGNED: `authorize` gates on `canDo` and then
//     signs a token binding the id, the action, the cost and the running total. A receiver verifies
//     it without trusting whoever handed it over.
//   · FALLROUTER / FALLHUB module manifests — the estate's OWN module format
//     (`module.manifest.json`: provides / requires / kernel_extension). openkonomi already reads
//     SKILL.md from the outside world; reading the estate's format through the SAME gate is what
//     makes this a mesh rather than two separate tools.
//
// ⚑ THE DOUBLE GATE, and why both halves are needed. The wallet knows about capability strings and
// one budget. openkonomi knows about a lattice, eight resources, two ceilings and the text of the
// thing being run. Neither subsumes the other: the wallet cannot tell that a skill's text contradicts
// its declaration, and openkonomi cannot prove to a third party that an action was permitted.
// `sealedAdmit` requires BOTH — and if they ever disagree it refuses and says which one objected,
// because two safety checks that can silently diverge are worse than one.
import { admit, permits, need, RESOURCES, rank } from './capability.mjs';
import { canDo, genesis, authorize, verifyToken, attenuates } from './organs/wallet.mjs';

/**
 * openkonomi's lattice → the wallet's capability strings.
 *
 * `filesystem:read` is one capability. A grant of `write` also confers `read`, so the strings are
 * expanded down the lattice — otherwise a wallet holding `filesystem:write` would refuse a read it is
 * plainly entitled to, and the two halves of the gate would disagree about an easy case.
 */
export function capStrings(grant) {
  const out = [];
  if (!grant || !grant.caps) return out;
  for (const r of RESOURCES) {
    const have = rank(grant.caps[r]);
    for (let lvl = 1; lvl <= have; lvl++) out.push(r + ':' + ['none', 'read', 'write', 'admin'][lvl]);
  }
  return out;
}

/** The action string the wallet gates on, derived from the same request openkonomi checks. */
export const actionOf = (n) => ({ type: n.resource + ':' + n.level, cost: n.calls });

/**
 * Open a signed wallet for a grant. The wallet's single budget is the CALL ceiling, because that is
 * the one both systems can count identically; spend stays with openkonomi, which is the only side
 * that knows what an action costs in money.
 */
export async function openWallet(crypto, grant) {
  const budget = grant.budget.calls === Infinity ? Number.MAX_SAFE_INTEGER : grant.budget.calls;
  const { wallet, sk } = await genesis(crypto, { caps: capStrings(grant), budget });
  return { wallet, sk };
}

/**
 * THE DOUBLE GATE. Admit an action through openkonomi AND the wallet, and return a signed token
 * proving it was permitted.
 *
 * Order matters: openkonomi is asked first because it is the side that can refuse for free, and a
 * refusal must not consume wallet budget. Only once it has allowed the action is the wallet asked to
 * sign — so a refused action leaves no signature, which is exactly the property that makes the
 * signature worth anything.
 */
export async function sealedAdmit(crypto, ctx, request) {
  const local = admit(ctx.grant, request);
  if (!local.ok) return { ok: false, by: 'openkonomi', why: local.why, code: local.code, token: null };

  const res = await authorize(crypto, ctx.wallet, ctx.sk, actionOf(request));
  if (!res.ok) {
    // The two halves disagreed: openkonomi allowed it and the wallet did not. That is a real
    // condition worth surfacing loudly rather than smoothing over — it means the mapping between the
    // lattice and the capability strings has drifted, and the safe reading is the stricter one.
    return { ok: false, by: 'wallet', why: res.why, code: 'wallet_refused', token: null, disagreed: true };
  }
  ctx.wallet = res.wallet;                     // the wallet is immutable; carry the new one forward
  return { ok: true, by: 'both', why: local.why, token: res.token, remaining: ctx.wallet.budget.total - ctx.wallet.budget.spent };
}

/** Verify a token someone else produced. This is the whole point of signing: no trust in the caller. */
export async function verifySealed(crypto, token) {
  return verifyToken(crypto, token);
}

/** A context the loop can carry: the local grant and the signed identity, kept together. */
export async function openContext(crypto, grant) {
  const { wallet, sk } = await openWallet(crypto, grant);
  return { grant, wallet, sk, id: wallet.id };
}

// ── the estate's own module format ───────────────────────────────────────────────────────────────
//
// A fallhub `module.manifest.json` declares what a module PROVIDES and what it REQUIRES. That is a
// declaration in exactly the sense skill.mjs means it, so it can be judged by the same rule — which
// is what lets one verifier cover both the outside ecosystem and the estate's own 1,600 repos.
const PROVIDES_CAPS = {
  llm_routing: { network: 'read' },
  cost_caps: {},
  fallback_rails: { network: 'read' },
  // Sending is a strictly bigger power than fetching, and a module that does both must end up with
  // the bigger one — whichever order the entries happen to be listed in.
  webhooks: { network: 'write' },
  storage: { filesystem: 'write' },
  memory: { filesystem: 'write' },
  browser_control: { browser: 'write' },
  shell: { shell: 'write' },
  signing: {},
};

/**
 * Read an estate module manifest into the same shape `inspect` produces, so a module and a skill can
 * be compared side by side.
 *
 * Anything it does not recognise is REPORTED, never dropped — an unknown `provides` entry is a
 * capability nobody has classified, and silently treating it as harmless is the failure this whole
 * repo exists to avoid.
 */
export function fromManifest(json) {
  const m = (json && typeof json === 'object') ? json : {};
  const provides = Array.isArray(m.provides) ? m.provides : [];
  const requires = Array.isArray(m.requires) ? m.requires : [];
  const caps = {}, unknown = [];

  for (const p of provides) {
    const mapped = PROVIDES_CAPS[String(p)];
    if (!mapped) { unknown.push(String(p)); continue; }
    for (const [r, lvl] of Object.entries(mapped)) {
      if (rank(lvl) > rank(caps[r] || 'none')) caps[r] = lvl;
    }
  }
  // A module that extends the kernel is asking for more than a module normally may, and that is worth
  // stating rather than inferring: an empty kernel_extension is not the same as none declared.
  const extends_ = m.kernel_extension && Object.keys(m.kernel_extension).length > 0;

  const problems = [];
  if (!m.name) problems.push({ kind: 'malformed', what: 'name', why: 'a module with no name cannot be listed or pinned' });
  if (!m.version) problems.push({ kind: 'malformed', what: 'version', why: 'without a version, two different modules share one identity' });
  for (const u of unknown) {
    problems.push({ kind: 'unclassified', what: u, why: `"${u}" is not a capability openkonomi knows how to bound — reported rather than assumed harmless` });
  }
  if (extends_) problems.push({ kind: 'kernel_extension', what: 'kernel_extension', why: 'this module modifies the kernel itself, which is outside what a capability grant can bound' });

  return {
    kind: 'module',
    name: m.name || '(unnamed)',
    version: m.version || null,
    description: m.description || null,
    declared: caps,
    requires,
    unknown,
    problems,
    admitted: problems.length === 0,
    verdict: problems.length === 0
      ? `ADMITTED — ${m.name} declares ${Object.keys(caps).length || 'no'} capabilit${Object.keys(caps).length === 1 ? 'y' : 'ies'}, all classified.`
      : `REFUSED — ${m.name || '(unnamed)'} has ${problems.length} problem${problems.length === 1 ? '' : 's'}.`,
  };
}

export default { capStrings, actionOf, openWallet, openContext, sealedAdmit, verifySealed, fromManifest };
