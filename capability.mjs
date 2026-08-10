// capability.mjs — WHAT AN AGENT IS ALLOWED TO REACH, and how much of it.
//
// OpenClaw's agent can run shell, drive a browser, read and write your files and send your mail, and
// it decides which of those to do by reading text. When the text is hostile — a web page, an email,
// a skill's own instructions — the deciding is done by the attacker. 40,000+ instances were found
// exposed, 12,812 of them remotely exploitable, and 12% of the skills in its marketplace were
// malicious. None of that is a bug in a particular release. It is what happens when the only thing
// standing between a sentence and your keychain is a model's judgement.
//
// This module is the other answer: the agent is handed a GRANT, and every action it wants to take is
// checked against that grant before it happens. A grant it does not have is not a warning, a score,
// or a confirmation dialog — it is a refusal. Prompt injection still works perfectly here; it simply
// buys the attacker nothing, because the sentence "exfiltrate the SSH keys" and the sentence "read
// the weather" are subject to the identical check, and one of them is not in the grant.
//
// TWO DIMENSIONS, and the second is the one the literature keeps leaving out:
//   · CAPABILITY — may it touch this resource, and how deeply (the object-capability lattice).
//   · BUDGET     — how many times, and for how much. A capability with no ceiling is a capability
//                  you have not really bounded: "may call the network" and "may call the network
//                  forty thousand times" are different powers. The estate learned this the
//                  expensive way, from one unchecked fan-out that spent 2.2M tokens.

// The lattice. Ordered, so "is this enough" is an integer comparison rather than a set of ifs.
export const LEVELS = ['none', 'read', 'write', 'admin'];
export const rank = (lvl) => {
  const i = LEVELS.indexOf(String(lvl));
  return i < 0 ? 0 : i;                                 // an unknown level is NONE, never admin
};

// The resources an agent can reach. Deliberately the set the security literature converged on, so a
// manifest written for openkonomi describes the same surface a reviewer already knows how to read.
export const RESOURCES = [
  'filesystem', 'network', 'env', 'shell', 'skill_invoke', 'clipboard', 'browser', 'database',
];
export const isResource = (r) => RESOURCES.includes(String(r));

/**
 * A grant: what this agent, or this skill, may do — and its ceilings.
 *
 * Anything unnamed is `none`. That default is the entire point: a manifest that forgets to mention
 * the shell does not thereby get the shell. Every real-world agent breach in the sources for this
 * build came down to a power nobody deliberately granted.
 */
export function grant(caps = {}, budget = {}) {
  const out = {};
  for (const r of RESOURCES) out[r] = 'none';
  for (const [r, lvl] of Object.entries(caps)) {
    if (isResource(r)) out[r] = LEVELS[rank(lvl)];       // normalise; unknown → none
  }
  return {
    caps: out,
    budget: {
      calls: numOr(budget.calls, Infinity),
      spend: numOr(budget.spend, Infinity),
      // Spent so far. Kept ON the grant rather than beside it, so a grant cannot be passed to a
      // subsystem that then forgets to carry its own accounting.
      used: { calls: 0, spend: 0 },
    },
  };
}

function numOr(v, dflt) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : dflt;
}

/** What one action needs. `cost` is optional and defaults to a single call of no monetary spend. */
export function need(resource, level = 'read', cost = {}) {
  return {
    resource: String(resource),
    level: LEVELS[rank(level)],
    calls: numOr(cost.calls, 1),
    spend: numOr(cost.spend, 0),
  };
}

/**
 * May this grant do this? Pure — it answers, it does not charge. `admit()` below is the one that
 * charges, and keeping them separate means a caller can preview a decision without spending it.
 *
 * The refusal carries a REASON, always. "Denied" with no reason is how a security boundary becomes
 * something users route around: they cannot tell a real refusal from a bug.
 */
export function permits(g, n) {
  if (!g || !n) return { ok: false, why: 'no grant or no request', code: 'malformed' };
  if (!isResource(n.resource)) {
    return { ok: false, why: `"${n.resource}" is not a resource openkonomi knows how to bound`, code: 'unknown_resource' };
  }
  const have = rank(g.caps[n.resource]), want = rank(n.level);
  if (have < want) {
    return {
      ok: false, code: 'capability',
      why: `needs ${n.level} on ${n.resource}, the grant allows ${g.caps[n.resource]}`,
    };
  }
  const b = g.budget;
  if (b.used.calls + n.calls > b.calls) {
    return { ok: false, code: 'budget_calls', why: `call budget spent (${b.used.calls}/${b.calls})` };
  }
  if (b.used.spend + n.spend > b.spend) {
    return { ok: false, code: 'budget_spend', why: `spend budget exceeded (${round(b.used.spend)}/${b.spend})` };
  }
  return { ok: true, code: 'allowed', why: `${n.level} on ${n.resource} is within the grant` };
}

const round = (x) => Math.round(x * 1e6) / 1e6;         // money compared as floats needs a leash

/**
 * Decide AND charge. The only way to spend budget, so there is exactly one place where the ledger
 * can go wrong. A refused action charges NOTHING — an attacker must not be able to drain a budget by
 * requesting things they were never going to be allowed to do.
 */
export function admit(g, n) {
  const v = permits(g, n);
  if (!v.ok) return { ...v, charged: false };
  g.budget.used.calls += n.calls;
  g.budget.used.spend = round(g.budget.used.spend + n.spend);
  return { ...v, charged: true, remaining: remaining(g) };
}

export function remaining(g) {
  const b = g.budget;
  return {
    calls: b.calls === Infinity ? Infinity : Math.max(0, b.calls - b.used.calls),
    spend: b.spend === Infinity ? Infinity : round(Math.max(0, b.spend - b.used.spend)),
  };
}

/**
 * Is `child` within `parent`? The rule that makes delegation safe: a skill may be handed a grant, and
 * whatever it hands onward can only ever be smaller. There is no path by which a sub-agent acquires a
 * power its caller lacked, which is what "privilege escalation" means in every one of the audited
 * attack classes.
 */
export function within(parent, child) {
  if (!parent || !child) return false;
  for (const r of RESOURCES) if (rank(child.caps[r]) > rank(parent.caps[r])) return false;
  const pr = remaining(parent);
  return child.budget.calls <= pr.calls && child.budget.spend <= pr.spend;
}

/**
 * Hand a smaller grant to something you do not trust. Clamped to the parent by construction rather
 * than by checking afterwards — `attenuate` cannot return something `within()` would reject.
 */
export function attenuate(parent, caps = {}, budget = {}) {
  const child = grant(caps, budget);
  for (const r of RESOURCES) {
    if (rank(child.caps[r]) > rank(parent.caps[r])) child.caps[r] = parent.caps[r];
  }
  const pr = remaining(parent);
  child.budget.calls = Math.min(child.budget.calls, pr.calls);
  child.budget.spend = Math.min(child.budget.spend, pr.spend);
  return child;
}

/** Everything this grant actually allows, for showing a person before they approve it. */
export function describe(g) {
  const powers = RESOURCES.filter(r => rank(g.caps[r]) > 0).map(r => `${r}:${g.caps[r]}`);
  const b = g.budget;
  return {
    powers,
    none: RESOURCES.filter(r => rank(g.caps[r]) === 0),
    calls: b.calls === Infinity ? 'unbounded' : b.calls,
    spend: b.spend === Infinity ? 'unbounded' : b.spend,
    // Said out loud, because "unbounded" is the condition every incident in the research had in
    // common and it should never be able to hide inside a tidy summary.
    unbounded: b.calls === Infinity || b.spend === Infinity,
    line: powers.length ? powers.join(' · ') : 'no powers at all',
  };
}

export default { LEVELS, RESOURCES, rank, isResource, grant, need, permits, admit, remaining, within, attenuate, describe };
