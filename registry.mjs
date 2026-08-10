// registry.mjs — THE LISTING, and why one cannot be bought or claimed.
//
// This is the fold that turns two kernels into an ecosystem. The verifier decided whether a skill may
// run; the loop bounded it while it ran. Neither answers the question a marketplace actually poses,
// which is: WHICH OF THE TEN THOUSAND SHOULD I INSTALL?
//
// ClawHub answered it with a description and a star count, and 341 of 2,857 listings were stealing
// keychains. Two weeks later 824. The listings were not lying about who published them — signing
// would have been perfectly satisfied. They were lying about what they did, and nothing in the
// registry was in a position to notice.
//
// So the rule here, which is the estate's oldest ratified position on marketplaces:
//
//   ⚑ NO LISTING WITHOUT A PASS. A skill is not listed because someone submitted it, paid for it, or
//     signed it. It is listed because it was INSPECTED and admitted, and the listing carries the
//     verdict that admitted it. `list()` REFUSES — it does not warn, score, or flag for review.
//
// And the second rule, which is what makes the first one survive contact with an attacker:
//
//   ⚑ THE LISTING IS BOUND TO THE EXACT TEXT THAT PASSED. A listing carries the content address of
//     the skill it was granted for. Change one character — add the prerequisite AFTER approval, the
//     oldest trick there is — and the address no longer matches, so the listing does not cover it.
//     A registry that keyed on NAME would hand a malicious update the reputation of the honest
//     version it replaced.
import { inspect } from './skill.mjs';
import { describe } from './capability.mjs';

// Content address: FNV-1a twice over, 16 hex — the estate's h16, so an address computed here is the
// same address computed anywhere else in the estate.
export function h16(s) {
  const str = String(s == null ? '' : s);
  let a = 0x811c9dc5, b = 0x01000193;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    a ^= c; a = Math.imul(a, 0x01000193) >>> 0;
    b ^= c + i; b = Math.imul(b, 0x85ebca6b) >>> 0;
  }
  return (a >>> 0).toString(16).padStart(8, '0') + (b >>> 0).toString(16).padStart(8, '0');
}

export function makeRegistry() {
  return { listed: new Map(), refused: [], byName: new Map() };
}

/**
 * Submit a skill. It is inspected here, on the spot, and the outcome is the outcome — there is no
 * queue, no reviewer, and no way to submit a verdict alongside the skill.
 *
 * A REFUSAL IS RECORDED AND PUBLISHED. That is the part ClawHub could not do: it removed the bad
 * listings quietly, so the next author learned nothing and the next user could not tell a marketplace
 * that had never been attacked from one that had been attacked and cleaned. The refused list here is
 * a permanent, public part of the registry.
 */
export function submit(reg, text, grant = null) {
  const addr = h16(text);
  const verdict = inspect(text, grant);
  const at = reg.listed.size + reg.refused.length;      // a deterministic sequence, not a clock

  if (!verdict.admitted) {
    const entry = {
      address: addr, name: verdict.name, admitted: false, at,
      problems: verdict.problems,
      why: verdict.verdict,
    };
    reg.refused.push(entry);
    return entry;
  }

  const entry = {
    address: addr, name: verdict.name, version: verdict.version, description: verdict.description,
    admitted: true, at,
    declared: verdict.declared,
    reaches: verdict.reaches.map(r => r.resource + ':' + r.level),
    grant: grant ? describe(grant) : null,
    // The evidence that admitted it, kept WITH the listing. A listing whose proof lives somewhere
    // else is a claim about a proof, which is the thing this registry exists not to accept.
    verdict: verdict.verdict,
  };
  reg.listed.set(addr, entry);
  // Names are an index, never the key. Two versions of a skill are two listings.
  const versions = reg.byName.get(entry.name) || [];
  versions.push(addr);
  reg.byName.set(entry.name, versions);
  return entry;
}

/**
 * Does this exact text have a listing?
 *
 * ⚑ THE WHOLE POINT: the lookup is by CONTENT, not by name. An installer that asks "is
 * solana-wallet-tracker listed?" can be answered yes about a file it is not holding. An installer
 * that asks "is THIS listed?" cannot.
 */
export function covers(reg, text) {
  const addr = h16(text);
  const entry = reg.listed.get(addr);
  if (entry) return { ok: true, address: addr, entry, why: `listed as ${entry.name}` };
  const named = inspect(text).name;
  const others = reg.byName.get(named) || [];
  return {
    ok: false, address: addr, entry: null,
    // Named precisely, because "not listed" and "a DIFFERENT version of this name is listed" are
    // very different situations for the person about to install it.
    why: others.length
      ? `this exact text is NOT listed — ${others.length} other version${others.length === 1 ? '' : 's'} of "${named}" ${others.length === 1 ? 'is' : 'are'}, and this is not one of them`
      : `nothing under this content address is listed`,
  };
}

/**
 * Re-verify every listing against the CURRENT kernel.
 *
 * A listing is not a permanent award. Rules improve — the signal that caught the real ClawHavoc line
 * was added AFTER the first version of this kernel — and when they do, everything already listed is
 * re-judged. Anything that no longer passes is DELISTED and moved to the refused list with its
 * reason. A grade that could not be revoked would not be a grade.
 */
export function revalidate(reg, grant = null) {
  const delisted = [];
  for (const [addr, entry] of [...reg.listed.entries()]) {
    const again = inspect(entry.source == null ? '' : entry.source, grant);
    if (entry.source == null) continue;                 // nothing to re-read
    if (!again.admitted) {
      reg.listed.delete(addr);
      const gone = { ...entry, admitted: false, problems: again.problems, why: 'DELISTED on re-verification — ' + again.verdict };
      reg.refused.push(gone);
      delisted.push(gone);
    }
  }
  return { delisted, remaining: reg.listed.size };
}

/** Keep the source with the listing so it can be re-judged later. Opt-in, because storing it is a choice. */
export function submitWithSource(reg, text, grant = null) {
  const e = submit(reg, text, grant);
  if (e.admitted) reg.listed.get(e.address).source = text;
  return e;
}

/**
 * What the registry looks like from outside — including, prominently, what it turned away.
 *
 * A marketplace that publishes only its successes is reporting a number with the denominator
 * removed. `refusedRate` is stated so the health of the catalogue is legible rather than implied.
 */
export function census(reg) {
  const listed = reg.listed.size, refused = reg.refused.length, seen = listed + refused;
  const kinds = {};
  for (const r of reg.refused) for (const p of (r.problems || [])) kinds[p.kind] = (kinds[p.kind] || 0) + 1;
  return {
    seen, listed, refused,
    refusedRate: seen ? Math.round((refused / seen) * 1000) / 10 : 0,
    kinds,
    // Said in words, because a rate on its own invites the reader to assume it is bad news.
    line: seen === 0
      ? 'nothing submitted yet'
      : `${listed} listed, ${refused} refused of ${seen} submitted (${seen ? Math.round((refused / seen) * 1000) / 10 : 0}% turned away, and the reasons are public)`,
  };
}

export default { h16, makeRegistry, submit, submitWithSource, covers, revalidate, census };
