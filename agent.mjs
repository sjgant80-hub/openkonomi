// agent.mjs — THE LOOP. Run an admitted skill under a grant it cannot leave.
//
// The verifier decides whether a skill may run at all. This is what happens next, and it is where
// every real agent incident actually occurred: not at install time, but on step nine, when a web page
// the agent read told it to do something nobody asked for.
//
// ⚑ THE PROPOSER IS UNTRUSTED. `propose()` is the model. It may suggest anything — including things
// the skill never declared, things the grant forbids, and things it was told to do by content it just
// read. The loop's entire job is that this does not matter: every proposal goes through `admit()`
// before it becomes an action, so a hostile proposal costs a refusal line in the transcript and
// nothing else. There is no code path from "the model asked" to "it happened".
//
// ⚑ AND OBSERVATIONS ARE DATA, NEVER INSTRUCTIONS. What a step RETURNS is fed back to the proposer as
// material to reason about, and it can never widen the grant, extend the budget, or unlock a
// resource. Indirect prompt injection is therefore a way to waste the visitor's remaining calls, and
// not a way to acquire a power. That is the whole difference between a boundary and a suggestion.
//
// The effects are INJECTED — `perform(action)` is supplied by the caller. The loop is therefore pure,
// deterministic, and provable without a filesystem, a network, or a model, which is why the gate on
// it means something.
import { admit, permits, need, remaining, describe } from './capability.mjs';
import { inspect } from './skill.mjs';

export const STOP = {
  DONE: 'done',                 // the proposer said there was nothing left to do
  BUDGET: 'budget',             // the ceiling was reached — the honest end of a bounded run
  STEPS: 'steps',               // the step cap was reached
  REFUSED_SKILL: 'refused',     // the skill never ran: it failed inspection
  PROPOSER_FAILED: 'proposer',  // the model itself errored
};

const clampSteps = (n) => {
  const v = Math.floor(Number(n));
  return Number.isFinite(v) && v > 0 ? Math.min(v, 100) : 12;
};

/**
 * Normalise whatever the proposer returned into an action, or reject it.
 *
 * A proposal is data from an untrusted source, so it is treated the way any untrusted input should
 * be: validated into a known shape, never spread into the action. Anything unrecognised is refused
 * with a reason rather than passed along in the hope that `perform` copes.
 */
export function readProposal(p) {
  if (p == null) return { ok: false, why: 'the proposer returned nothing' };
  if (p.done === true) return { ok: true, done: true };
  if (typeof p !== 'object') return { ok: false, why: 'a proposal must be an object' };
  const resource = String(p.resource || '');
  const level = String(p.level || 'read');
  if (!resource) return { ok: false, why: 'the proposal names no resource' };
  return {
    ok: true,
    done: false,
    action: {
      resource, level,
      // The description is for the transcript a person reads. It is text from an untrusted source,
      // so it is truncated and never interpreted.
      what: String(p.what == null ? '' : p.what).slice(0, 200),
      cost: { calls: Number(p.calls) || 1, spend: Number(p.spend) || 0 },
    },
  };
}

/**
 * Run the skill.
 *
 * Returns a TRANSCRIPT: every proposal, whether it was allowed, and why. A refused step is recorded
 * in the same list as an allowed one — a run that hid its refusals would be exactly as useless as a
 * conformance report that hid the tags it choked on.
 */
export async function run(skillText, grant, { propose, perform, maxSteps = 12 } = {}) {
  const limit = clampSteps(maxSteps);
  const verdict = inspect(skillText, grant);
  const transcript = [];

  // The skill is inspected FIRST and refused as a whole. A skill whose text contradicts its
  // declaration never reaches step one — there is no "run it carefully and see".
  if (!verdict.admitted) {
    return {
      ran: false, stop: STOP.REFUSED_SKILL, verdict, transcript,
      steps: 0, allowed: 0, refused: 0,
      why: verdict.verdict,
      spent: { calls: 0, spend: 0 },
    };
  }

  let stop = STOP.STEPS, allowed = 0, refused = 0;
  const observations = [];

  for (let n = 1; n <= limit; n++) {
    let raw;
    try {
      // Everything the proposer is given is material to think about. It is NOT given the grant to
      // modify, and there is no argument through which it could raise its own ceiling.
      raw = await propose({
        step: n,
        skill: verdict.name,
        declared: verdict.declared,
        observations: observations.slice(),
        remaining: remaining(grant),
      });
    } catch (e) {
      stop = STOP.PROPOSER_FAILED;
      transcript.push({ n, proposed: null, allowed: false, why: 'the proposer failed: ' + msg(e) });
      break;
    }

    const p = readProposal(raw);
    if (!p.ok) { refused++; transcript.push({ n, proposed: null, allowed: false, why: p.why }); continue; }
    if (p.done) { stop = STOP.DONE; break; }

    const req = need(p.action.resource, p.action.level, p.action.cost);
    const decision = admit(grant, req);

    if (!decision.ok) {
      refused++;
      transcript.push({
        n, proposed: p.action, allowed: false, code: decision.code,
        why: decision.why,
      });
      // A spent budget is the end of the run, not something to keep hammering. Any other refusal is
      // survivable: the proposer is free to suggest something it IS allowed to do next.
      if (decision.code === 'budget_calls' || decision.code === 'budget_spend') { stop = STOP.BUDGET; break; }
      continue;
    }

    allowed++;
    let result, failed = null;
    try {
      result = await perform(p.action);
    } catch (e) {
      failed = msg(e);
    }
    // The budget was already charged by admit(). A step that fails after being allowed STAYS
    // charged — it consumed the thing the ceiling exists to ration, and refunding it would let a
    // proposer loop forever on actions that always fail.
    transcript.push({
      n, proposed: p.action, allowed: true, why: decision.why,
      failed, result: failed ? null : truncate(result),
    });
    observations.push({ step: n, what: p.action.what, failed, result: failed ? null : truncate(result) });
  }

  const spentCalls = grant.budget.used.calls, spentSpend = grant.budget.used.spend;
  return {
    ran: true, stop, verdict, transcript,
    steps: transcript.length, allowed, refused,
    spent: { calls: spentCalls, spend: spentSpend },
    remaining: remaining(grant),
    why: reason(stop, allowed, refused),
  };
}

const msg = (e) => (e && e.message ? e.message : String(e));
const truncate = (v) => (typeof v === 'string' ? v.slice(0, 500) : v);

function reason(stop, allowed, refused) {
  if (stop === STOP.REFUSED_SKILL) return 'the skill was refused before it ran';
  if (stop === STOP.BUDGET) return `stopped on the budget after ${allowed} action${allowed === 1 ? '' : 's'} — the ceiling is arithmetic, not a policy`;
  if (stop === STOP.STEPS) return `reached the step cap with ${allowed} allowed and ${refused} refused`;
  if (stop === STOP.PROPOSER_FAILED) return 'the proposer failed, so the run stopped rather than guessing what it meant';
  return `finished with ${allowed} action${allowed === 1 ? '' : 's'} taken and ${refused} refused`;
}

/**
 * What a run is ALLOWED to do, before it does anything — for showing a person the moment they are
 * asked to approve it. The point of a bound is that it can be read in advance.
 */
export function preflight(skillText, grant) {
  const v = inspect(skillText, grant);
  const g = describe(grant);
  return {
    name: v.name,
    admitted: v.admitted,
    verdict: v.verdict,
    powers: g.powers,
    calls: g.calls,
    spend: g.spend,
    unbounded: g.unbounded,
    // Stated separately because "it passed inspection" and "the run is bounded" are different
    // assurances, and an unbounded run of an honest skill is still an unbounded run.
    summary: !v.admitted
      ? 'This will not run.'
      : g.unbounded
        ? `${v.name} may use ${g.line}, with NO ceiling — this run is unbounded.`
        : `${v.name} may use ${g.line}, at most ${g.calls} actions and ${g.spend} spend.`,
  };
}

export default { STOP, readProposal, run, preflight };
