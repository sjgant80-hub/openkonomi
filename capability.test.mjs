// capability.test.mjs — PROOF-OF-PLAY for the bound an agent cannot cross.
//
// The claim is not "openkonomi is careful". It is that a power outside the grant is UNREACHABLE, and
// that a budget, once spent, stays spent. So these tests are written as attacks: escalate, delegate
// upward, drain a budget with requests that were never going to be allowed, smuggle an unknown level
// past the lattice. Every one of them has to come back refused, with a reason.
import { LEVELS, RESOURCES, rank, grant, need, permits, admit, remaining, within, attenuate, describe } from './capability.mjs';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? '  ✓ ' : '  ✗ FAIL ') + m); };

console.log('\n=== §1 · THE LATTICE — unknown means none, never admin ===');
{
  ok(rank('none') === 0 && rank('admin') === 3, 'the levels are ordered');
  ok(rank('root') === 0 && rank(undefined) === 0 && rank(null) === 0, 'an unrecognised level is NONE — the fail-safe direction');
  ok(rank('ADMIN') === 0, 'levels are case-sensitive, so a near-miss spelling does not silently grant power');
  ok(LEVELS.length === 4 && RESOURCES.length === 8, 'the surface is the eight resources and four levels the literature converged on');
}

console.log('\n=== §2 · A GRANT DEFAULTS TO NOTHING ===');
{
  const g = grant();
  ok(RESOURCES.every(r => g.caps[r] === 'none'), 'an empty grant allows nothing at all');
  const partial = grant({ network: 'read' });
  ok(partial.caps.shell === 'none', 'a manifest that forgets to mention the shell does NOT thereby get the shell');
  ok(grant({ notAResource: 'admin' }).caps.notAResource === undefined, 'an invented resource name is dropped, not honoured');
  ok(grant({ shell: 'wizard' }).caps.shell === 'none', 'an invented LEVEL collapses to none rather than being trusted');
}

console.log('\n=== §3 · ESCALATION IS REFUSED, WITH A REASON ===');
{
  const g = grant({ filesystem: 'read' }, { calls: 5 });
  const up = permits(g, need('filesystem', 'admin'));
  ok(!up.ok && up.code === 'capability', 'read does not become admin by asking');
  ok(/needs admin on filesystem/.test(up.why), 'and the refusal says exactly what was wanted versus allowed');
  ok(permits(g, need('filesystem', 'read')).ok, 'what was granted still works');
  ok(!permits(g, need('shell', 'read')).ok, 'an ungranted resource is refused at the lowest level');
  const bogus = permits(g, need('mainframe', 'read'));
  ok(!bogus.ok && bogus.code === 'unknown_resource', 'a resource openkonomi cannot bound is refused rather than waved through');
  ok(!permits(null, need('shell')).ok && !permits(g, null).ok, 'a missing grant or request is a refusal, not a crash');
}

console.log('\n=== §4 · ⚑ THE BUDGET IS REAL — this is the 2.2M-token lesson ===');
{
  const g = grant({ network: 'read' }, { calls: 3 });
  ok(admit(g, need('network')).ok && admit(g, need('network')).ok, 'the first calls are allowed');
  ok(admit(g, need('network')).ok, 'up to the ceiling');
  const over = admit(g, need('network'));
  ok(!over.ok && over.code === 'budget_calls', 'and the next one is refused — the ceiling is real, not advisory');
  ok(/3\/3/.test(over.why), 'the refusal shows the spend against the budget');
  ok(remaining(g).calls === 0, 'nothing is left');
  ok(over.charged === false, 'a refused call is NOT charged');
}

console.log('\n=== §5 · a refused action cannot drain the budget ===');
{
  // The attack: ask repeatedly for something you are never allowed, so the ceiling is exhausted and
  // the legitimate work fails. Refusals must be free.
  const g = grant({ network: 'read' }, { calls: 2 });
  for (let i = 0; i < 50; i++) admit(g, need('shell', 'admin'));
  ok(remaining(g).calls === 2, 'fifty refused requests spent nothing');
  ok(admit(g, need('network')).ok, 'and the legitimate work still runs');
}

console.log('\n=== §6 · SPEND is bounded separately from calls ===');
{
  const g = grant({ network: 'read' }, { calls: 100, spend: 1 });
  ok(admit(g, need('network', 'read', { spend: 0.6 })).ok, 'spend under the ceiling is allowed');
  const over = admit(g, need('network', 'read', { spend: 0.6 }));
  ok(!over.ok && over.code === 'budget_spend', 'spend over the ceiling is refused even with calls to spare');
  ok(remaining(g).calls === 99, 'and the refusal did not consume a call either');
  ok(remaining(g).spend === 0.4, 'the remainder is exact — no float drift');
}

console.log('\n=== §7 · DELEGATION ONLY EVER SHRINKS ===');
{
  const parent = grant({ filesystem: 'write', network: 'read' }, { calls: 10, spend: 5 });
  const child = attenuate(parent, { filesystem: 'admin', shell: 'admin' }, { calls: 999, spend: 999 });
  ok(child.caps.filesystem === 'write', 'a child asking for MORE than its parent is clamped to the parent');
  ok(child.caps.shell === 'none', 'a power the parent never had cannot be conjured by a child');
  ok(child.budget.calls === 10 && child.budget.spend === 5, 'the budget is clamped too');
  ok(within(parent, child), 'the result is within the parent by construction');
  const forged = grant({ shell: 'admin' }, { calls: 1 });
  ok(!within(parent, forged), 'a hand-built child claiming more is detected');
  ok(!within(parent, grant({}, { calls: 99 })), 'and so is one claiming a bigger budget');
  ok(!within(null, child) && !within(parent, null), 'missing sides compare false rather than throwing');
}

console.log('\n=== §8 · attenuation respects what the parent has ALREADY SPENT ===');
{
  const parent = grant({ network: 'read' }, { calls: 10 });
  for (let i = 0; i < 7; i++) admit(parent, need('network'));
  const child = attenuate(parent, { network: 'read' }, { calls: 10 });
  ok(child.budget.calls === 3, 'the child gets what is LEFT, not the original ceiling — otherwise delegation mints budget');
}

console.log('\n=== §9 · DESCRIBE — a person can read what they are approving ===');
{
  const g = grant({ network: 'read', shell: 'write' }, { calls: 20, spend: 2 });
  const d = describe(g);
  ok(d.powers.includes('network:read') && d.powers.includes('shell:write'), 'the powers are listed');
  ok(d.none.includes('database'), 'and so is what it explicitly cannot touch');
  ok(d.unbounded === false, 'a bounded grant says so');
  ok(describe(grant({ shell: 'admin' })).unbounded === true, 'an unbounded one says so LOUDLY — every incident in the research had this in common');
  ok(describe(grant()).line === 'no powers at all', 'a grant with nothing reads as nothing, not as an empty string');
}

console.log('\n=== §10 · ⚑ A ZERO BUDGET IS A REAL BUDGET, and a negative one is not a budget at all ===');
{
  // The dangerous direction is a ceiling of 0 being read as "unset" and quietly becoming unlimited —
  // that is precisely how a deliberate "this skill may do nothing" turns into a skill that may do
  // everything. Zero must mean zero.
  const zero = grant({ network: 'read' }, { calls: 0 });
  ok(!admit(zero, need('network')).ok, 'a budget of ZERO calls allows nothing — it is not treated as unset');
  ok(describe(zero).calls === 0, 'and it reports as 0, not as unbounded');
  const zeroSpend = grant({ network: 'read' }, { calls: 5, spend: 0 });
  ok(admit(zeroSpend, need('network', 'read', { spend: 0 })).ok, 'a zero SPEND ceiling still permits free actions');
  ok(!admit(zeroSpend, need('network', 'read', { spend: 0.01 })).ok, 'but not a single penny of spend');

  // A nonsense ceiling must fall back to the default rather than being honoured as-is: a negative
  // budget would otherwise make every comparison behave inside-out.
  ok(describe(grant({}, { calls: -5 })).calls === 'unbounded', 'a NEGATIVE budget is rejected and falls back to the default');
  ok(describe(grant({}, { calls: 'lots' })).calls === 'unbounded', 'and so is a non-numeric one');
  ok(admit(grant({ network: 'read' }, { calls: -1 }), need('network')).ok, 'a rejected budget does not accidentally block everything either');
}

console.log('\n=== §11 · the ceilings are inclusive — spending exactly the budget is allowed ===');
{
  const g = grant({ network: 'read' }, { calls: 2, spend: 1 });
  ok(admit(g, need('network', 'read', { spend: 1 })).ok, 'spending EXACTLY the ceiling is allowed, not refused by an off-by-one');
  ok(remaining(g).spend === 0, 'and it leaves nothing');
  const h = grant({ network: 'read' }, { calls: 1 });
  ok(admit(h, need('network')).ok && !admit(h, need('network')).ok, 'a budget of one permits exactly one call');
}

console.log('\n=== §12 · describe() reports the real numbers, not just the flags ===');
{
  const d = describe(grant({ network: 'read' }, { calls: 20, spend: 2.5 }));
  ok(d.calls === 20, 'a finite call ceiling is reported as its number');
  ok(d.spend === 2.5, 'and so is a finite spend ceiling');
  ok(describe(grant({}, {})).calls === 'unbounded' && describe(grant({}, {})).spend === 'unbounded', 'missing ceilings read as unbounded');
  // Either ceiling being open is enough to make the grant unbounded. Requiring BOTH to be open would
  // let "capped calls, open spend" present itself as bounded, which is the shape that reads careful
  // and is not.
  ok(describe(grant({}, { calls: 5 })).unbounded === true, 'a call ceiling with spend left open is STILL unbounded');
  ok(describe(grant({}, { spend: 5 })).unbounded === true, 'and a spend ceiling with calls left open is too');
}

console.log('\n=== §13 · within() checks BOTH ceilings, not whichever it happens to hit first ===');
{
  const parent = grant({ network: 'read' }, { calls: 10, spend: 10 });
  ok(!within(parent, grant({ network: 'read' }, { calls: 99, spend: 5 })), 'a child over on CALLS is rejected even though its spend fits');
  ok(!within(parent, grant({ network: 'read' }, { calls: 5, spend: 99 })), 'a child over on SPEND is rejected even though its calls fit');
  ok(within(parent, grant({ network: 'read' }, { calls: 5, spend: 5 })), 'a child inside both is accepted');
}

console.log(`\n${fail === 0 ? '✓ CAPABILITY GATE CLEAN' : '✗ CAPABILITY GATE FAILED'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
