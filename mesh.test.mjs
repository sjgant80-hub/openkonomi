// mesh.test.mjs — PROOF-OF-PLAY for the join.
//
// Real Ed25519, not a stub: the wallet is the estate's own kernel, vendored verbatim, driven through
// node:crypto. A signature test against a fake signer proves nothing, so there isn't one here.
import { capStrings, actionOf, openWallet, openContext, sealedAdmit, verifySealed, fromManifest } from './mesh.mjs';
import { grant, need, remaining } from './capability.mjs';
import { nodeCrypto } from './organs/crypto-node.mjs';

const crypto = nodeCrypto();
let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? '  ✓ ' : '  ✗ FAIL ') + m); };

console.log('\n=== §1 · the lattice maps onto the wallet WITHOUT the two halves disagreeing ===');
{
  const caps = capStrings(grant({ filesystem: 'write', network: 'read' }));
  ok(caps.includes('filesystem:write'), 'the granted level is a capability');
  ok(caps.includes('filesystem:read'), 'and so is every level BENEATH it — write confers read');
  ok(!caps.includes('filesystem:admin'), 'but nothing above it');
  ok(!caps.some(c => c.startsWith('shell')), 'an ungranted resource contributes no capability at all');
  ok(capStrings(grant()).length === 0, 'an empty grant maps to no capabilities');
  ok(capStrings(null).length === 0 && capStrings({}).length === 0, 'a missing grant does not throw');
  ok(actionOf(need('network', 'read', { calls: 2 })).type === 'network:read', 'an action string is derived from the same request openkonomi checks');
  ok(actionOf(need('network', 'read', { calls: 2 })).cost === 2, 'and carries its cost');
}

console.log('\n=== §2 · ⚑ A REAL SIGNED TOKEN, verifiable without trusting the caller ===');
{
  const ctx = await openContext(crypto, grant({ filesystem: 'read' }, { calls: 3 }));
  ok(typeof ctx.id === 'string' && ctx.id.length > 20, 'the context has a real Ed25519 identity');

  const a = await sealedAdmit(crypto, ctx, need('filesystem', 'read'));
  ok(a.ok === true && a.by === 'both', 'an allowed action passes BOTH gates');
  ok(a.token && a.token.sig, 'and comes back with a signed token');
  ok((await verifySealed(crypto, a.token)).ok === true, 'which verifies');
  ok(a.token.type === 'filesystem:read', 'the token names the action it permitted');
  ok(a.token.id === ctx.id, 'and the identity that permitted it');
}

console.log('\n=== §3 · a forged or tampered token does NOT verify ===');
{
  const ctx = await openContext(crypto, grant({ filesystem: 'read' }, { calls: 3 }));
  const a = await sealedAdmit(crypto, ctx, need('filesystem', 'read'));

  const escalated = { ...a.token, type: 'shell:admin' };
  ok((await verifySealed(crypto, escalated)).ok === false, 'changing the action after signing breaks the signature');
  const cheaper = { ...a.token, cost: 0 };
  ok((await verifySealed(crypto, cheaper)).ok === false, 'so does changing the cost');
  const richer = { ...a.token, budgetTotal: 999999 };
  ok((await verifySealed(crypto, richer)).ok === false, 'and so does inflating the budget');
  ok((await verifySealed(crypto, null)).ok === false, 'a missing token is refused');
  ok((await verifySealed(crypto, { type: 'x' })).ok === false, 'and so is one with no signature at all');

  const other = await openContext(crypto, grant({ shell: 'admin' }, { calls: 9 }));
  const impostor = { ...a.token, id: other.id };
  ok((await verifySealed(crypto, impostor)).ok === false, 'a token cannot be re-attributed to another identity');
}

console.log('\n=== §4 · ⚑ A REFUSED ACTION LEAVES NO SIGNATURE ===');
{
  // This is what makes the signature worth anything: it can only exist if the action was permitted.
  const ctx = await openContext(crypto, grant({ filesystem: 'read' }, { calls: 5 }));
  const no = await sealedAdmit(crypto, ctx, need('shell', 'admin'));
  ok(no.ok === false && no.token === null, 'an escalation gets no token');
  ok(no.by === 'openkonomi', 'refused by the local gate, which is asked first');
  ok(no.code === 'capability', 'with the reason typed');
  ok(remaining(ctx.grant).calls === 5, 'and NOTHING was charged — refusals are free on both sides');
  ok(ctx.wallet.budget.spent === 0, 'including the wallet, which was never asked');
}

console.log('\n=== §5 · both budgets stay in step ===');
{
  const ctx = await openContext(crypto, grant({ network: 'read' }, { calls: 2 }));
  await sealedAdmit(crypto, ctx, need('network', 'read'));
  ok(ctx.wallet.budget.spent === 1 && remaining(ctx.grant).calls === 1, 'one action spends one on each side');
  await sealedAdmit(crypto, ctx, need('network', 'read'));
  const over = await sealedAdmit(crypto, ctx, need('network', 'read'));
  ok(over.ok === false, 'the third is refused');
  ok(over.by === 'openkonomi' && /budget/.test(over.code), 'by the local ceiling, which is reached first and costs nothing to enforce');
  ok(ctx.wallet.budget.spent === 2, 'and the wallet was not spent past its own total either');
}

console.log('\n=== §6 · an unbounded grant still yields a usable wallet ===');
{
  const ctx = await openContext(crypto, grant({ network: 'read' }));
  const a = await sealedAdmit(crypto, ctx, need('network', 'read'));
  ok(a.ok === true, 'an unbounded grant can still act');
  ok(Number.isFinite(ctx.wallet.budget.total), 'the wallet gets a finite stand-in rather than Infinity, which cannot be signed meaningfully');
}

console.log('\n=== §7 · THE ESTATE’S OWN MODULE FORMAT goes through the same gate ===');
{
  // fallrouter's real manifest, verbatim from the repo.
  const fallrouter = {
    name: 'fallrouter', version: '1.0.0', publisher: 'AI-Native Solutions',
    description: 'Multi-LLM router · cost caps · fallback rails',
    provides: ['llm_routing', 'cost_caps', 'fallback_rails'],
    requires: ['byok_adapter@>=1.0.0'], tools: [], kernel_extension: {}, estate: true,
  };
  const r = fromManifest(fallrouter);
  ok(r.admitted === true, 'fallrouter is admitted');
  ok(r.declared.network === 'read', 'routing between model hosts is read on the network, derived from what it PROVIDES');
  ok(r.requires.includes('byok_adapter@>=1.0.0'), 'its requirements are carried through');
  ok(/ADMITTED/.test(r.verdict), 'with a verdict in the same shape a skill gets');

  const unknown = fromManifest({ name: 'x', version: '1.0.0', provides: ['mind_reading'] });
  ok(unknown.admitted === false, 'an unclassified capability is NOT waved through');
  ok(unknown.unknown.includes('mind_reading'), 'it is named');
  ok(unknown.problems.some(p => p.kind === 'unclassified'), 'and reported as unclassified rather than assumed harmless');

  const extender = fromManifest({ name: 'y', version: '1.0.0', provides: [], kernel_extension: { patch: 'core' } });
  ok(extender.admitted === false && extender.problems.some(p => p.kind === 'kernel_extension'),
    'a module that modifies the kernel is refused — that is outside what any capability grant can bound');

  ok(fromManifest({}).admitted === false, 'a manifest with no name or version is refused');
  ok(fromManifest(null).problems.length > 0, 'and null does not throw');
  ok(fromManifest({ name: 'z', version: '1', provides: [] }).admitted === true, 'a module that claims nothing is fine');
  ok(/1 problem\./.test(fromManifest({ name: 'q', provides: [] }).verdict), 'one problem reads as singular');
}

console.log('\n=== §8 · the highest level wins, whatever order it was listed in ===');
{
  const up = fromManifest({ name: 'a', version: '1', provides: ['llm_routing', 'webhooks'] });
  const down = fromManifest({ name: 'a', version: '1', provides: ['webhooks', 'llm_routing'] });
  ok(up.declared.network === 'write', 'read then write ends at WRITE');
  ok(down.declared.network === 'write', 'and so does write then read — the order it is listed in cannot lower the power');
  ok(fromManifest({ name: 'a', version: '1', provides: ['llm_routing'] }).declared.network === 'read', 'while routing alone stays read');
}

console.log('\n=== §9 · the manifest report says what it read, not a placeholder ===');
{
  const m = fromManifest({ name: 'fallrecall', version: '2.1.0', description: 'take your AI memory back', provides: ['memory'] });
  ok(m.name === 'fallrecall', 'the real name is reported');
  ok(m.version === '2.1.0', 'the real version is reported');
  ok(m.description === 'take your AI memory back', 'and the real description');
  ok(m.declared.filesystem === 'write', 'memory is filesystem:write — holding your recall means writing it down');

  const bare = fromManifest({ name: 'n', version: '1', provides: [] });
  ok(bare.description === null, 'a missing description is null rather than a made-up string');
  ok(/declares no capabilities/.test(bare.verdict), 'a module claiming nothing says "no capabilities"');
  ok(/declares 1 capability,/.test(fromManifest({ name: 'n', version: '1', provides: ['shell'] }).verdict), 'exactly one reads as singular');
  ok(/declares 2 capabilities,/.test(fromManifest({ name: 'n', version: '1', provides: ['shell', 'webhooks'] }).verdict), 'two read as plural');

  const refused = fromManifest({ name: 'named-but-broken', provides: [] });
  ok(/named-but-broken/.test(refused.verdict), 'a REFUSED module is still named in its verdict — an author has to know which one failed');
  ok(/\(unnamed\)/.test(fromManifest({ version: '1', provides: [] }).verdict), 'and a nameless one says so explicitly');
}

console.log(`\n${fail === 0 ? '✓ MESH GATE CLEAN' : '✗ MESH GATE FAILED'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
