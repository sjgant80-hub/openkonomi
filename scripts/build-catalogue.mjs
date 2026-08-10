// build-catalogue.mjs — GENERATE the organ catalogue from the canonical estate index.
//
// Never hand-typed. The estate has drifted from 1,548 to 1,621 while surfaces went on quoting the
// old number, because someone once wrote a count into a page instead of reading one. A catalogue that
// lists what an agent may install is exactly the kind of thing that must be a READING of the estate,
// not a claim about it.
//
//   node scripts/build-catalogue.mjs
//
// Reads the canonical index, drops the minted -api/-mcp/-sdk companions (they are packaging, not
// organs), classifies what remains into the rooms an agent actually needs, and writes catalogue.json
// with a live URL for every entry.
import { readFileSync, writeFileSync } from 'node:fs';

const INDEX = 'C:/Users/sjgan/.claude/projects/C--Users-sjgan--claude/memory/estate-index.json';
const OUT = new URL('../catalogue.json', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

// The rooms. Order matters: an organ lands in the FIRST room it matches, so the more specific
// patterns come first and nothing is double-counted.
const ROOMS = [
  { id: 'trust', name: 'Trust & identity', why: 'Proving who an agent is and that its work is real.',
    re: /^(witness|earned|acg-assessor|ring-assessor|the-wallet|konomi-signer|fallsignature|falltrust|fallshield|fallsecurity|fallhardened)$/i },
  { id: 'rooms', name: 'Agent rooms', why: 'More than one agent working together, and the conductor that runs them.',
    re: /^(didy|si-didy-.*|fallcolony|fallherd|fallmesh|fallswarm|konomesh|konomi-swarm|fall127agents|ACG-Ballroom|mesh-89-tracker|mesh-sings|fallseed-agents)$/i },
  { id: 'memory', name: 'Memory & recall', why: 'What the agent remembers, and what it is allowed to forget.',
    re: /^(fall-remember|fallrecall|estate-nest|offramp-v2|the-wisp|the-dreamer|the-oracle|seedmind|oracleengine|honestly|fallseed.*)$/i },
  { id: 'models', name: 'Models & routing', why: 'Which brain answers, local first, cloud only if you say so.',
    re: /^(fallrouter|fallrelay|fallcore|fallcore-factory|fallmind|fallmage|fallmirror)$/i },
  { id: 'market', name: 'Markets & registries', why: 'Where tools are listed — and where they are refused.',
    re: /^(fallmarket|fallhub|fall-registry|fallstore|fallforge|forge-lab|fallkard|fallkard-forge|kard|kardv5|roost|tradeshub|trilogy-forge)$/i },
  { id: 'social', name: 'Talking to people', why: 'Mail, feeds and posts — the parts that reach other humans.',
    re: /^(fallmail|fallpost|fallfeed|fallreach|fallecho|fallcarousel|offgridcommunitiessystem)$/i },
  { id: 'clinics', name: 'Clinics & practices', why: 'Ready-made setups for a real business, not a demo.',
    re: /^(fallclinic.*|falldental.*|fallvet.*|fall-vetter|falloptom.*|fallpharm.*|fallphysio.*|fallelder.*)$/i },
];

// What each room implies an organ will reach for. Stated here, once, so the page never guesses.
const ROOM_CAPS = {
  trust:   { filesystem: 'read' },
  rooms:   { skill_invoke: 'write', network: 'read' },
  memory:  { filesystem: 'write' },
  models:  { network: 'read' },
  market:  { network: 'read' },
  social:  { network: 'write' },
  clinics: { filesystem: 'write', network: 'read' },
};

const raw = JSON.parse(readFileSync(INDEX, 'utf8'));
const all = raw.nodes || raw;
const companion = /-(api|mcp|sdk)$/;

const organs = [];
const counted = new Set();

for (const room of ROOMS) {
  for (const r of all) {
    if (companion.test(r.name) || counted.has(r.name)) continue;
    if (!room.re.test(r.name)) continue;
    counted.add(r.name);
    if (!r.live || r.private) continue;                 // only what a visitor can actually open
    organs.push({
      name: r.name,
      room: room.id,
      description: (r.desc || '').trim() || null,       // null, never an invented sentence
      url: `https://sjgant80-hub.github.io/${r.name}/`,
      repo: r.url || `https://github.com/sjgant80-hub/${r.name}`,
      caps: ROOM_CAPS[room.id] || {},
    });
  }
}

const undescribed = organs.filter(o => !o.description).map(o => o.name);

const catalogue = {
  generated_from: 'estate-index.json',
  totals: {
    indexed: all.length,
    organs: organs.length,
    // Stated because a catalogue that shows only what it could classify is reporting a number with
    // the denominator removed.
    live_unclassified: all.filter(r => r.live && !r.private && !companion.test(r.name) && !counted.has(r.name)).length,
    undescribed: undescribed.length,
  },
  rooms: ROOMS.map(r => ({
    id: r.id, name: r.name, why: r.why,
    caps: ROOM_CAPS[r.id] || {},
    count: organs.filter(o => o.room === r.id).length,
  })),
  organs,
  undescribed,
};

writeFileSync(OUT, JSON.stringify(catalogue, null, 1));
console.log(`catalogue.json written · ${organs.length} organs across ${ROOMS.length} rooms`);
for (const r of catalogue.rooms) console.log(`  ${String(r.count).padStart(3)}  ${r.name}`);
console.log(`  ${catalogue.totals.live_unclassified} live organs not in any room (not hidden — counted)`);
if (undescribed.length) console.log(`  ⚠ ${undescribed.length} with no description at source: ${undescribed.slice(0, 8).join(', ')}${undescribed.length > 8 ? '…' : ''}`);
