// serve.mjs — a static server for checking the page locally. Not shipped behaviour; Pages serves the
// real thing. Kept because "it works on my disk" is not the same claim as "it works when served".
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const ROOT = new URL('.', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const PORT = Number(process.env.PORT || 8270);
const TYPES = { '.html': 'text/html', '.mjs': 'text/javascript', '.js': 'text/javascript', '.json': 'application/json' };

createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p === '/') p = '/index.html';
    const safe = normalize(p).split(/[\\/]/).filter(s => s && s !== '..').join('/');
    const body = await readFile(join(ROOT, safe));
    res.writeHead(200, { 'content-type': TYPES[extname(safe)] || 'application/octet-stream' });
    res.end(body);
  } catch { res.writeHead(404); res.end('404'); }
}).listen(PORT, () => console.log('openkonomi on http://localhost:' + PORT));
