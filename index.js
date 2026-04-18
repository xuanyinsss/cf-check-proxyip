import { connect } from 'cloudflare:sockets';

const TMO = 5000;  // Timeout in milliseconds
const RDL = 65536; // Read limit
const EOL = Uint8Array.of(13, 10);  // End of line for HTTP response
const SEP = Uint8Array.of(13, 10, 13, 10);  // Separators for HTTP response
const SRE = /^HTTP\/\d\.\d\s+(\d{3})/;  // Regex for HTTP status
const CRE = /\r\ntransfer-encoding:\s*chunked\r\n/i;  // Regex for transfer encoding
const USE = ['GET /probe?candidate=118.34.215.56:34042', 'GET /probe?candidates=1.1.1.1:443,2.2.2.2:443', 'POST JSON {"candidate":"118.34.215.56:34042"}'];

const js = (data, status = 200) => new Response(JSON.stringify(data, null, 2), {
  status,
  headers: { 'content-type': 'application/json;charset=utf-8' }
});

// Utility functions
const uq = v => [...new Set((Array.isArray(v) ? v : `${v ?? ''}`.split(/[\s,]+/)).map(x => `${x ?? ''}`.trim()).filter(Boolean))];
const pi = (v, d) => ((n) => Number.isFinite(n) && n > 0 ? n : d)(Number.parseInt(`${v ?? ''}`, 10));

const inp = async req => {
  const sp = new URL(req.url).searchParams;
  const txt = req.method === 'POST' ? await req.text() : '';
  const x = txt ? JSON.parse(txt) : {};
  const raw = x.candidates ?? x.candidate ?? sp.get('candidates') ?? sp.get('candidate');
  return {
    cs: uq(raw),
    to: pi(x.timeoutMs ?? sp.get('timeoutMs'), TMO),
    rl: pi(x.readLimit ?? sp.get('readLimit'), RDL)
  };
};

// Function to parse the candidate address (IP or domain)
const pc = (c, d = 443) => {
  const [, h = c, p] = c.match(/^([^:]+):(\d+)$/) ?? [];
  return { r: c, h, p: Number(p) || d };
};

// Scan function to check the connection
const scan = async (raw, to, rl) => {
  const c = pc(raw);

  try {
    const socket = connect({ hostname: c.h, port: c.p });

    const t0 = Date.now();
    await socket.opened;
    const delay = Date.now() - t0;

    socket.close();

    return {
      candidate: raw,
      ok: true,
      delay,
      supports_ipv4: true,
      supports_ipv6: false,
      probe_results: []
    };

  } catch (e) {
    return {
      candidate: raw,
      ok: false,
      error: String(e.message || e)
    };
  }
};

// Worker entry point for handling requests
export default {
  async fetch(req) {
    try {
      const { cs, to, rl } = await inp(req);

      if (!cs.length) {
        return js({
          ok: false,
          error: 'missing candidate',
          usage: USE
        }, 400);
      }

      const results = await Promise.all(cs.map(c => scan(c, to, rl)));

      return js(results.length === 1 ? results[0] : results);

    } catch (e) {
      return js({ ok: false, error: String(e?.message || e) }, 500);
    }
  }
};
