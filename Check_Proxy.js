import { connect } from 'cloudflare:sockets';

/**
 * merged worker
 * TLS + target worker
 */

// Helper functions and constants
const TMO = 5000;
const RDL = 65536;
const EOL = Uint8Array.of(13, 10);
const SEP = Uint8Array.of(13, 10, 13, 10);

// Utility functions for processing requests and candidates
const js = (data, status = 200) => 
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'content-type': 'application/json;charset=utf-8' }
  });

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

const pc = (c, d = 443) => {
  const [, h = c, p] = c.match(/^([^:]+):(\d+)$/) ?? [];
  return { r: c, h, p: Number(p) || d };
};

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

/**
 * ================== GUI HTML for Proxy Checker ====================
 */

const GUI_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Proxy Checker Pro+</title>
<style>
body { font-family: Arial; background:#0f172a; color:#fff; padding:20px; }
textarea { width:100%; height:120px; border-radius:10px; padding:10px; }
button { margin-top:10px; padding:10px 15px; border:none; border-radius:8px; background:#22c55e; cursor:pointer; }
table { width:100%; margin-top:20px; border-collapse: collapse; }
td, th { padding:10px; border-bottom:1px solid #333; text-align:left; }
.ok { color:#22c55e; }
.fail { color:#ef4444; }
.fast { color:#22c55e; }
.mid { color:#facc15; }
.slow { color:#ef4444; }
</style>
</head>
<body>

<h2>🚀 Proxy Checker Pro+</h2>

<textarea id="ips" placeholder="请输入IP，每行一个：
1.1.1.1:443
8.8.8.8:443"></textarea>

<br>
<button onclick="start()">开始检测</button>
<button onclick="copy()">一键复制</button>

<table id="table">
<thead>
<tr>
<th>IP</th>
<th>状态</th>
<th>延迟</th>
<th>类型</th>
<th>国家</th>
<th>地区</th>
<th>ASN</th>
<th>运营商</th>
</tr>
</thead>
<tbody></tbody>
</table>

<script>
let results = [];

function speedClass(ms) {
  if (ms < 300) return "fast";
  if (ms < 1000) return "mid";
  return "slow";
}

async function start() {
  const lines = document.getElementById("ips").value
    .split("\\n")
    .map(x => x.trim())
    .filter(Boolean);

  const tbody = document.querySelector("#table tbody");
  tbody.innerHTML = "";
  results = [];

  await Promise.all(lines.map(async ip => {
    const t0 = Date.now();

    let data = {}, ok = false;

    try {
      const res = await fetch(`https://你的workers地址/?candidate=${ip}`);
      data = await res.json();
      ok = data.ok;
    } catch (e) {
      data = { error: e.message };
    }

    const delay = Date.now() - t0;
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${ip}</td>
      <td class="${ok ? 'ok' : 'fail'}">${ok ? '成功' : '失败'}</td>
      <td class="${speedClass(delay)}">${delay} ms</td>
      <td>IPv4</td>
      <td>${data?.exitCountry || ''}</td>
      <td>${data?.exitRegion || ''}</td>
      <td>${data?.exitAsn || ''}</td>
      <td>${data?.exitOrg || ''}</td>
    `;
    tbody.appendChild(row);
  }));
}

function copy() {
  const ips = document.getElementById("ips").value;
  navigator.clipboard.writeText(ips).then(() => {
    alert("IP 已复制到剪贴板！");
  });
}
</script>

</body>
</html>
`;

export default {
  async fetch(req) {
    if (req.method === 'GET') {
      const url = new URL(req.url);
      if (url.pathname === '/') {
        return new Response(GUI_HTML, { headers: { 'Content-Type': 'text/html' } });
      }
    }

    try {
      const { cs, to, rl } = await inp(req);

      if (!cs.length) {
        return js({
          ok: false,
          error: 'missing candidate',
          usage: ['GET /probe?candidate=1.1.1.1:443', 'GET /probe?candidates=1.1.1.1:443,8.8.8.8:443', 'POST JSON {"candidate":"1.1.1.1:443"}']
        }, 400);
      }

      const results = await Promise.all(cs.map(c => scan(c, to, rl)));

      return js(results.length === 1 ? results[0] : results);

    } catch (e) {
      return js({ ok: false, error: String(e?.message || e) }, 500);
    }
  }
};
