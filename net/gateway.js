#!/usr/bin/env node
// gateway.js — the only way out of an agent-cleanroom network.
//
// The agent container sits on a Docker network created with --internal: it has
// no route to the host or the internet. This gateway is attached to that
// network *and* to a normal one, and passes on exactly what a run declared:
//
//   ACR_FORWARDS       "11434=host.docker.internal:11435,8080=host.docker.internal:9000"
//                      fixed TCP forwards: a connection to gateway:<listen>
//                      is piped to <host>:<port>. Nothing else is reachable
//                      through a forward.
//   ACR_CONNECT_PORT   port of an HTTP CONNECT proxy (optional)
//   ACR_CONNECT_ALLOW  "api.anthropic.com:443" — the only CONNECT targets the
//                      proxy accepts (exact host:port, case-insensitive).
//                      Everything else gets 403; non-CONNECT requests get 405.
//   ACR_BIND           listen address (default 0.0.0.0)
//
// One JSON line per decision goes to stderr (target and verdict only — never
// request headers, which can carry credentials). A {"event":"ready"} line on
// stdout tells the caller that every listener is up.
// Only Node core modules are used, so the base image needs nothing extra.
'use strict';
const net = require('net');

const HEADER_LIMIT = 8192;
const HEADER_TIMEOUT_MS = 10000;

function log(obj) {
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), ...obj }) + '\n');
}

function parseHostPort(s) {
  const t = String(s).trim();
  const m = t.match(/^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/) || t.match(/^([A-Za-z0-9.-]+):(\d{1,5})$/);
  if (!m) return null;
  const port = Number(m[2]);
  if (!(port >= 1 && port <= 65535)) return null;
  return { host: m[1].toLowerCase(), port };
}

function parseForwards(spec) {
  const out = [];
  for (const item of String(spec || '').split(',').map((x) => x.trim()).filter(Boolean)) {
    const eq = item.indexOf('=');
    const listen = Number(item.slice(0, eq));
    const target = parseHostPort(item.slice(eq + 1));
    if (eq < 1 || !(listen >= 1 && listen <= 65535) || !target) {
      throw new Error(`bad ACR_FORWARDS entry: ${item}`);
    }
    out.push({ listen, target });
  }
  return out;
}

function parseAllow(spec) {
  const allow = new Set();
  for (const item of String(spec || '').split(',').map((x) => x.trim()).filter(Boolean)) {
    const hp = parseHostPort(item);
    if (!hp) throw new Error(`bad ACR_CONNECT_ALLOW entry: ${item}`);
    allow.add(`${hp.host}:${hp.port}`);
  }
  return allow;
}

function pipeBoth(a, b) {
  a.on('error', () => b.destroy());
  b.on('error', () => a.destroy());
  a.pipe(b);
  b.pipe(a);
}

function startForward(bind, f) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((client) => {
      const upstream = net.connect(f.target.port, f.target.host);
      log({ event: 'forward', listen: f.listen, to: `${f.target.host}:${f.target.port}` });
      upstream.on('error', (e) => {
        log({ event: 'forward-error', listen: f.listen, code: e.code || 'error' });
        client.destroy();
      });
      upstream.on('connect', () => pipeBoth(client, upstream));
      client.on('error', () => upstream.destroy());
    });
    server.on('error', reject);
    server.listen(f.listen, bind, () => resolve(server));
  });
}

function reply(sock, code, text) {
  sock.end(`HTTP/1.1 ${code} ${text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
}

function startConnectProxy(bind, port, allow) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((client) => {
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => client.destroy(), HEADER_TIMEOUT_MS);
      client.on('error', () => clearTimeout(timer));
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const end = buf.indexOf('\r\n\r\n');
        if (end < 0) {
          if (buf.length > HEADER_LIMIT) { clearTimeout(timer); reply(client, 431, 'Request Header Fields Too Large'); }
          return;
        }
        client.removeListener('data', onData);
        clearTimeout(timer);
        const requestLine = buf.slice(0, buf.indexOf('\r\n')).toString('latin1');
        const rest = buf.slice(end + 4);
        const m = requestLine.match(/^(\S+)\s+(\S+)\s+HTTP\/1\.[01]$/);
        if (!m || m[1] !== 'CONNECT') {
          log({ event: 'connect', method: m ? m[1] : 'invalid', allowed: false });
          reply(client, 405, 'Method Not Allowed');
          return;
        }
        const hp = parseHostPort(m[2]);
        const target = hp ? `${hp.host}:${hp.port}` : String(m[2]).slice(0, 255);
        const allowed = Boolean(hp) && allow.has(target);
        log({ event: 'connect', target, allowed });
        if (!allowed) { reply(client, 403, 'Forbidden'); return; }
        const upstream = net.connect(hp.port, hp.host);
        upstream.on('error', (e) => {
          log({ event: 'connect-error', target, code: e.code || 'error' });
          if (!client.destroyed) reply(client, 502, 'Bad Gateway');
        });
        upstream.on('connect', () => {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (rest.length) upstream.write(rest);
          pipeBoth(client, upstream);
        });
      };
      client.on('data', onData);
    });
    server.on('error', reject);
    server.listen(port, bind, () => resolve(server));
  });
}

async function main() {
  const bind = process.env.ACR_BIND || '0.0.0.0';
  const forwards = parseForwards(process.env.ACR_FORWARDS);
  const allow = parseAllow(process.env.ACR_CONNECT_ALLOW);
  const connectPort = process.env.ACR_CONNECT_PORT ? Number(process.env.ACR_CONNECT_PORT) : 0;
  if (!forwards.length && !connectPort) throw new Error('nothing to do: set ACR_FORWARDS and/or ACR_CONNECT_PORT');
  if (connectPort && !(connectPort >= 1 && connectPort <= 65535)) throw new Error('bad ACR_CONNECT_PORT');
  for (const f of forwards) await startForward(bind, f);
  if (connectPort) await startConnectProxy(bind, connectPort, allow);
  process.stdout.write(JSON.stringify({
    event: 'ready',
    forwards: forwards.map((f) => `${f.listen}=${f.target.host}:${f.target.port}`),
    connect_port: connectPort || null,
    connect_allow: [...allow].sort(),
  }) + '\n');
}

if (require.main === module) {
  main().catch((e) => { log({ event: 'fatal', message: e.message }); process.exit(2); });
}

module.exports = { parseForwards, parseAllow, parseHostPort };
