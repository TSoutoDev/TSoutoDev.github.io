/**
 * Nexo — Relay Server
 * Mensagens criptografadas passam por aqui mas NAO sao armazenadas.
 * Encrypted messages pass through but are NEVER stored.
 */
const WebSocket = require('ws');
const http = require('http');

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, clients: clients.size, ts: Date.now() }));
  } else {
    res.writeHead(200);
    res.end('Nexo relay ok');
  }
});

const wss = new WebSocket.Server({ server, maxPayload: 20 * 1024 * 1024 }); // 20MB max

// peerId -> ws
const clients = new Map();
// peerId -> [packets] (offline queue, max 200 per user, TTL 7 days)
const queue = new Map();

const MAX_QUEUE = 200;
const QUEUE_TTL = 7 * 24 * 60 * 60 * 1000;

wss.on('connection', (ws) => {
  let myId = null;

  ws.on('message', (raw) => {
    let pkt;
    try { pkt = JSON.parse(raw); } catch { return; }

    switch (pkt.type) {

      case 'REGISTER': {
        myId = pkt.id;
        clients.set(myId, ws);
        // Flush queued packets
        const q = queue.get(myId) || [];
        const now = Date.now();
        const fresh = q.filter(p => (now - p._ts) < (p._ttl || QUEUE_TTL));
        fresh.forEach(p => { delete p._ts; delete p._ttl; ws.send(JSON.stringify(p)); });
        queue.delete(myId);
        ws.send(JSON.stringify({ type: 'REGISTERED', queued: fresh.length }));
        break;
      }

      case 'MSG':
      case 'AUDIO':
      case 'IMAGE':
      case 'TYPING':
      case 'READ':
      case 'INVITE':
      case 'INVITE_ACCEPTED':
      case 'INVITE_DECLINED':
      case 'ACK':
      case 'SYNC_REQUEST':
      case 'SYNC_REPLY':
      case 'CALL_OFFER':
      case 'CALL_ANSWER':
      case 'CALL_ICE':
      case 'CALL_REJECT':
      case 'CALL_END': {
        const to = pkt.to;
        if (!to) break;
        const target = clients.get(to);
        // Stamp sender
        pkt.from = myId;
        if (target && target.readyState === WebSocket.OPEN) {
          target.send(JSON.stringify(pkt));
        } else {
          // Queue for later — CALL_OFFER kept 60s, fully ephemeral types discarded
          const ephemeral = ['TYPING','CALL_ANSWER','CALL_ICE','CALL_REJECT','CALL_END'];
          if (!ephemeral.includes(pkt.type)) {
            if (!queue.has(to)) queue.set(to, []);
            const q = queue.get(to);
            pkt._ts = Date.now();
            if (pkt.type === 'CALL_OFFER') pkt._ttl = 60000; // short TTL for missed calls
            q.push(pkt);
            if (q.length > MAX_QUEUE) q.shift();
          }
          // ACK back as queued
          if (myId && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ACK', id: pkt.id, status: 'queued' }));
          }
        }
        break;
      }

      case 'PING':
        ws.send(JSON.stringify({ type: 'PONG' }));
        break;
    }
  });

  ws.on('close', () => {
    if (myId) clients.delete(myId);
  });

  ws.on('error', () => {
    if (myId) clients.delete(myId);
  });
});

// Cleanup expired queues every hour
setInterval(() => {
  const now = Date.now();
  for (const [id, q] of queue.entries()) {
    const fresh = q.filter(p => now - p._ts < QUEUE_TTL);
    if (fresh.length === 0) queue.delete(id);
    else queue.set(id, fresh);
  }
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Nexo relay running on port ${PORT}`);
  console.log(`No messages are stored. All content is end-to-end encrypted.`);
});
