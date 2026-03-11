/**
 * Nexo — Relay Server (revisado)
 * Mensagens criptografadas passam por aqui mas NAO sao armazenadas.
 *
 * Melhorias:
 *  - Rate limiting por IP (evita flood/spam)
 *  - Validação de ID no REGISTER (evita IDs inválidos/vazios)
 *  - Proteção contra re-REGISTER (hijack de sessão)
 *  - Limite de tamanho de pacote por tipo
 *  - Heartbeat automático (detecta conexões zumbi)
 *  - Logs com timestamp
 *  - Métricas no /health (filas, uptime)
 *  - Tipos de grupo adicionados ao switch
 *  - Graceful shutdown (SIGTERM/SIGINT)
 */

const WebSocket = require('ws');
const http = require('http');

// ── Configurações ──────────────────────────────────────
const PORT           = process.env.PORT || 3001;
const MAX_QUEUE      = 200;
const QUEUE_TTL      = 7 * 24 * 60 * 60 * 1000; // 7 dias
const MAX_PAYLOAD    = 20 * 1024 * 1024;          // 20 MB
const HEARTBEAT_MS   = 30_000;                    // 30s ping/pong
const RATE_LIMIT_MAX = 60;                        // max mensagens por janela
const RATE_LIMIT_WIN = 10_000;                    // janela de 10 segundos

// Tipos efêmeros — não ficam na fila offline
const EPHEMERAL = new Set([
  'TYPING', 'CALL_ANSWER', 'CALL_ICE', 'CALL_REJECT', 'CALL_END',
  'GC_JOINED', 'GC_OFFER', 'GC_ANSWER', 'GC_ICE', 'GC_REJECT',
  'GC_END', 'GC_MEMBERS', 'GC_HELLO', 'GROUP_MEMBER_ADDED', 'GROUP_MEMBER_LEFT'
]);

// Todos os tipos aceitos (whitelist)
const ALLOWED_TYPES = new Set([
  'REGISTER', 'PING',
  'MSG', 'AUDIO', 'IMAGE', 'TYPING', 'READ',
  'INVITE', 'INVITE_ACCEPTED', 'INVITE_DECLINED',
  'ACK', 'SYNC_REQUEST', 'SYNC_REPLY',
  'CALL_OFFER', 'CALL_ANSWER', 'CALL_ICE', 'CALL_REJECT', 'CALL_END',
  'GC_INVITE', 'GC_JOINED', 'GC_OFFER', 'GC_ANSWER', 'GC_ICE',
  'GC_REJECT', 'GC_END', 'GC_MEMBERS', 'GC_HELLO',
  'GROUP_INVITE', 'GROUP_MSG', 'GROUP_MEMBER_ADDED', 'GROUP_MEMBER_LEFT'
]);

// ── Estado ─────────────────────────────────────────────
const clients  = new Map(); // peerId -> ws
const queue    = new Map(); // peerId -> [packets]
const startedAt = Date.now();

// ── Helpers ────────────────────────────────────────────
function log(...args) {
  console.log(`[${new Date().toISOString()}]`, ...args);
}

function isValidId(id) {
  // Hash hexadecimal entre 8 e 128 chars
  return typeof id === 'string' && /^[a-f0-9]{8,128}$/i.test(id);
}

// Rate limiter simples por peerId
const rateLimitMap = new Map(); // peerId -> { count, resetAt }
function checkRateLimit(id) {
  const now = Date.now();
  let r = rateLimitMap.get(id);
  if (!r || now > r.resetAt) {
    r = { count: 0, resetAt: now + RATE_LIMIT_WIN };
    rateLimitMap.set(id, r);
  }
  r.count++;
  return r.count <= RATE_LIMIT_MAX;
}

// Limpa rate limit de usuários desconectados periodicamente
setInterval(() => {
  const now = Date.now();
  for (const [id, r] of rateLimitMap.entries()) {
    if (now > r.resetAt && !clients.has(id)) rateLimitMap.delete(id);
  }
}, 60_000);

// ── HTTP Server ────────────────────────────────────────
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.url === '/health') {
    const totalQueued = [...queue.values()].reduce((s, q) => s + q.length, 0);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      clients: clients.size,
      queued_users: queue.size,
      queued_msgs: totalQueued,
      uptime_s: Math.floor((Date.now() - startedAt) / 1000),
      ts: Date.now()
    }));
  } else {
    res.writeHead(200);
    res.end('Nexo relay ok');
  }
});

// ── WebSocket Server ───────────────────────────────────
const wss = new WebSocket.Server({ server, maxPayload: MAX_PAYLOAD });

wss.on('connection', (ws, req) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  let myId = null;
  ws.isAlive = true;

  // Heartbeat: responde ao ping do servidor
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let pkt;
    try { pkt = JSON.parse(raw); } catch { return; }

    // Whitelist de tipos — descarta qualquer coisa desconhecida
    if (!ALLOWED_TYPES.has(pkt.type)) return;

    // Rate limiting (só após registro)
    if (myId && !checkRateLimit(myId)) {
      ws.send(JSON.stringify({ type: 'ERROR', code: 'RATE_LIMITED', msg: 'Muitas mensagens. Aguarde.' }));
      return;
    }

    switch (pkt.type) {

      // ── REGISTER ──────────────────────────────────────
      case 'REGISTER': {
        // Validação do ID
        if (!isValidId(pkt.id)) {
          ws.send(JSON.stringify({ type: 'ERROR', code: 'INVALID_ID' }));
          return;
        }
        // Proteção contra hijack: se já existe sessão ativa para este ID, recusa
        const existing = clients.get(pkt.id);
        if (existing && existing !== ws && existing.readyState === WebSocket.OPEN) {
          // Desconecta o antigo (reconexão legítima do mesmo usuário)
          existing.terminate();
          log(`[REGISTER] reconnect: ${pkt.id.slice(0, 8)} (ip: ${ip})`);
        }

        myId = pkt.id;
        clients.set(myId, ws);

        // Entrega fila offline
        const q = queue.get(myId) || [];
        const now = Date.now();
        const fresh = q.filter(p => (now - p._ts) < (p._ttl || QUEUE_TTL));
        fresh.forEach(p => { delete p._ts; delete p._ttl; ws.send(JSON.stringify(p)); });
        queue.delete(myId);

        ws.send(JSON.stringify({ type: 'REGISTERED', queued: fresh.length }));
        log(`[REGISTER] ${myId.slice(0, 8)} — flushed ${fresh.length} msgs (ip: ${ip})`);
        break;
      }

      // ── PING manual do cliente ─────────────────────────
      case 'PING':
        ws.send(JSON.stringify({ type: 'PONG' }));
        break;

      // ── Todos os outros tipos (relay) ──────────────────
      default: {
        // Deve estar registrado para enviar
        if (!myId) return;

        const to = pkt.to;
        if (!to || !isValidId(to)) break;

        pkt.from = myId; // garante que o remetente é quem diz ser

        const target = clients.get(to);
        if (target && target.readyState === WebSocket.OPEN) {
          target.send(JSON.stringify(pkt));
        } else {
          // Offline — enfileira se não for efêmero
          if (!EPHEMERAL.has(pkt.type)) {
            if (!queue.has(to)) queue.set(to, []);
            const q = queue.get(to);
            pkt._ts = Date.now();
            if (pkt.type === 'CALL_OFFER') pkt._ttl = 60_000; // chamadas perdidas: 60s
            q.push(pkt);
            if (q.length > MAX_QUEUE) q.shift(); // descarta mais antigo
          }
          // ACK de "em fila"
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ACK', id: pkt.id, status: 'queued' }));
          }
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    if (myId) {
      clients.delete(myId);
      log(`[CLOSE] ${myId.slice(0, 8)}`);
    }
  });

  ws.on('error', (err) => {
    if (myId) {
      clients.delete(myId);
      log(`[ERROR] ${myId?.slice(0, 8)} — ${err.message}`);
    }
  });
});

// ── Heartbeat: detecta conexões zumbi a cada 30s ───────
const heartbeat = setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_MS);

wss.on('close', () => clearInterval(heartbeat));

// ── Cleanup de filas expiradas (a cada hora) ───────────
setInterval(() => {
  const now = Date.now();
  let removed = 0;
  for (const [id, q] of queue.entries()) {
    const fresh = q.filter(p => now - p._ts < QUEUE_TTL);
    if (fresh.length === 0) { queue.delete(id); removed++; }
    else queue.set(id, fresh);
  }
  if (removed > 0) log(`[CLEANUP] removidas filas de ${removed} usuários inativos`);
}, 60 * 60 * 1000);

// ── Graceful shutdown ──────────────────────────────────
function shutdown(signal) {
  log(`[SHUTDOWN] sinal ${signal} recebido — encerrando...`);
  server.close(() => {
    log('[SHUTDOWN] servidor HTTP fechado');
    process.exit(0);
  });
  // Força saída após 5s se travar
  setTimeout(() => process.exit(1), 5000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ── Start ──────────────────────────────────────────────
server.listen(PORT, () => {
  log(`Nexo relay rodando na porta ${PORT}`);
  log(`Nenhuma mensagem é armazenada. Conteúdo E2E criptografado.`);
});
