'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT) || 10000;
const PUBLIC_DIR = path.join(__dirname, 'src', 'public');

app.use(express.static(PUBLIC_DIR));
app.get('/health', (_req, res) => res.json({
  status: 'ok', game: 'CrashZone Aviator', phase: state.phase, round: state.roundId
}));
app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

const WAIT_MS = 8000;
const TICK_MS = 100;
const MAX_BET = 1000;
const STARTING_CREDITS = 1000;
const players = new Map();
const bets = new Map();

let state = {
  phase: 'waiting', roundId: 0, multiplier: 1, crashPoint: null,
  roundStartedAt: null, nextRoundAt: Date.now() + WAIT_MS,
  history: [], online: 0
};
let targetCrashAtMs = null;

function randomCrashPoint() {
  // Demo-only weighted outcome table. Supplied weights total 105, so they are
  // treated as relative weights and normalized across 105 tickets.
  // The requested ranges leave 3.00x–4.00x and 1.01x–1.19x unassigned.
  const buckets = [
    { weight: 10, min: 1.00, max: 1.00 },
    { weight: 15, min: 1.20, max: 1.40 },
    { weight: 15, min: 1.40, max: 1.60 },
    { weight: 40, min: 1.60, max: 2.00 },
    { weight: 10, min: 2.00, max: 3.00 },
    { weight: 10, min: 4.00, max: 10.00 },
    { weight: 3, min: 10.00, max: 50.00 },
    { weight: 2, min: 50.00, max: 100.00 }
  ];
  const totalWeight = buckets.reduce((sum, bucket) => sum + bucket.weight, 0);
  let ticket = crypto.randomInt(0, totalWeight);
  let selected = buckets[buckets.length - 1];
  for (const bucket of buckets) {
    if (ticket < bucket.weight) { selected = bucket; break; }
    ticket -= bucket.weight;
  }
  if (selected.min === selected.max) return selected.min;
  const value = selected.min + Math.random() * (selected.max - selected.min);
  return Math.round(value * 100) / 100;
}
function elapsedForMultiplier(m) {
  // Exponential-style growth; shared server timeline determines crash and cash-out.
  return Math.log(Math.max(1, m)) * 9000;
}
function multiplierAtElapsed(ms) {
  return Math.max(1, Math.exp(Math.max(0, ms) / 9000));
}
function publicPlayer(p) {
  return { id: p.id, name: p.name, balance: p.balance };
}
function snapshot() {
  return {
    phase: state.phase, roundId: state.roundId, multiplier: state.multiplier,
    crashPoint: state.crashPoint, roundStartedAt: state.roundStartedAt,
    nextRoundAt: state.nextRoundAt, history: state.history.slice(0, 12),
    online: state.online,
    players: [...players.values()].map(publicPlayer),
    myBetState: null,
    serverTime: Date.now()
  };
}
function broadcast() { io.emit('game:state', snapshot()); }
function sendPlayer(socket) {
  const p = players.get(socket.id);
  if (p) socket.emit('player:state', { ...publicPlayer(p), bet: bets.get(socket.id) || null });
}
function startRound() {
  state.phase = 'running';
  state.roundId += 1;
  state.multiplier = 1;
  state.crashPoint = null;
  state.roundStartedAt = Date.now();
  state.nextRoundAt = null;
  // Keep bets placed during the countdown; they belong to the round that just started.
  for (const bet of bets.values()) bet.roundId = state.roundId;
  const point = randomCrashPoint();
  targetCrashAtMs = elapsedForMultiplier(point);
  state._target = point;
  broadcast();
}
function cashoutPlayer(id, multiplier, automatic = false) {
  const current = players.get(id);
  const bet = bets.get(id);
  if (!current || !bet || bet.cashedOut || bet.status !== 'active') return false;
  const safeMultiplier = Number(multiplier.toFixed(2));
  const payout = Math.floor(bet.amount * safeMultiplier);
  bet.cashedOut = true;
  bet.status = 'cashed_out';
  bet.multiplier = safeMultiplier;
  bet.payout = payout;
  bet.automatic = automatic;
  current.balance += payout;
  io.to(id).emit('bet:result', {
    status: 'cashed_out', amount: bet.amount, multiplier: bet.multiplier,
    payout, balance: current.balance, automatic
  });
  const sock = io.sockets.sockets.get(id);
  if (sock) sendPlayer(sock);
  broadcast();
  return true;
}
function finishRound(point) {
  state.phase = 'crashed';
  state.multiplier = Number(point.toFixed(2));
  state.crashPoint = state.multiplier;
  state.history.unshift({ roundId: state.roundId, crashPoint: state.crashPoint });
  state.history = state.history.slice(0, 12);
  state.nextRoundAt = Date.now() + WAIT_MS;
  targetCrashAtMs = null;
  for (const [id, bet] of bets) {
    if (!bet.cashedOut) {
      bet.status = 'lost';
      const p = players.get(id);
      if (p) io.to(id).emit('bet:result', { status: 'lost', amount: bet.amount, balance: p.balance });
    }
  }
  broadcast();
}
io.on('connection', socket => {
  const p = { id: socket.id, name: `Pilot-${socket.id.slice(0, 4)}`, balance: STARTING_CREDITS };
  players.set(socket.id, p);
  state.online = players.size;
  socket.emit('game:state', snapshot());
  sendPlayer(socket);
  broadcast();

  socket.on('player:name', raw => {
    const current = players.get(socket.id);
    if (!current || typeof raw !== 'string') return;
    const name = raw.trim().replace(/[<>]/g, '').slice(0, 18);
    if (name) current.name = name;
    sendPlayer(socket);
    broadcast();
  });

  socket.on('bet:place', raw => {
    const current = players.get(socket.id);
    if (!current) return;
    if (state.phase !== 'waiting' && state.phase !== 'crashed') return socket.emit('game:error', 'Bets are closed for this round.');
    const previousBet = bets.get(socket.id);
    if (previousBet && previousBet.status === 'active') return socket.emit('game:error', 'You already have an active bet.');
    if (previousBet) bets.delete(socket.id);
    const amount = Number(raw && raw.amount);
    const autoCashoutRaw = Number(raw && raw.autoCashout);
    const autoCashout = Number.isFinite(autoCashoutRaw) && autoCashoutRaw >= 1.01 && autoCashoutRaw <= 100 ? Math.round(autoCashoutRaw * 100) / 100 : null;
    if (!Number.isInteger(amount) || amount < 1 || amount > MAX_BET) {
      return socket.emit('game:error', `Bet must be 1–${MAX_BET} virtual credits.`);
    }
    if (amount > current.balance) return socket.emit('game:error', 'Not enough virtual credits.');
    current.balance -= amount;
    bets.set(socket.id, { amount, cashedOut: false, status: 'active', roundId: state.roundId + 1, autoCashout });
    sendPlayer(socket);
    broadcast();
  });

  socket.on('bet:cashout', () => {
    const current = players.get(socket.id);
    const bet = bets.get(socket.id);
    if (!current || !bet || bet.cashedOut || bet.status !== 'active') {
      return socket.emit('game:error', 'No active bet to cash out.');
    }
    if (state.phase !== 'running' || state.roundStartedAt === null) {
      return socket.emit('game:error', 'Cash-out is only available while the plane is flying.');
    }
    const elapsed = Date.now() - state.roundStartedAt;
    if (targetCrashAtMs === null || elapsed >= targetCrashAtMs) {
      return socket.emit('game:error', 'Too late — the plane has crashed.');
    }
    const multiplier = Math.min(state._target, multiplierAtElapsed(elapsed));
    cashoutPlayer(socket.id, multiplier, false);
  });

  socket.on('disconnect', () => {
    players.delete(socket.id);
    // Bets remain in the round and are not refunded on disconnect.
    state.online = players.size;
    broadcast();
  });
});

setInterval(() => {
  const now = Date.now();
  if (state.phase === 'waiting' || state.phase === 'crashed') {
    if (state.nextRoundAt && now >= state.nextRoundAt) startRound();
    else broadcast();
    return;
  }
  if (state.phase === 'running' && state.roundStartedAt !== null) {
    const elapsed = now - state.roundStartedAt;
    if (targetCrashAtMs !== null && elapsed >= targetCrashAtMs) {
      finishRound(state._target);
      return;
    }
    state.multiplier = Number(multiplierAtElapsed(elapsed).toFixed(2));
    for (const [id, bet] of bets) {
      if (bet.status === 'active' && bet.autoCashout && state.multiplier >= bet.autoCashout && elapsed < targetCrashAtMs) {
        cashoutPlayer(id, bet.autoCashout, true);
      }
    }
    broadcast();
  }
}, TICK_MS);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`CrashZone Aviator listening on port ${PORT}`);
  console.log(`Serving ${PUBLIC_DIR}`);
});
