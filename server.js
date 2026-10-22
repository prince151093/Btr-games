'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const PORT = Number(process.env.PORT) || 10000;
const TICK_MS = 100;
const WAIT_MS = 10_000;

// Time required to travel through each complete multiplier range.
const SEGMENTS = [
  { from: 1, to: 2, ms: 5_000 },
  { from: 2, to: 5, ms: 7_000 },
  { from: 5, to: 10, ms: 6_000 },
  { from: 10, to: 50, ms: 25_000 },
  { from: 50, to: 100, ms: 30_000 }
];

// Outcome weights retained from the project plan. They are normalized at selection time.
const OUTCOME_BUCKETS = [
  { min: 1.00, max: 1.00, weight: 10 },
  { min: 1.20, max: 1.40, weight: 15 },
  { min: 1.40, max: 1.60, weight: 15 },
  { min: 1.60, max: 2.00, weight: 40 },
  { min: 2.00, max: 3.00, weight: 10 },
  { min: 4.00, max: 10.00, weight: 10 },
  { min: 10.00, max: 50.00, weight: 3 },
  { min: 50.00, max: 100.00, weight: 2 }
];

app.use(express.static(path.join(__dirname, 'public')));
app.get('/health', (_req, res) => res.json({ status: 'ok', game: 'CrashZone', phase: state.phase, round: state.roundId }));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

let state = {
  phase: 'waiting',
  roundId: 0,
  multiplier: 1,
  crashPoint: null,
  roundStartedAt: null,
  nextRoundAt: Date.now() + WAIT_MS,
  history: [],
  online: 0
};
let targetCrashAtMs = null;

function chooseCrashPoint() {
  const total = OUTCOME_BUCKETS.reduce((sum, b) => sum + b.weight, 0);
  let pick = Math.random() * total;
  let bucket = OUTCOME_BUCKETS[OUTCOME_BUCKETS.length - 1];
  for (const b of OUTCOME_BUCKETS) {
    pick -= b.weight;
    if (pick < 0) { bucket = b; break; }
  }
  if (bucket.min === bucket.max) return bucket.min;
  return Math.round((bucket.min + Math.random() * (bucket.max - bucket.min)) * 100) / 100;
}

function elapsedForMultiplier(multiplier) {
  if (multiplier <= 1) return 0;
  let elapsed = 0;
  for (const seg of SEGMENTS) {
    if (multiplier >= seg.to) {
      elapsed += seg.ms;
      continue;
    }
    if (multiplier > seg.from) elapsed += ((multiplier - seg.from) / (seg.to - seg.from)) * seg.ms;
    break;
  }
  return elapsed;
}

function multiplierAtElapsed(elapsedMs) {
  let remaining = Math.max(0, elapsedMs);
  for (const seg of SEGMENTS) {
    if (remaining >= seg.ms) {
      remaining -= seg.ms;
      continue;
    }
    const fraction = remaining / seg.ms;
    return seg.from + fraction * (seg.to - seg.from);
  }
  return 100;
}

function snapshot() {
  return {
    phase: state.phase,
    roundId: state.roundId,
    multiplier: state.multiplier,
    crashPoint: state.crashPoint,
    roundStartedAt: state.roundStartedAt,
    nextRoundAt: state.nextRoundAt,
    history: state.history.slice(0, 10),
    online: state.online,
    serverTime: Date.now()
  };
}

function broadcast() { io.emit('game:state', snapshot()); }

function startRound() {
  state.phase = 'running';
  state.roundId += 1;
  state.multiplier = 1;
  state.crashPoint = null;
  state.roundStartedAt = Date.now();
  state.nextRoundAt = null;
  const target = chooseCrashPoint();
  targetCrashAtMs = elapsedForMultiplier(target);
  // An outcome of 1.00x crashes immediately at the start of the round.
  if (target <= 1) finishRound(1.00);
  else broadcast();
}

function finishRound(point) {
  state.phase = 'crashed';
  state.multiplier = Number(point.toFixed(2));
  state.crashPoint = state.multiplier;
  state.history.unshift({ roundId: state.roundId, crashPoint: state.crashPoint });
  state.history = state.history.slice(0, 10);
  state.nextRoundAt = Date.now() + WAIT_MS;
  targetCrashAtMs = null;
  broadcast();
}

io.on('connection', socket => {
  state.online += 1;
  socket.emit('game:state', snapshot());
  broadcast();
  socket.on('disconnect', () => {
    state.online = Math.max(0, state.online - 1);
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
  if (state.phase === 'running' && state.roundStartedAt != null) {
    const elapsed = now - state.roundStartedAt;
    if (targetCrashAtMs != null && elapsed >= targetCrashAtMs) {
      finishRound(state.crashPoint == null ? multiplierAtElapsed(targetCrashAtMs) : state.crashPoint);
      return;
    }
    state.multiplier = Math.min(100, Number(multiplierAtElapsed(elapsed).toFixed(2)));
    broadcast();
  }
}, TICK_MS);

server.listen(PORT, '0.0.0.0', () => console.log(`CrashZone listening on ${PORT}`));
