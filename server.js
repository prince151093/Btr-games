'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

const PORT = Number(process.env.PORT) || 10000;
const TICK_MS = 100;
const WAIT_MS = 10_000;

// Correct path: index.html is inside src/public/
const PUBLIC_DIR = path.join(__dirname, 'src', 'public');

app.use(express.static(PUBLIC_DIR));

// Shared game state
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

// Multiplier progression
const SEGMENTS = [
  { from: 1, to: 2, ms: 5_000 },
  { from: 2, to: 5, ms: 7_000 },
  { from: 5, to: 10, ms: 6_000 },
  { from: 10, to: 50, ms: 25_000 },
  { from: 50, to: 100, ms: 30_000 }
];

// Crash outcome weights
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

// Health check
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    game: 'CrashZone',
    phase: state.phase,
    round: state.roundId
  });
});

// Serve the main page from the correct directory
app.get('/', (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Handle missing pages
app.use((req, res, next) => {
  if (req.path.startsWith('/socket.io/')) {
    return next();
  }

  res.status(404).send('Page not found');
});

// Select a crash multiplier
function chooseCrashPoint() {
  const total = OUTCOME_BUCKETS.reduce(
    (sum, bucket) => sum + bucket.weight,
    0
  );

  let pick = Math.random() * total;
  let selected = OUTCOME_BUCKETS[OUTCOME_BUCKETS.length - 1];

  for (const bucket of OUTCOME_BUCKETS) {
    pick -= bucket.weight;

    if (pick < 0) {
      selected = bucket;
      break;
    }
  }

  if (selected.min === selected.max) {
    return selected.min;
  }

  return Math.round(
    (
      selected.min +
      Math.random() * (selected.max - selected.min)
    ) * 100
  ) / 100;
}

// Calculate elapsed time for a multiplier
function elapsedForMultiplier(multiplier) {
  if (multiplier <= 1) return 0;

  let elapsed = 0;

  for (const segment of SEGMENTS) {
    if (multiplier >= segment.to) {
      elapsed += segment.ms;
      continue;
    }

    if (multiplier > segment.from) {
      elapsed +=
        ((multiplier - segment.from) /
          (segment.to - segment.from)) *
        segment.ms;
    }

    break;
  }

  return elapsed;
}

// Calculate multiplier from elapsed time
function multiplierAtElapsed(elapsedMs) {
  let remaining = Math.max(0, elapsedMs);

  for (const segment of SEGMENTS) {
    if (remaining >= segment.ms) {
      remaining -= segment.ms;
      continue;
    }

    const fraction = remaining / segment.ms;

    return (
      segment.from +
      fraction * (segment.to - segment.from)
    );
  }

  return 100;
}

// Create the current game snapshot
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

// Broadcast game state to all connected clients
function broadcast() {
  io.emit('game:state', snapshot());
}

// Finish the current round
function finishRound(point) {
  state.phase = 'crashed';
  state.multiplier = Number(point.toFixed(2));
  state.crashPoint = state.multiplier;

  state.history.unshift({
    roundId: state.roundId,
    crashPoint: state.crashPoint
  });

  state.history = state.history.slice(0, 10);
  state.nextRoundAt = Date.now() + WAIT_MS;
  targetCrashAtMs = null;

  broadcast();
}

// Start a new round
function startRound() {
  state.phase = 'running';
  state.roundId += 1;
  state.multiplier = 1;
  state.crashPoint = null;
  state.roundStartedAt = Date.now();
  state.nextRoundAt = null;

  const target = chooseCrashPoint();
  targetCrashAtMs = elapsedForMultiplier(target);

  // A 1.00x result crashes immediately
  if (target <= 1) {
    finishRound(1.00);
  } else {
    broadcast();
  }
}

// Socket.IO connections
io.on('connection', socket => {
  state.online += 1;

  socket.emit('game:state', snapshot());
  broadcast();

  socket.on('disconnect', () => {
    state.online = Math.max(0, state.online - 1);
    broadcast();
  });
});

// Game loop
setInterval(() => {
  const now = Date.now();

  if (state.phase === 'waiting' || state.phase === 'crashed') {
    if (state.nextRoundAt && now >= state.nextRoundAt) {
      startRound();
    } else {
      broadcast();
    }

    return;
  }

  if (
    state.phase === 'running' &&
    state.roundStartedAt !== null
  ) {
    const elapsed = now - state.roundStartedAt;

    if (
      targetCrashAtMs !== null &&
      elapsed >= targetCrashAtMs
    ) {
      finishRound(multiplierAtElapsed(targetCrashAtMs));
      return;
    }

    state.multiplier = Math.min(
      100,
      Number(multiplierAtElapsed(elapsed).toFixed(2))
    );

    broadcast();
  }
}, TICK_MS);

// Start the HTTP server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`CrashZone listening on port ${PORT}`);
  console.log(`Serving website from: ${PUBLIC_DIR}`);
});
