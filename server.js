'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT) || 10000;
const PUBLIC_DIR = path.join(__dirname, 'src', 'public');

app.use(express.json({ limit: '20kb' }));
app.use(express.static(PUBLIC_DIR));

// Supabase-backed account store. Keep the service-role key server-side only.
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!supabaseUrl || !supabaseKey) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variable.');
  process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseKey, { auth: { persistSession: false, autoRefreshToken: false } });
let database = { users: [] };
function mapUser(row) {
  return { id: row.id, userNumber: row.user_number, uid: row.uid, phone: row.phone, username: row.username,
    balance: Number(row.balance), passwordSalt: row.password_salt, passwordHash: row.password_hash, createdAt: row.created_at };
}
function dbUser(user) {
  return { id: user.id, user_number: user.userNumber, uid: user.uid, phone: user.phone, username: user.username,
    balance: user.balance, password_salt: user.passwordSalt, password_hash: user.passwordHash, created_at: user.createdAt };
}
async function loadDatabase() {
  const { data, error } = await supabase.from('crashzone_users').select('*');
  if (error) throw new Error('Could not load CrashZone users from Supabase: ' + error.message);
  database.users = (data || []).map(mapUser);
}
async function saveUser(user) {
  const { error } = await supabase.from('crashzone_users').upsert(dbUser(user), { onConflict: 'id' });
  if (error) console.error('Supabase account save failed:', error.message);
}
const sessions = new Map();
function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('='); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function sessionUser(req) {
  const token = parseCookies(req.headers.cookie).cz_session;
  const userId = token && sessions.get(token);
  return userId ? database.users.find(u => u.id === userId) || null : null;
}
function publicAccount(user) {
  return { phone: user.phone, username: user.username, uid: user.uid, userNumber: user.userNumber, balance: user.balance };
}
function setSession(res, user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `cz_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secure}`);
}
function authRequired(req, res, next) {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ error: 'Please log in to continue.' });
  req.account = user; next();
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function passwordMatches(password, user) {
  const actual = crypto.scryptSync(password, user.passwordSalt, 64);
  const expected = Buffer.from(user.passwordHash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
app.get('/api/auth/me', (req, res) => {
  const user = sessionUser(req);
  res.json({ user: user ? publicAccount(user) : null });
});
app.post('/api/auth/signup', async (req, res) => {
  const phone = String(req.body?.phone || '').replace(/[\s()-]/g, '');
  const password = String(req.body?.password || '');
  const requestedUsername = String(req.body?.username || '').trim();
  if (!/^\+?[0-9]{10,15}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid phone number (10–15 digits).' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (database.users.some(u => u.phone === phone)) return res.status(409).json({ error: 'An account with this phone number already exists. Please log in.' });
  const { data: userNumber, error: numberError } = await supabase.rpc('crashzone_next_user_number');
  if (numberError) return res.status(500).json({ error: 'Could not allocate an account number. Check the Supabase SQL setup.' });
  const username = requestedUsername || `user${userNumber}`;
  if (!/^[A-Za-z0-9_]{3,18}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–18 characters: letters, numbers, or underscores.' });
  if (database.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'That username is already taken. Choose another.' });
  const credentials = hashPassword(password);
  const user = { id: crypto.randomUUID(), userNumber: Number(userNumber), uid: String(1000000000 + Number(userNumber)), phone, username, balance: STARTING_CREDITS, passwordSalt: credentials.salt, passwordHash: credentials.hash, createdAt: new Date().toISOString() };
  const { error: insertError } = await supabase.from('crashzone_users').insert(dbUser(user));
  if (insertError) return res.status(insertError.code === '23505' ? 409 : 500).json({ error: insertError.code === '23505' ? 'An account with this phone number already exists. Please log in.' : 'Account creation failed. Please try again.' });
  database.users.push(user); setSession(res, user);
  res.status(201).json({ user: publicAccount(user) });
});
app.post('/api/auth/login', async (req, res) => {
  const phone = String(req.body?.phone || '').replace(/[\s()-]/g, '');
  const password = String(req.body?.password || '');
  let user = database.users.find(u => u.phone === phone);
  if (!user) { const { data } = await supabase.from('crashzone_users').select('*').eq('phone', phone).maybeSingle(); if (data) { user = mapUser(data); database.users.push(user); } }
  if (!user || !passwordMatches(password, user)) return res.status(401).json({ error: 'Incorrect phone number or password.' });
  setSession(res, user); res.json({ user: publicAccount(user) });
});
app.post('/api/auth/logout', (req, res) => {
  const token = parseCookies(req.headers.cookie).cz_session;
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'cz_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.patch('/api/auth/profile', authRequired, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  if (!/^[A-Za-z0-9_]{3,18}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–18 characters: letters, numbers, or underscores.' });
  if (database.users.some(u => u.id !== req.account.id && u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'That username is already taken.' });
  const { error: profileError } = await supabase.from('crashzone_users').update({ username }).eq('id', req.account.id);
  if (profileError) return res.status(profileError.code === '23505' ? 409 : 500).json({ error: profileError.code === '23505' ? 'That username is already taken.' : 'Could not save your profile.' });
  req.account.username = username;
  for (const [socketId, player] of players) if (player.userId === req.account.id) { player.name = username; const sock = io.sockets.sockets.get(socketId); if (sock) sendPlayer(sock); }
  broadcast(); res.json({ user: publicAccount(req.account) });
});
app.get('/health', (_req, res) => res.json({
  status: 'ok', game: 'CrashZone Aviator', phase: state.phase, round: state.roundId
}));
app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

const WAIT_MS = 12000;
const TICK_MS = 100;
const MAX_BET = 1000;
const STARTING_CREDITS = 1000;
const players = new Map();
const bets = new Map();
const miniGames = new Map();
const MINI_BET_WINDOW_MS = 10000;
const MINI_ROUND_MS = 12000;
const MINI_MAX_BET = 1000;
const MINI_CONFIG = { bigsmall: { payout: 1.9 }, color: { payout: 7 }, lucky: { payout: 8 } };
function randomMiniResult(type) {
  if (type === 'bigsmall') return crypto.randomInt(0, 10);
  if (type === 'color') return ['blue','green','yellow','red','pink','violet','black','orange'][crypto.randomInt(0, 8)];
  return crypto.randomInt(0, 10);
}
function miniSnapshot(type) {
  const g = miniGames.get(type);
  return { type, roundId: g.roundId, phase: Date.now() < g.closesAt ? 'open' : 'revealing', closesAt: g.closesAt, revealAt: g.revealAt, serverTime: Date.now(), result: g.resultVisible ? g.result : null, history: g.history.slice(0, 500) };
}
function broadcastMini(type) { io.emit('mini:state', miniSnapshot(type)); }
function startMiniRound(type) {
  const now = Date.now(); const old = miniGames.get(type);
  const history = old ? old.history : [];
  const g = { type, roundId: old ? old.roundId + 1 : 1, openedAt: now, closesAt: now + MINI_BET_WINDOW_MS, revealAt: now + MINI_ROUND_MS, result: randomMiniResult(type), resultVisible: false, history, wagers: new Map() };
  miniGames.set(type, g); broadcastMini(type);
}
for (const type of Object.keys(MINI_CONFIG)) startMiniRound(type);
setInterval(() => {
  const now = Date.now();
  for (const type of Object.keys(MINI_CONFIG)) {
    let g = miniGames.get(type);
    if (now >= g.revealAt && !g.resultVisible) {
      g.resultVisible = true; g.history.unshift({ roundId: g.roundId, result: g.result }); g.history = g.history.slice(0, 500);
      for (const [socketId, wagers] of g.wagers) {
        const player = players.get(socketId); if (!player) continue;
        for (const wager of wagers) {
          if (wager.settled) continue;
          const isDigitPick = type === 'bigsmall' && /^[0-9]$/.test(wager.pick);
          const won = type === 'bigsmall' ? (isDigitPick ? Number(wager.pick) === g.result : wager.pick === 'big' ? g.result >= 5 : g.result <= 4) : wager.pick === String(g.result);
          const exactNumberCount = type === 'bigsmall' ? wagers.filter(w => /^[0-9]$/.test(w.pick)).length : 0;
          // Fair, transparent gross-return multipliers: 8 / number of exact digits selected.
          // Side bets (BIG/SMALL) do not change the exact-number multiplier.
          const multiplier = isDigitPick ? 8 / Math.max(1, exactNumberCount) : MINI_CONFIG[type].payout;
          const payout = won ? Math.floor(wager.amount * multiplier) : 0;
          player.balance += payout; wager.settled = true; wager.status = won ? 'won' : 'lost'; wager.payout = payout;
          io.to(socketId).emit('mini:result', { type, roundId: g.roundId, pick: wager.pick, result: g.result, amount: wager.amount, won, payout, balance: player.balance, multiplier });
        }
        persistBalance(player); const sock = io.sockets.sockets.get(socketId); if (sock) sendPlayer(sock);
      }
      broadcastMini(type);
      setTimeout(() => startMiniRound(type), 1800);
    } else if (now < g.revealAt) broadcastMini(type);
  }
}, 500);

let state = {
  phase: 'waiting', roundId: 0, multiplier: 1, crashPoint: null,
  roundStartedAt: null, nextRoundAt: Date.now() + WAIT_MS,
  history: [], online: 0
};
let targetCrashAtMs = null;

function randomCrashPoint() {
  // Demo-only weighted outcome table. Supplied weights total 100.
  // The requested ranges leave 3.00x–4.00x and 1.01x–1.19x unassigned.
  const buckets = [
    { weight: 5, min: 1.00, max: 1.00 },
    { weight: 15, min: 1.20, max: 1.40 },
    { weight: 10, min: 1.40, max: 1.60 },
    { weight: 30, min: 1.60, max: 2.00 },
    { weight: 15, min: 2.00, max: 3.00 },
    { weight: 10, min: 4.00, max: 10.00 },
    { weight: 3, min: 10.00, max: 50.00 },
    { weight: 12, min: 50.00, max: 100.00 }
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
  return { id: p.id, name: p.name, balance: p.balance, uid: p.uid };
}
function persistBalance(player) {
  const user = database.users.find(u => u.id === player.userId);
  if (user) { user.balance = player.balance; void saveUser(user); }
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
  persistBalance(current);
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
io.use((socket, next) => {
  const token = parseCookies(socket.handshake.headers.cookie).cz_session;
  const userId = token && sessions.get(token);
  const user = userId && database.users.find(u => u.id === userId);
  if (!user) return next(new Error('AUTH_REQUIRED'));
  socket.data.accountId = user.id; next();
});
io.on('connection', socket => {
  const account = database.users.find(u => u.id === socket.data.accountId);
  if (!account) return socket.disconnect(true);
  const p = { id: socket.id, userId: account.id, uid: account.uid, name: account.username, balance: account.balance };
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

  socket.on('mini:join', type => { if (MINI_CONFIG[type]) socket.emit('mini:state', miniSnapshot(type)); });
  socket.on('mini:bet', raw => {
    const current = players.get(socket.id); if (!current) return;
    const type = String(raw && raw.type || ''); const g = miniGames.get(type);
    if (!g || !MINI_CONFIG[type]) return socket.emit('game:error', 'Unknown game.');
    if (Date.now() >= g.closesAt || g.resultVisible) return socket.emit('game:error', 'Betting is closed for this round.');
    const picks = [...new Set((Array.isArray(raw.picks) ? raw.picks : [raw.pick]).map(v => String(v)))];
    const validPick = pick => type === 'bigsmall' ? (['big','small'].includes(pick) || /^[0-9]$/.test(pick)) : type === 'color' ? ['blue','green','yellow','red','pink','violet','black','orange'].includes(pick) : /^[0-9]$/.test(pick);
    if (!picks.length || picks.some(pick => !validPick(pick))) return socket.emit('game:error', 'Choose valid options.');
    const existingWagers = g.wagers.get(socket.id) || [];
    if (picks.some(pick => existingWagers.some(w => w.pick === pick))) return socket.emit('game:error', 'You already placed a bid on one of these options this round.');
    if (existingWagers.length + picks.length > 5) return socket.emit('game:error', 'Maximum 5 bids per round. Remove some selections and try again.');
    const amount = Number(raw.amount);
    if (!Number.isInteger(amount) || amount < 1 || amount > MINI_MAX_BET) return socket.emit('game:error', `Each bid must be 1–${MINI_MAX_BET} virtual credits.`);
    const total = amount * picks.length;
    if (total > current.balance) return socket.emit('game:error', `Not enough virtual credits for ${picks.length} bids (${total} total).`);
    current.balance -= total; persistBalance(current);
    const wagers = g.wagers.get(socket.id) || [];
    picks.forEach(pick => wagers.push({ amount, pick, settled: false })); g.wagers.set(socket.id, wagers);
    socket.emit('mini:bet:accepted', { type, roundId: g.roundId, amount, total, picks, balance: current.balance });
    sendPlayer(socket); broadcast();
  });

  socket.on('bet:place', raw => {
    const current = players.get(socket.id);
    if (!current) return;
    if (state.phase !== 'waiting' && state.phase !== 'crashed') return socket.emit('game:error', 'Bets are closed for this round.');
    const previousBet = bets.get(socket.id);
    if (previousBet && previousBet.status !== 'active') bets.delete(socket.id);
    const amount = Number(raw && raw.amount);
    const autoValue = raw && raw.autoCashout;
    const autoCashoutRaw = autoValue === null || autoValue === undefined || String(autoValue).trim() === '' ? null : Number(autoValue);
    if (autoCashoutRaw !== null && (!Number.isFinite(autoCashoutRaw) || autoCashoutRaw < 1.01 || autoCashoutRaw > 100)) {
      return socket.emit('game:error', 'Auto cash-out must be between 1.01× and 100×, or leave it blank.');
    }
    const autoCashout = autoCashoutRaw === null ? null : Math.round(autoCashoutRaw * 100) / 100;
    if (!Number.isInteger(amount) || amount < 1 || amount > MAX_BET) {
      return socket.emit('game:error', `Bet must be 1–${MAX_BET} virtual credits.`);
    }
    if (amount > current.balance) return socket.emit('game:error', 'Not enough virtual credits.');
    current.balance -= amount;
    persistBalance(current);
    if (previousBet && previousBet.status === 'active') {
      previousBet.amount += amount;
      if (autoCashout !== null) previousBet.autoCashout = autoCashout;
      previousBet.bids = (previousBet.bids || 1) + 1;
      socket.emit('bet:added', { amount, totalAmount: previousBet.amount, bids: previousBet.bids, balance: current.balance });
    } else {
      bets.set(socket.id, { amount, bids: 1, cashedOut: false, status: 'active', roundId: state.roundId + 1, autoCashout });
    }
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
    const liveMultiplier = multiplierAtElapsed(elapsed);
    state.multiplier = Number(liveMultiplier.toFixed(2));
    // Trigger auto cash-out from the shared server timeline. A target only pays
    // if its multiplier is reached strictly before the crash point.
    for (const [id, bet] of bets) {
      if (bet.status !== 'active' || !Number.isFinite(bet.autoCashout)) continue;
      const autoAtMs = elapsedForMultiplier(bet.autoCashout);
      if (bet.autoCashout < state._target && elapsed >= autoAtMs && autoAtMs < targetCrashAtMs) {
        cashoutPlayer(id, bet.autoCashout, true);
      }
    }
    broadcast();
  }
}, TICK_MS);

loadDatabase().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`CrashZone Aviator listening on port ${PORT}`);
    console.log(`Loaded ${database.users.length} CrashZone accounts from Supabase`);
    console.log(`Serving ${PUBLIC_DIR}`);
  });
}).catch(error => { console.error(error.message); process.exit(1); });
