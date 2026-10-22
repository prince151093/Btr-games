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
  if (suspendedUsers.has(user.id)) return res.status(403).json({ error: 'This account is suspended. Contact support.' });
  req.account = user; next();
}

// Separate owner-admin session. Credentials are configured only in server environment.
const adminSessions = new Map();
const runtimeSettings = { aviator:{enabled:true,duration_seconds:30,rules:''}, bigsmall:{enabled:true,duration_seconds:30,rules:''}, color:{enabled:true,duration_seconds:30,rules:''}, lucky:{enabled:true,duration_seconds:30,rules:''} };
// Transparent, in-memory one-shot outcome overrides for virtual-credit QA/demo only.
const pendingOutcomes = new Map();
const suspendedUsers = new Set();
function gameEnabled(game){ return runtimeSettings[game]?.enabled !== false; }
function gameDurationMs(game){ return Math.max(5,Math.min(300,Number(runtimeSettings[game]?.duration_seconds)||30))*1000; }
function safeStringEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function adminRequired(req, res, next) {
  const token = parseCookies(req.headers.cookie).cz_admin;
  const session = token && adminSessions.get(token);
  if (!session || Date.now() - session.createdAt > 8 * 60 * 60 * 1000) {
    if (token) adminSessions.delete(token);
    res.setHeader('Set-Cookie', 'cz_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    return res.status(401).json({ error: 'Admin login required. Please sign in again.' });
  }
  req.admin = { username: process.env.ADMIN_USERNAME };
  next();
}
function writeLedger(entry) {
  // Requires the SQL migration in admin/supabase-admin.sql. Never blocks gameplay.
  void supabase.from('crashzone_admin_ledger').insert({
    game: entry.game, round_id: String(entry.roundId), user_id: entry.userId,
    username: entry.username || null, entry_type: entry.entryType,
    amount: Math.max(0, Math.floor(Number(entry.amount) || 0)),
    details: entry.details || {}
  }).then(({ error }) => { if (error) console.error('Admin ledger write failed:', error.message); });
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
  if (suspendedUsers.has(user.id)) return res.status(403).json({ error: 'This account is suspended. Contact support.' });
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

// Admin login and reporting API
app.post('/api/admin/login', (req, res) => {
  const username = String(req.body?.username || '');
  const password = String(req.body?.password || '');
  const configuredUser = process.env.ADMIN_USERNAME;
  const configuredPass = process.env.ADMIN_PASSWORD;
  if (!configuredUser || !configuredPass) return res.status(503).json({ error: 'Admin login is not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD in server environment.' });
  if (!safeStringEqual(username, configuredUser) || !safeStringEqual(password, configuredPass)) {
    return res.status(401).json({ error: 'Incorrect admin username or password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, { createdAt: Date.now() });
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `cz_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
  res.json({ ok: true, username: configuredUser });
});
app.post('/api/admin/logout', adminRequired, (req, res) => {
  const token = parseCookies(req.headers.cookie).cz_admin;
  if (token) adminSessions.delete(token);
  res.setHeader('Set-Cookie', 'cz_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.get('/api/admin/me', adminRequired, (req, res) => res.json({ username: req.admin.username }));
app.get('/api/admin/overview', adminRequired, async (req, res) => {
  const { data: ledger, error } = await supabase.from('crashzone_admin_ledger')
    .select('game,entry_type,amount,created_at,round_id,user_id,username,details').order('created_at', { ascending: false }).limit(10000);
  if (error) return res.status(503).json({ error: 'P&L ledger is unavailable. Run admin/supabase-admin.sql in Supabase SQL Editor first.' });
  const byGame = {};
  for (const game of ['aviator','bigsmall','color','lucky']) byGame[game] = { stakes: 0, payouts: 0, refunds: 0, entries: 0, rounds: new Set() };
  for (const row of ledger || []) {
    const g = byGame[row.game]; if (!g) continue;
    g.entries++;
    if (row.round_id) g.rounds.add(row.round_id);
    if (row.entry_type === 'stake') g.stakes += Number(row.amount) || 0;
    if (row.entry_type === 'payout') g.payouts += Number(row.amount) || 0;
    if (row.entry_type === 'refund') g.refunds += Number(row.amount) || 0;
  }
  const games = Object.fromEntries(Object.entries(byGame).map(([k,v]) => [k, { stakes:v.stakes, payouts:v.payouts, refunds:v.refunds, net:v.stakes-v.payouts-v.refunds, entries:v.entries, rounds:v.rounds.size }]));
  res.json({ userCount: database.users.length, online: players.size, virtualCreditsInAccounts: database.users.reduce((n,u)=>n+(Number(u.balance)||0),0), games, ledger: (ledger||[]).slice(0,250), current: { aviator: { phase: state.phase, roundId: state.roundId, multiplier: state.multiplier }, mini: Object.fromEntries([...miniGames].map(([k,g])=>[k,{roundId:g.roundId,phase:Date.now()<g.closesAt?'open':'revealing'}])) } });
});
app.get('/api/admin/users', adminRequired, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().slice(0,100);
  const users = database.users.filter(u => !q || [u.username,u.phone,u.uid,String(u.userNumber)].some(v=>String(v||'').toLowerCase().includes(q)))
    .slice(0,500).map(u => ({ id:u.id, username:u.username, phone:u.phone, uid:u.uid, userNumber:u.userNumber, balance:u.balance, createdAt:u.createdAt, suspended:suspendedUsers.has(u.id) }));
  res.json({ users });
});
app.post('/api/admin/users/:id/adjust-balance', adminRequired, async (req, res) => {
  const user = database.users.find(u=>u.id===req.params.id);
  if (!user) return res.status(404).json({error:'User not found.'});
  const amount = Number(req.body?.amount);
  const reason = String(req.body?.reason||'').trim().slice(0,200);
  if (!Number.isSafeInteger(amount) || amount===0 || Math.abs(amount)>100000000 || !reason) return res.status(400).json({error:'Enter a non-zero whole-credit adjustment and a reason.'});
  if (user.balance + amount < 0) return res.status(400).json({error:'Adjustment cannot make the balance negative.'});
  user.balance += amount;
  await saveUser(user);
  writeLedger({game:'admin',roundId:'manual',userId:user.id,username:user.username,entryType:amount>0?'bonus':'adjustment',amount:Math.abs(amount),details:{reason,delta:amount,admin:req.admin.username}});
  for (const p of players.values()) if(p.userId===user.id){p.balance=user.balance;const sock=io.sockets.sockets.get(p.id);if(sock)sendPlayer(sock);}
  broadcast();
  res.json({ok:true,balance:user.balance});
});

// Extended admin APIs: settings, expenses, support, staff, history, audit and reports.
async function adminTable(table, queryFn) {
  let q = supabase.from(table).select('*');
  return await queryFn(q);
}
async function auditAdmin(req, action, entityType, entityId, details={}) {
  const { error } = await supabase.from('crashzone_admin_audit_logs').insert({
    actor_username: req.admin?.username || 'unknown', action, entity_type: entityType,
    entity_id: entityId == null ? null : String(entityId), details
  });
  if (error) console.error('Admin audit write failed:', error.message);
}
app.get('/api/admin/reports', adminRequired, async (req,res) => {
  const game = String(req.query.game || 'all');
  const from = String(req.query.from || '').slice(0,10);
  const to = String(req.query.to || '').slice(0,10);
  const user = String(req.query.user || '').slice(0,100);
  const round = String(req.query.round || '').slice(0,100);
  let q = supabase.from('crashzone_admin_ledger').select('*').order('created_at',{ascending:false}).limit(10000);
  if (game !== 'all' && ['aviator','bigsmall','color','lucky','admin'].includes(game)) q=q.eq('game',game);
  if (from) q=q.gte('created_at',from+'T00:00:00.000Z');
  if (to) q=q.lte('created_at',to+'T23:59:59.999Z');
  if (user) { if (/^[0-9a-f-]{36}$/i.test(user)) q=q.eq('user_id',user); else q=q.ilike('username',`%${user.replace(/[%,()]/g,'')}%`); }
  if (round) q=q.ilike('round_id',`%${round.replace(/[%,]/g,'')}%`);
  const {data,error}=await q;
  if(error)return res.status(503).json({error:'Could not load ledger. Apply the admin SQL migration.'});
  const rows=data||[]; const byGame={};
  for(const k of ['aviator','bigsmall','color','lucky'])byGame[k]={stakes:0,payouts:0,refunds:0,bonuses:0,adjustments:0,net:0,entries:0};
  for(const r of rows){const g=byGame[r.game];if(!g)continue;g.entries++;const n=Number(r.amount)||0;if(r.entry_type==='stake')g.stakes+=n;if(r.entry_type==='payout')g.payouts+=n;if(r.entry_type==='refund')g.refunds+=n;if(r.entry_type==='bonus')g.bonuses+=n;if(r.entry_type==='adjustment')g.adjustments+=n;}
  for(const g of Object.values(byGame))g.net=g.stakes-g.payouts-g.refunds;
  const ex=await supabase.from('crashzone_admin_expenses').select('*').order('expense_date',{ascending:false}).limit(2000);
  if(ex.error && ex.error.code!=='42P01') return res.status(503).json({error:'Could not load expenses. Apply the admin SQL migration.'});
  const expenses=(ex.data||[]).filter(e=>(!from||e.expense_date>=from)&&(!to||e.expense_date<=to));
  res.json({rows:rows.slice(0,1000),byGame,expenses,totalExpenses:expenses.reduce((n,e)=>n+Number(e.amount||0),0),net:Object.values(byGame).reduce((n,g)=>n+g.net,0),operatingNet:Object.values(byGame).reduce((n,g)=>n+g.net,0)-expenses.reduce((n,e)=>n+Number(e.amount||0),0)});
});
app.get('/api/admin/settings',adminRequired,async(req,res)=>{const {data,error}=await supabase.from('crashzone_admin_game_settings').select('*').order('game');if(error)return res.status(503).json({error:'Settings table unavailable. Apply admin SQL migration.'});for(const row of data||[])runtimeSettings[row.game]={enabled:row.enabled,duration_seconds:row.duration_seconds,rules:row.rules||''};res.json({settings:data||[]});});
app.put('/api/admin/settings/:game',adminRequired,async(req,res)=>{const game=String(req.params.game);if(!['aviator','bigsmall','color','lucky'].includes(game))return res.status(400).json({error:'Unknown game.'});const enabled=req.body?.enabled===true;const duration=Number(req.body?.duration_seconds);const rules=String(req.body?.rules||'').slice(0,4000);if(!Number.isInteger(duration)||duration<5||duration>300)return res.status(400).json({error:'Duration must be 5–300 seconds.'});const {data,error}=await supabase.from('crashzone_admin_game_settings').upsert({game,enabled,duration_seconds:duration,rules,updated_by:req.admin.username,updated_at:new Date().toISOString()},{onConflict:'game'}).select().single();if(error)return res.status(503).json({error:'Could not save settings. Apply admin SQL migration.'});runtimeSettings[game]={enabled,duration_seconds:duration,rules};await auditAdmin(req,'update_game_settings','game',game,{enabled,duration_seconds:duration});res.json({setting:data});});
app.get('/api/admin/future-results',adminRequired,(req,res)=>res.json({results:[...pendingOutcomes.entries()].map(([game,value])=>({game,value,queuedAt:value.queuedAt||null}))}));
app.post('/api/admin/future-results',adminRequired,async(req,res)=>{const game=String(req.body?.game||'');let value=req.body?.value;if(!['aviator','bigsmall','color','lucky'].includes(game))return res.status(400).json({error:'Unknown game.'});if(game==='aviator'){value=Number(value);if(!Number.isFinite(value)||value<1||value>1000)return res.status(400).json({error:'Aviator multiplier must be 1.00–1000.00.'});value=Math.round(value*100)/100;}else if(game==='bigsmall'||game==='lucky'){value=Number(value);if(!Number.isInteger(value)||value<0||value>9)return res.status(400).json({error:'Choose a digit from 0 to 9.'});}else{value=String(value);if(!['blue','green','yellow','red','pink','violet','black','orange'].includes(value))return res.status(400).json({error:'Choose a valid Color Prediction result.'});}const queued={value,queuedAt:new Date().toISOString(),queuedBy:req.admin.username};pendingOutcomes.set(game,queued);await auditAdmin(req,'queue_demo_outcome','game',game,{value});res.json({ok:true,game,value,queuedAt:queued.queuedAt,note:'One-shot override for virtual-credit QA/demo; consumed by the next round start.'});});
app.delete('/api/admin/future-results/:game',adminRequired,async(req,res)=>{const game=String(req.params.game);if(!pendingOutcomes.has(game))return res.status(404).json({error:'No queued result for this game.'});pendingOutcomes.delete(game);await auditAdmin(req,'cancel_demo_outcome','game',game);res.json({ok:true});});
app.get('/api/admin/expenses',adminRequired,async(req,res)=>{const {data,error}=await supabase.from('crashzone_admin_expenses').select('*').order('expense_date',{ascending:false}).limit(500);if(error)return res.status(503).json({error:'Expenses table unavailable. Apply admin SQL migration.'});res.json({expenses:data||[]});});
app.post('/api/admin/expenses',adminRequired,async(req,res)=>{const description=String(req.body?.description||'').trim().slice(0,200),category=String(req.body?.category||'other').slice(0,60),amount=Number(req.body?.amount),expense_date=String(req.body?.expense_date||new Date().toISOString().slice(0,10));if(!description||!Number.isSafeInteger(amount)||amount<0||amount>1000000000)return res.status(400).json({error:'Enter a description and a non-negative whole amount.'});const {data,error}=await supabase.from('crashzone_admin_expenses').insert({description,category,amount,expense_date,created_by:req.admin.username}).select().single();if(error)return res.status(503).json({error:'Could not save expense. Apply admin SQL migration.'});await auditAdmin(req,'create_expense','expense',data.id,{amount,category});res.status(201).json({expense:data});});
app.get('/api/admin/support',adminRequired,async(req,res)=>{const {data,error}=await supabase.from('crashzone_admin_support_tickets').select('*').order('created_at',{ascending:false}).limit(500);if(error)return res.status(503).json({error:'Support table unavailable. Apply admin SQL migration.'});res.json({tickets:data||[]});});
app.post('/api/admin/support',adminRequired,async(req,res)=>{const subject=String(req.body?.subject||'').trim().slice(0,200),message=String(req.body?.message||'').trim().slice(0,5000),status=String(req.body?.status||'open');if(!subject||!message||!['open','in_progress','closed'].includes(status))return res.status(400).json({error:'Subject, message and valid status are required.'});const {data,error}=await supabase.from('crashzone_admin_support_tickets').insert({subject,message,status,assigned_to:req.admin.username,created_by:req.admin.username}).select().single();if(error)return res.status(503).json({error:'Could not create ticket. Apply admin SQL migration.'});await auditAdmin(req,'create_support_ticket','ticket',data.id,{subject});res.status(201).json({ticket:data});});
app.patch('/api/admin/support/:id',adminRequired,async(req,res)=>{const status=String(req.body?.status||'');if(!['open','in_progress','closed'].includes(status))return res.status(400).json({error:'Invalid ticket status.'});const {data,error}=await supabase.from('crashzone_admin_support_tickets').update({status,updated_at:new Date().toISOString(),assigned_to:String(req.body?.assigned_to||req.admin.username).slice(0,100)}).eq('id',req.params.id).select().single();if(error)return res.status(503).json({error:'Could not update ticket.'});await auditAdmin(req,'update_support_ticket','ticket',req.params.id,{status});res.json({ticket:data});});
app.get('/api/admin/staff',adminRequired,async(req,res)=>{const {data,error}=await supabase.from('crashzone_admin_memberships').select('*').order('created_at',{ascending:false});if(error)return res.status(503).json({error:'Staff table unavailable. Apply admin SQL migration.'});res.json({staff:data||[]});});
app.post('/api/admin/staff',adminRequired,async(req,res)=>{const username=String(req.body?.username||'').trim(),role=String(req.body?.role||'support');const allowed=['manager','support'];const permissions=Array.isArray(req.body?.permissions)?req.body.permissions.filter(x=>['dashboard','users_read','users_suspend','game_settings','wallet_adjust','pnl_read','audit_read','support_manage'].includes(x)):[];if(!/^[A-Za-z0-9_.-]{3,50}$/.test(username)||!allowed.includes(role))return res.status(400).json({error:'Enter a valid staff username and role.'});const {data,error}=await supabase.from('crashzone_admin_memberships').upsert({username,role,permissions,active:true,created_by:req.admin.username},{onConflict:'username'}).select().single();if(error)return res.status(503).json({error:'Could not save staff member. Apply admin SQL migration.'});await auditAdmin(req,'upsert_staff','staff',username,{role,permissions});res.json({staff:data});});
app.delete('/api/admin/staff/:username',adminRequired,async(req,res)=>{const username=String(req.params.username);if(username===req.admin.username)return res.status(400).json({error:'You cannot deactivate the current owner account.'});const {error}=await supabase.from('crashzone_admin_memberships').update({active:false}).eq('username',username);if(error)return res.status(503).json({error:'Could not deactivate staff member.'});await auditAdmin(req,'deactivate_staff','staff',username);res.json({ok:true});});
app.get('/api/admin/audit',adminRequired,async(req,res)=>{const {data,error}=await supabase.from('crashzone_admin_audit_logs').select('*').order('created_at',{ascending:false}).limit(500);if(error)return res.status(503).json({error:'Audit table unavailable. Apply admin SQL migration.'});res.json({logs:data||[]});});
app.post('/api/admin/announcements',adminRequired,async(req,res)=>{const title=String(req.body?.title||'').trim().slice(0,150),message=String(req.body?.message||'').trim().slice(0,3000),active=req.body?.active!==false;if(!title||!message)return res.status(400).json({error:'Title and message are required.'});const {data,error}=await supabase.from('crashzone_admin_announcements').insert({title,message,active,created_by:req.admin.username}).select().single();if(error)return res.status(503).json({error:'Announcements table unavailable. Apply admin SQL migration.'});await auditAdmin(req,'create_announcement','announcement',data.id,{title,active});res.status(201).json({announcement:data});});
app.get('/api/admin/announcements',adminRequired,async(req,res)=>{const {data,error}=await supabase.from('crashzone_admin_announcements').select('*').order('created_at',{ascending:false}).limit(200);if(error)return res.status(503).json({error:'Announcements table unavailable. Apply admin SQL migration.'});res.json({announcements:data||[]});});


app.get('/api/admin/users/:id/history',adminRequired,async(req,res)=>{const {data,error}=await supabase.from('crashzone_admin_ledger').select('*').eq('user_id',req.params.id).order('created_at',{ascending:false}).limit(500);if(error)return res.status(503).json({error:'Ledger history unavailable.'});res.json({history:data||[]});});
app.post('/api/admin/users/:id/suspension',adminRequired,async(req,res)=>{const user=database.users.find(u=>u.id===req.params.id);if(!user)return res.status(404).json({error:'User not found.'});const suspended=req.body?.suspended===true;const {error}=await supabase.from('crashzone_admin_user_controls').upsert({user_id:user.id,suspended,reason:String(req.body?.reason||'').slice(0,300),updated_by:req.admin.username,updated_at:new Date().toISOString()},{onConflict:'user_id'});if(error)return res.status(503).json({error:'User controls table unavailable. Apply admin SQL migration.'});if(suspended)suspendedUsers.add(user.id);else suspendedUsers.delete(user.id);await auditAdmin(req,suspended?'suspend_user':'unsuspend_user','user',user.id,{reason:String(req.body?.reason||'').slice(0,300)});res.json({ok:true,suspended});});

app.get('/admin', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));

app.get('/health', (_req, res) => res.json({
  status: 'ok', game: 'CrashZone Aviator', phase: state.phase, round: state.roundId
}));
app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

const WAIT_MS = 30000; // fallback; admin-configured duration is used by waitMs()
function waitMs(){ return gameDurationMs('aviator'); }
const TICK_MS = 100;
const MAX_BET = 1000;
const STARTING_CREDITS = 1000;
const players = new Map();
const bets = new Map();
const miniGames = new Map();
const MINI_BET_WINDOW_MS = 30000; // 30-second betting window for all mini games
const MINI_ROUND_MS = 30000; // reveal the result after the 30-second round
const MINI_MAX_BET = 1000;
const MINI_CONFIG = { bigsmall: { payout: 1.9 }, color: { payout: 7 }, lucky: { payout: 8 } };
function randomMiniResult(type) {
  if (type === 'bigsmall') return crypto.randomInt(0, 10);
  if (type === 'color') return ['blue','green','yellow','red','pink','violet','black','orange'][crypto.randomInt(0, 8)];
  return crypto.randomInt(0, 10);
}
function miniSnapshot(type) {
  const g = miniGames.get(type);
  return { type, roundId: g.roundId, phase: Date.now() < g.closesAt ? 'open' : 'revealing', closesAt: g.closesAt, revealAt: g.revealAt, serverTime: Date.now(), result: g.resultVisible ? g.result : null, history: g.history.slice(0, 100) };
}
function broadcastMini(type) { io.emit('mini:state', miniSnapshot(type)); }
function startMiniRound(type) {
  const now = Date.now(); const old = miniGames.get(type);
  if (!gameEnabled(type)) { const g={type,roundId:old?old.roundId+1:1,openedAt:now,closesAt:now,revealAt:now+gameDurationMs(type),result:randomMiniResult(type),resultVisible:false,history:old?old.history:[],wagers:new Map()}; miniGames.set(type,g); broadcastMini(type); return; }
  const history = old ? old.history : [];
  const queued = pendingOutcomes.get(type); if (queued) pendingOutcomes.delete(type);
  const g = { type, roundId: old ? old.roundId + 1 : 1, openedAt: now, closesAt: now + gameDurationMs(type), revealAt: now + gameDurationMs(type), result: queued ? queued.value : randomMiniResult(type), resultVisible: false, history, wagers: new Map() };
  miniGames.set(type, g); broadcastMini(type);
}
for (const type of Object.keys(MINI_CONFIG)) startMiniRound(type);
setInterval(() => {
  const now = Date.now();
  for (const type of Object.keys(MINI_CONFIG)) {
    let g = miniGames.get(type);
    if (now >= g.revealAt && !g.resultVisible) {
      g.resultVisible = true; g.history.unshift({ roundId: g.roundId, result: g.result }); g.history = g.history.slice(0, 100);
      for (const [socketId, wagers] of g.wagers) {
        const player = players.get(socketId); if (!player) continue;
        const roundTotalStake = wagers.reduce((sum, w) => sum + (Number(w.amount) || 0), 0);
        let roundTotalPayout = 0;
        for (const wager of wagers) {
          if (wager.settled) continue;
          const isDigitPick = type === 'bigsmall' && /^[0-9]$/.test(wager.pick);
          const resultColor = g.result === 0 ? 'red' : g.result === 5 ? 'green' : (g.result % 2 === 1 ? 'green' : 'red');
          const won = type === 'bigsmall' ? (isDigitPick ? Number(wager.pick) === g.result : wager.pick === 'big' ? g.result >= 5 : wager.pick === 'small' ? g.result <= 4 : wager.pick === 'violet' ? (g.result === 0 || g.result === 5) : ['green','red'].includes(wager.pick) ? resultColor === wager.pick : false) : wager.pick === String(g.result);
          const exactNumberCount = type === 'bigsmall' ? wagers.filter(w => /^[0-9]$/.test(w.pick)).length : 0;
          // Fair, transparent gross-return multipliers: 8 / number of exact digits selected.
          // Side bets (BIG/SMALL) do not change the exact-number multiplier.
          const multiplier = isDigitPick ? 8 / Math.max(1, exactNumberCount) : type === 'bigsmall' && wager.pick === 'violet' ? 4.5 : type === 'bigsmall' && ['green','red'].includes(wager.pick) ? 1.9 : MINI_CONFIG[type].payout;
          const payout = won ? Math.floor(wager.amount * multiplier) : 0;
          player.balance += payout; roundTotalPayout += payout; wager.settled = true; wager.status = won ? 'won' : 'lost'; wager.payout = payout;
          if (payout > 0) writeLedger({game:type,roundId:g.roundId,userId:player.userId,username:player.name,entryType:'payout',amount:payout,details:{pick:wager.pick,result:g.result,multiplier}});
          io.to(socketId).emit('mini:result', { type, roundId: g.roundId, pick: wager.pick, result: g.result, amount: wager.amount, won, payout, balance: player.balance, multiplier });
        }
        persistBalance(player); const sock = io.sockets.sockets.get(socketId); if (sock) { sendPlayer(sock); sock.emit('mini:round:summary', { type, roundId:g.roundId, totalStake:roundTotalStake, totalPayout:roundTotalPayout, net:roundTotalPayout-roundTotalStake, balance:player.balance }); }
      }
      broadcastMini(type);
      setTimeout(() => startMiniRound(type), 1800);
    } else if (now < g.revealAt) broadcastMini(type);
  }
}, 500);

let state = {
  phase: 'waiting', roundId: 0, multiplier: 1, crashPoint: null,
  roundStartedAt: null, nextRoundAt: Date.now() + waitMs(),
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
    nextRoundAt: state.nextRoundAt, history: state.history.slice(0, 100),
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
  const queued = pendingOutcomes.get('aviator'); if (queued) pendingOutcomes.delete('aviator');
  const point = queued ? Number(queued.value) : randomCrashPoint();
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
  writeLedger({game:'aviator',roundId:bet.roundId,userId:current.userId,username:current.name,entryType:'payout',amount:payout,details:{multiplier:safeMultiplier,automatic}});
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
  state.history = state.history.slice(0, 100);
  state.nextRoundAt = Date.now() + waitMs();
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
  if (!user || suspendedUsers.has(user.id)) return next(new Error('AUTH_REQUIRED'));
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
    const current = players.get(socket.id);
    if (!gameEnabled(String(raw?.type||''))) return socket.emit('game:error', 'This game is currently disabled by the administrator.'); if (!current) return;
    const type = String(raw && raw.type || ''); const g = miniGames.get(type);
    if (!g || !MINI_CONFIG[type]) return socket.emit('game:error', 'Unknown game.');
    if (Date.now() >= g.closesAt || g.resultVisible) return socket.emit('game:error', 'Betting is closed for this round.');
    const picks = [...new Set((Array.isArray(raw.picks) ? raw.picks : [raw.pick]).map(v => String(v)))];
    const validPick = pick => type === 'bigsmall' ? (['big','small','green','red','violet'].includes(pick) || /^[0-9]$/.test(pick)) : type === 'color' ? ['blue','green','yellow','red','pink','violet','black','orange'].includes(pick) : /^[0-9]$/.test(pick);
    if (!picks.length || picks.some(pick => !validPick(pick))) return socket.emit('game:error', 'Choose valid options.');
    const existingWagers = g.wagers.get(socket.id) || [];
    if (picks.some(pick => existingWagers.some(w => w.pick === pick))) return socket.emit('game:error', 'You already placed a bid on one of these options this round.');
    if (existingWagers.length + picks.length > 5) return socket.emit('game:error', 'Maximum 5 bids per round. Remove some selections and try again.');
    const amount = Number(raw.amount);
    if (!Number.isInteger(amount) || amount < 1 || amount > MINI_MAX_BET) return socket.emit('game:error', `Each bid must be 1–${MINI_MAX_BET} virtual credits.`);
    const total = amount * picks.length;
    if (total > current.balance) return socket.emit('game:error', `Not enough virtual credits for ${picks.length} bids (${total} total).`);
    current.balance -= total;
    for (const pick of picks) writeLedger({game:type,roundId:g.roundId,userId:current.userId,username:current.name,entryType:'stake',amount,details:{pick}});
    persistBalance(current);
    const wagers = g.wagers.get(socket.id) || [];
    picks.forEach(pick => wagers.push({ amount, pick, settled: false })); g.wagers.set(socket.id, wagers);
    socket.emit('mini:bet:accepted', { type, roundId: g.roundId, amount, total, picks, balance: current.balance });
    sendPlayer(socket); broadcast();
  });

  socket.on('bet:place', raw => {
    const current = players.get(socket.id);
    if (!gameEnabled('aviator')) return socket.emit('game:error', 'Aviator is currently disabled by the administrator.');
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
    writeLedger({game:'aviator',roundId:previousBet && previousBet.status==='active' ? previousBet.roundId : state.roundId+1,userId:current.userId,username:current.name,entryType:'stake',amount,details:{kind:'aviator_bet'}});
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

loadDatabase().then(async () => {
  const settingsResult=await supabase.from('crashzone_admin_game_settings').select('*');
  if(!settingsResult.error) for(const row of settingsResult.data||[]) runtimeSettings[row.game]={enabled:row.enabled,duration_seconds:row.duration_seconds,rules:row.rules||''};
  const controlsResult=await supabase.from('crashzone_admin_user_controls').select('user_id,suspended');
  if(!controlsResult.error) for(const row of controlsResult.data||[]) if(row.suspended)suspendedUsers.add(row.user_id);
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`CrashZone Aviator listening on port ${PORT}`);
    console.log(`Loaded ${database.users.length} CrashZone accounts from Supabase`);
    console.log(`Serving ${PUBLIC_DIR}`);
  });
}).catch(error => { console.error(error.message); process.exit(1); });
