const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const PORT = process.env.PORT || 3000;
app.use(express.static(__dirname));
app.get('/health', (_req,res) => res.json({ok:true, phase:round.phase, roundId:round.id, users:io.engine.clientsCount}));
const WAIT_MS = 10000;
const buckets = [
  {weight:10,min:1,max:1},{weight:15,min:1.20,max:1.40},{weight:15,min:1.40,max:1.60},
  {weight:40,min:1.60,max:2.00},{weight:10,min:2.00,max:3.00},{weight:10,min:4,max:10},
  {weight:3,min:10,max:50},{weight:2,min:50,max:100}
];
function crashPoint(){ const total=buckets.reduce((a,b)=>a+b.weight,0); let n=Math.random()*total; for(const b of buckets){n-=b.weight;if(n<0)return b.min===b.max?b.min:Math.round((b.min+Math.random()*(b.max-b.min))*100)/100;} return 1.6; }
let round = {id:1,phase:'waiting',phaseEndsAt:Date.now()+WAIT_MS,startedAt:0,crashAt:0,multiplier:1,history:[],players:new Map()};
function currentMultiplier(){ if(round.phase!=='live')return round.phase==='crashed'?round.crashAt:1; return Math.min(round.crashAt,Math.exp(((Date.now()-round.startedAt)/1000)*0.32)); }
function publicState(){return {id:round.id,phase:round.phase,phaseEndsAt:round.phaseEndsAt,serverNow:Date.now(),multiplier:currentMultiplier(),history:round.history.slice(0,12),joined:round.players.size};}
function broadcast(){io.emit('round:state',publicState());}
function startRound(){round.phase='live';round.startedAt=Date.now();round.crashAt=crashPoint();round.phaseEndsAt=0;round.players.forEach(p=>{p.cashedOut=false;p.cashoutAt=0;});io.emit('round:live',{id:round.id,startedAt:round.startedAt});broadcast();}
function crashRound(){round.phase='crashed';round.multiplier=round.crashAt;round.history.unshift(round.crashAt);round.history=round.history.slice(0,12);io.emit('round:crash',{id:round.id,crashAt:round.crashAt,history:round.history});round.phase='waiting';round.id++;round.players=new Map();round.phaseEndsAt=Date.now()+WAIT_MS;io.emit('round:waiting',{id:round.id,phaseEndsAt:round.phaseEndsAt});broadcast();}
setInterval(()=>{if(round.phase==='waiting'&&Date.now()>=round.phaseEndsAt)startRound();else if(round.phase==='live'){const m=currentMultiplier();if(m>=round.crashAt)crashRound();else broadcast();}else broadcast();},100);
io.on('connection',socket=>{
 socket.emit('round:state',publicState());
 socket.on('round:join',payload=>{
  if(round.phase!=='waiting')return socket.emit('round:error',{message:'Round already started. Join the next round.'});
  const stake=Number(payload&&payload.stake);
  if(!Number.isInteger(stake)||stake<10||stake>1000)return socket.emit('round:error',{message:'Stake must be 10–1,000 practice points.'});
  round.players.set(socket.id,{stake,cashedOut:false,cashoutAt:0});
  socket.emit('round:joined',{id:round.id,stake});broadcast();
 });
 socket.on('round:cashout',()=>{
  if(round.phase!=='live')return socket.emit('round:error',{message:'There is no live round to cash out from.'});
  const p=round.players.get(socket.id);if(!p)return socket.emit('round:error',{message:'You did not join this round.'});
  if(p.cashedOut)return socket.emit('round:error',{message:'You already cashed out.'});
  const m=currentMultiplier();if(m>=round.crashAt)return socket.emit('round:error',{message:'Too late — the round has crashed.'});
  p.cashedOut=true;p.cashoutAt=Math.floor(m*100)/100;
  socket.emit('round:cashedout',{id:round.id,stake:p.stake,multiplier:p.cashoutAt,payout:Math.floor(p.stake*p.cashoutAt)});
 });
 socket.on('disconnect',()=>{ /* A disconnect does not alter the shared round or its crash point. */ });
});
server.listen(PORT,()=>console.log(`CRASH ZONE shared server listening on ${PORT}`));
