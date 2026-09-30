const express=require('express');
const http=require('http');
const path=require('path');
const helmet=require('helmet');
const cors=require('cors');
const rateLimit=require('express-rate-limit');
const {Server}=require('socket.io');
const Database=require('better-sqlite3');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const {AccessToken}=require('livekit-server-sdk');

const app=express();
const server=http.createServer(app);
const PORT=Number(process.env.PORT||3000);
const CLIENT_ORIGIN=process.env.CLIENT_ORIGIN||'';
const SECRET=process.env.JWT_SECRET||'';
if(!SECRET && process.env.NODE_ENV==='production') throw new Error('JWT_SECRET must be set in production');
const JWT_SECRET=SECRET||'dev-only-change-me-'+require('crypto').randomBytes(24).toString('hex');
const allowedOrigin=CLIENT_ORIGIN||true;
const io=new Server(server,{cors:{origin:allowedOrigin,methods:['GET','POST'],credentials:true}});
const db=new Database(process.env.DB_FILE||'neet.db');
db.pragma('journal_mode=WAL');
db.pragma('foreign_keys=ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 target INTEGER DEFAULT 680,
 role TEXT DEFAULT 'student',
 banned INTEGER DEFAULT 0,
 streak INTEGER DEFAULT 0,
 total_minutes INTEGER DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 reporter INTEGER,
 room TEXT,
 reason TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 status TEXT DEFAULT 'open',
 FOREIGN KEY(reporter) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS study_sessions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 room TEXT,
 minutes INTEGER NOT NULL,
 studied_on TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_date ON study_sessions(user_id,studied_on);
CREATE INDEX IF NOT EXISTS idx_users_total ON users(total_minutes DESC);
`);
if(process.env.ADMIN_EMAIL){
 db.prepare("UPDATE users SET role='admin' WHERE lower(email)=lower(?)").run(process.env.ADMIN_EMAIL.trim());
}

app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false}));
app.use(cors({origin:allowedOrigin,credentials:true}));
app.use(express.json({limit:'20kb'}));
app.use(rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));
app.use('/api/login',rateLimit({windowMs:15*60*1000,max:30,message:{error:'Too many login attempts. Try again later.'}}));
app.use('/api/register',rateLimit({windowMs:15*60*1000,max:20,message:{error:'Too many signup attempts. Try again later.'}}));
app.use(express.static(path.join(__dirname,'../client')));

const cleanName=x=>String(x||'').trim().replace(/\s+/g,' ').slice(0,50);
const cleanEmail=x=>String(x||'').trim().toLowerCase().slice(0,160);
const cleanRoom=x=>String(x||'').trim().slice(0,60);
const validRooms=new Set(['Biology','Chemistry','Physics']);
const publicUser=u=>u&&({id:u.id,name:u.name,email:u.email,target:u.target,role:u.role,streak:u.streak,total_minutes:u.total_minutes,banned:!!u.banned});
const sign=u=>jwt.sign({id:u.id,name:u.name,email:u.email,role:u.role},JWT_SECRET,{expiresIn:'7d'});
function auth(req,res,next){
 try{
  const raw=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  const p=jwt.verify(raw,JWT_SECRET);
  const u=db.prepare('SELECT id,name,email,target,role,streak,total_minutes,banned FROM users WHERE id=?').get(p.id);
  if(!u||u.banned)return res.status(403).json({error:'Account is unavailable.'});
  req.user=u;next();
 }catch(e){res.status(401).json({error:'Unauthorized'});}
}
function admin(req,res,next){if(req.user?.role!=='admin')return res.status(403).json({error:'Admin only'});next();}
function todayUTC(){return new Date().toISOString().slice(0,10)}
function calculateStreak(userId,today=todayUTC()){
 const dates=db.prepare('SELECT DISTINCT studied_on FROM study_sessions WHERE user_id=? ORDER BY studied_on DESC LIMIT 90').all(userId).map(x=>x.studied_on);
 let streak=0;const d=new Date(today+'T00:00:00Z');
 for(let i=0;i<dates.length;i++){const expected=new Date(d);expected.setUTCDate(d.getUTCDate()-i);if(dates[i]!==expected.toISOString().slice(0,10))break;streak++;}
 return streak;
}

app.get('/api/health',(req,res)=>res.json({ok:true,service:'NEET StudyHub',time:new Date().toISOString()}));
app.post('/api/register',(req,res)=>{
 const name=cleanName(req.body?.name),email=cleanEmail(req.body?.email),password=String(req.body?.password||''),target=Math.max(0,Math.min(720,Math.floor(Number(req.body?.target)||680)));
 if(name.length<2)return res.status(400).json({error:'Name must be at least 2 characters.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:'Enter a valid email.'});
 if(password.length<8)return res.status(400).json({error:'Password must be at least 8 characters.'});
 try{
  const role=process.env.ADMIN_EMAIL&&email===cleanEmail(process.env.ADMIN_EMAIL)?'admin':'student';
  const r=db.prepare('INSERT INTO users(name,email,password,target,role) VALUES(?,?,?,?,?)').run(name,email,bcrypt.hashSync(password,12),target,role);
  const u=db.prepare('SELECT id,name,email,target,role,streak,total_minutes,banned FROM users WHERE id=?').get(r.lastInsertRowid);
  res.json({token:sign(u),user:publicUser(u)});
 }catch(e){res.status(409).json({error:'Email already registered.'});}
});
app.post('/api/login',(req,res)=>{
 const email=cleanEmail(req.body?.email),password=String(req.body?.password||'');
 const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!u||u.banned||!bcrypt.compareSync(password,u.password))return res.status(401).json({error:'Invalid email or password.'});
 res.json({token:sign(u),user:publicUser(u)});
});
app.get('/api/me',auth,(req,res)=>res.json(publicUser(req.user)));
app.patch('/api/me',auth,(req,res)=>{
 const name=cleanName(req.body?.name),target=Math.max(0,Math.min(720,Math.floor(Number(req.body?.target)||0)));
 if(name.length<2)return res.status(400).json({error:'Name must be at least 2 characters.'});
 db.prepare('UPDATE users SET name=?,target=? WHERE id=?').run(name,target,req.user.id);
 const u=db.prepare('SELECT id,name,email,target,role,streak,total_minutes,banned FROM users WHERE id=?').get(req.user.id);
 res.json({user:publicUser(u),token:sign(u)});
});
app.post('/api/study',auth,(req,res)=>{
 const m=Math.max(1,Math.min(600,Math.floor(Number(req.body?.minutes)||0)));if(!m)return res.status(400).json({error:'Minutes required.'});
 const room=cleanRoom(req.body?.room);const today=todayUTC();
 db.prepare('INSERT INTO study_sessions(user_id,room,minutes,studied_on) VALUES(?,?,?,?)').run(req.user.id,room,m,today);
 const streak=calculateStreak(req.user.id,today);
 db.prepare('UPDATE users SET total_minutes=total_minutes+?,streak=? WHERE id=?').run(m,streak,req.user.id);
 const total=db.prepare('SELECT total_minutes FROM users WHERE id=?').get(req.user.id).total_minutes;
 res.json({ok:true,streak,total_minutes:total});
});
app.get('/api/stats',auth,(req,res)=>{
 const today=todayUTC();
 const week=db.prepare("SELECT COALESCE(SUM(minutes),0) minutes FROM study_sessions WHERE user_id=? AND studied_on>=date(?, '-6 day')").get(req.user.id,today);
 const recent=db.prepare('SELECT room,minutes,studied_on,created_at FROM study_sessions WHERE user_id=? ORDER BY id DESC LIMIT 12').all(req.user.id);
 const byDay=db.prepare("SELECT studied_on,SUM(minutes) minutes FROM study_sessions WHERE user_id=? AND studied_on>=date(?, '-6 day') GROUP BY studied_on ORDER BY studied_on").all(req.user.id,today);
 res.json({week_minutes:week.minutes,recent,byDay});
});
app.get('/api/leaderboard',(req,res)=>res.json(db.prepare('SELECT name,streak,total_minutes FROM users WHERE banned=0 ORDER BY total_minutes DESC, streak DESC, id ASC LIMIT 50').all()));
app.get('/api/rooms',(req,res)=>res.json([...validRooms].map(name=>({name,online:rooms.get(name)?.size||0}))));
app.get('/api/media-config',auth,(req,res)=>res.json({mode:'sfu',configured:!!(process.env.LIVEKIT_URL&&process.env.LIVEKIT_API_KEY&&process.env.LIVEKIT_API_SECRET),url:process.env.LIVEKIT_URL||''}));
app.post('/api/livekit/token',auth,async(req,res)=>{
 try{const room=cleanRoom(req.body?.room);if(!validRooms.has(room))return res.status(400).json({error:'Invalid room.'});
  if(!(process.env.LIVEKIT_URL&&process.env.LIVEKIT_API_KEY&&process.env.LIVEKIT_API_SECRET))return res.status(503).json({error:'Live video is not configured yet. Chat and presence still work.'});
  const at=new AccessToken(process.env.LIVEKIT_API_KEY,process.env.LIVEKIT_API_SECRET,{identity:String(req.user.id),name:req.user.name,ttl:'2h'});
  at.addGrant({roomJoin:true,room,canPublish:true,canSubscribe:true,canPublishData:true});
  res.json({token:await at.toJwt(),url:process.env.LIVEKIT_URL});
 }catch(e){console.error(e);res.status(500).json({error:'Could not create media token.'});}
});
app.post('/api/report',auth,(req,res)=>{
 const room=cleanRoom(req.body?.room),reason=String(req.body?.reason||'').trim().slice(0,500);
 if(!reason)return res.status(400).json({error:'Reason required.'});
 db.prepare('INSERT INTO reports(reporter,room,reason) VALUES(?,?,?)').run(req.user.id,room,reason);res.json({ok:true});
});
app.get('/api/admin/overview',auth,admin,(req,res)=>res.json({users:db.prepare('SELECT COUNT(*) n FROM users WHERE banned=0').get().n,banned:db.prepare('SELECT COUNT(*) n FROM users WHERE banned=1').get().n,reports:db.prepare("SELECT COUNT(*) n FROM reports WHERE status='open'").get().n,minutes:db.prepare('SELECT COALESCE(SUM(minutes),0) n FROM study_sessions').get().n}));
app.get('/api/admin/reports',auth,admin,(req,res)=>res.json(db.prepare('SELECT r.*,u.name reporter_name,u.email reporter_email FROM reports r LEFT JOIN users u ON u.id=r.reporter ORDER BY r.id DESC LIMIT 200').all()));
app.patch('/api/admin/reports/:id',auth,admin,(req,res)=>{const status=['open','reviewed','resolved'].includes(req.body?.status)?req.body.status:'reviewed';db.prepare('UPDATE reports SET status=? WHERE id=?').run(status,req.params.id);res.json({ok:true});});
app.get('/api/admin/users',auth,admin,(req,res)=>res.json(db.prepare('SELECT id,name,email,role,banned,streak,total_minutes,created_at FROM users ORDER BY id DESC LIMIT 200').all()));
app.patch('/api/admin/users/:id/ban',auth,admin,(req,res)=>{const id=Number(req.params.id);if(id===req.user.id)return res.status(400).json({error:'You cannot ban yourself.'});const banned=req.body?.banned?1:0;db.prepare('UPDATE users SET banned=? WHERE id=?').run(banned,id);for(const [sid,s] of activeSockets){if(s.userId===id&&banned)s.disconnect(true)}res.json({ok:true,banned:!!banned});});

const rooms=new Map();const activeSockets=new Map();
function getRoom(name){if(!rooms.has(name))rooms.set(name,new Map());return rooms.get(name)}
function leaveSocket(s){const r=s.data.room;if(r&&rooms.has(r)){getRoom(r).delete(s.id);if(getRoom(r).size===0)rooms.delete(r);io.to(r).emit('users',[...getRoom(r).values()]);s.to(r).emit('system',`${s.data.name||'Student'} left the room`);}activeSockets.delete(s.id);}
const blockedWords=(process.env.CHAT_BLOCKED_WORDS||'').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean);
function safeChat(x){let t=String(x||'').trim().slice(0,500);for(const w of blockedWords)if(w&&t.toLowerCase().includes(w))return '';return t;}
io.on('connection',s=>{
 activeSockets.set(s.id,s);
 s.on('join',({room:r,name})=>{
  const u=s.userId?db.prepare('SELECT id,name,banned FROM users WHERE id=?').get(s.userId):null;
  if(!u||u.banned||!validRooms.has(r))return s.emit('blocked','You cannot join this room.');
  leaveSocket(s);s.data.room=r;s.data.name=u.name;s.userId=u.id;getRoom(r).set(s.id,{id:s.id,name:u.name});
  s.join(r);io.to(r).emit('users',[...getRoom(r).values()]);s.to(r).emit('system',u.name+' joined the room');
 });
 s.on('chat',({room:r,text})=>{if(s.data.room!==r)return;const t=safeChat(text);if(t)io.to(r).emit('chat',{name:s.data.name,text:t});});
 s.on('leave',()=>{s.leave(s.data.room||'');leaveSocket(s)});
 s.on('disconnect',()=>leaveSocket(s));
});
// Socket auth: the client sends the same JWT during handshake.
io.use((s,next)=>{try{const raw=s.handshake.auth?.token||'';const p=jwt.verify(raw,JWT_SECRET);const u=db.prepare('SELECT id,name,banned FROM users WHERE id=?').get(p.id);if(!u||u.banned)return next(new Error('Unauthorized'));s.userId=u.id;next();}catch(e){next(new Error('Unauthorized'));}});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'../client/index.html')));
server.listen(PORT,()=>console.log(`NEET StudyHub running on :${PORT}`));
