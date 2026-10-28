/* AI Sentinel server: static site + REST API + SQLite database. Zero npm dependencies (Node 22.5+). */
const http=require('http'),fs=require('fs'),path=require('path'),{DatabaseSync}=require('node:sqlite');
const PROD=process.env.NODE_ENV==='production',DEMO=process.env.SEED_DEMO!=='0'; /* SEED_DEMO=0 -> real-data mode: starts empty, no synthetic records, no simulator */
if(PROD&&!process.env.ALLOW_DEFAULTS&&(!process.env.ADMIN_PASSWORD||!process.env.ADMIN_KEY)){console.error('Refusing to start in production without ADMIN_PASSWORD and ADMIN_KEY set (use ALLOW_DEFAULTS=1 for a throw-away demo).');process.exit(1)}
const PORT=+process.env.PORT||3000,ROOT=__dirname,SEED=path.join(ROOT,'seed'),DATA=process.env.DATA_DIR||path.join(ROOT,'data'),PUB=path.join(ROOT,'public');
fs.mkdirSync(DATA,{recursive:true});
const db=new DatabaseSync(process.env.DB_FILE||path.join(DATA,'sentinel.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,name TEXT,role TEXT,hash TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,username TEXT,created INTEGER);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS sv_records(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS sv_history(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,ts TEXT,username TEXT,data TEXT);`);

/* ---------- CSV ---------- */
function parseCsv(t){t=t.replace(/^\uFEFF/,'');const rows=[];let r=[],c='',q=false;
 for(let i=0;i<t.length;i++){const ch=t[i];if(q){if(ch=='"'&&t[i+1]=='"'){c+='"';i++}else if(ch=='"')q=false;else c+=ch}
  else if(ch=='"')q=true;else if(ch==','){r.push(c);c=''}else if(ch=='\n'||ch=='\r'){if(ch=='\r'&&t[i+1]=='\n')i++;r.push(c);c='';if(r.some(x=>x!==''))rows.push(r);r=[]}else c+=ch}
 if(c!==''||r.length){r.push(c);rows.push(r)}return rows}
const csvHead=f=>parseCsv(fs.readFileSync(path.join(SEED,f),'utf8'))[0];
const csvObjs=(f,lower)=>{const [h,...b]=parseCsv(fs.readFileSync(path.join(SEED,f),'utf8'));return b.map(a=>Object.fromEntries(h.map((k,i)=>[lower?k.toLowerCase():k,a[i]||''])))};

/* ---------- operational datasets (employees, customers, transactions, events): real SQL tables ---------- */
const IDK={employees:'EmployeeID',customers:'CustomerID',transactions:'TransactionID',activity_events:'EventID'};
const q=s=>'"'+s+'"',RAW={},HEAD={},saved={},dirty=new Set();
for(const k of Object.keys(IDK)){
 const has=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get('ds_'+k);
 if(has&&db.prepare(`SELECT COUNT(*) n FROM ds_${k}`).get().n)RAW[k]=db.prepare(`SELECT * FROM ds_${k} ORDER BY rowid`).all().map(r=>({...r}));
 else if(DEMO){RAW[k]=csvObjs(k+'.csv');dirty.add(k)}
 else RAW[k]=[];
 HEAD[k]=csvHead(k+'.csv');const cols=HEAD[k];db.exec(`CREATE TABLE IF NOT EXISTS ds_${k}(${cols.map((c,i)=>q(c)+' TEXT'+(c==IDK[k]?' PRIMARY KEY':'')).join(',')})`);saved[k]=0}
const E=require('./engine.js')(RAW,HEAD,DEMO);

/* ---------- users ---------- */
const ADMIN_PW=process.env.ADMIN_PASSWORD||'sentinel123';
if(!db.prepare('SELECT 1 FROM users WHERE username=?').get('admin'))
 db.prepare('INSERT INTO users VALUES(?,?,?,?)').run('admin','Fraud Investigator','admin',E.H.hash(ADMIN_PW));
db.prepare('SELECT * FROM users').all().forEach(u=>E.USERS[u.username]={name:u.name,role:u.role,hash:u.hash});
/* sessions: stored in the database, expire after SESSION_HOURS (default 12) */
const TTL=(+process.env.SESSION_HOURS||12)*36e5,SESS_T={};
db.prepare('SELECT * FROM sessions').all().forEach(s=>{if(Date.now()-s.created<TTL&&E.USERS[s.username]){E.sessions[s.token]=s.username;SESS_T[s.token]=s.created}});
const purge=()=>{const n=Date.now();for(const t of Object.keys(SESS_T))if(!E.sessions[t]||n-SESS_T[t]>TTL){delete E.sessions[t];delete SESS_T[t]}for(const t of Object.keys(E.sessions))SESS_T[t]=SESS_T[t]||n};
const st0=db.prepare("SELECT v FROM kv WHERE k='state'").get();
if(st0)try{E.st=JSON.parse(st0.v)}catch(e){console.error('Could not restore saved state:',e.message)}

/* ---------- verification datasets (message + loan) ---------- */
const SV={mv:{idk:'checkid',pre:'MSG',csv:'ai_sentinel_message_verification_400.csv',ok:r=>r.messagetext&&/^(susp|gen)/i.test(r.label||'')},
          dv:{idk:'applicationid',pre:'LOAN',csv:'ai_sentinel_loan_verification_400.csv',ok:r=>r.applicantname&&/^(review|cons)/i.test(r.label||'')}};
const svPut=db.prepare('INSERT OR REPLACE INTO sv_records VALUES(?,?,?)');
function svSeed(k){db.prepare('DELETE FROM sv_records WHERE kind=?').run(k);const c=SV[k];let n=0;
 db.exec('BEGIN');for(const r of csvObjs(c.csv,true))if(c.ok(r)&&r[c.idk]){svPut.run(k,r[c.idk],JSON.stringify(r));n++}db.exec('COMMIT');return n}
if(DEMO)for(const k of Object.keys(SV))if(!db.prepare('SELECT 1 FROM sv_records WHERE kind=?').get(k))svSeed(k);
const J=(b,s=200)=>({status:s,json:()=>b}),bad=(s,d)=>J({detail:d},s);
function svRoute(m,p,b,tok){
 const un=Object.entries(E.sessions).find(([t])=>t==tok);if(!un)return bad(401,'Login required');
 const x=p.match(/^\/sv\/(mv|dv)\/(records|import|reset|history)$/);if(!x)return bad(404,'Not found');const k=x[1],c=SV[k];
 if(x[2]=='records')return J({rows:db.prepare('SELECT data FROM sv_records WHERE kind=? ORDER BY rowid').all(k).map(r=>JSON.parse(r.data))});
 if(m!='POST')return bad(405,'POST required');
 if(x[2]=='reset'){if(!DEMO)return bad(403,'Disabled in real-data mode (it would delete your records)');return J({ok:true,records:svSeed(k)})}
 if(x[2]=='import'){const rows=Array.isArray(b.rows)?b.rows.slice(0,5000):[];let added=0;db.exec('BEGIN');
  rows.forEach((r,i)=>{r=Object.fromEntries(Object.entries(r||{}).map(([a,v])=>[a.toLowerCase(),String(v).slice(0,2000)]));if(!c.ok(r))return;
   r[c.idk]=r[c.idk]||c.pre+'-'+Date.now().toString(36).toUpperCase()+i;svPut.run(k,r[c.idk],JSON.stringify(r));added++});db.exec('COMMIT');return J({added,skipped:rows.length-added})}
 if(x[2]=='history'){db.prepare('INSERT INTO sv_history(kind,ts,username,data) VALUES(?,?,?,?)').run(k,new Date().toISOString(),un[1],JSON.stringify(b).slice(0,20000));return J({ok:true})}}

/* ---------- persistence ---------- */
function save(){try{db.exec('BEGIN');
 db.prepare("INSERT OR REPLACE INTO kv VALUES('state',?)").run(JSON.stringify(E.st));
 purge();db.exec('DELETE FROM sessions');const sp=db.prepare('INSERT INTO sessions VALUES(?,?,?)');Object.entries(E.sessions).forEach(([t,u])=>sp.run(t,u,SESS_T[t]));
 const up=db.prepare('INSERT OR REPLACE INTO users VALUES(?,?,?,?)');Object.entries(E.USERS).forEach(([u,v])=>up.run(u,v.name,v.role,v.hash));
 for(const k of Object.keys(IDK)){const rows=E.DB[k];if(!rows.length)continue;const cols=Object.keys(rows[0]),
   ins=db.prepare(`INSERT OR REPLACE INTO ds_${k}(${cols.map(q).join(',')}) VALUES(${cols.map(()=>'?').join(',')})`);
  for(const r of rows.slice(dirty.has(k)?0:saved[k]))ins.run(...cols.map(c=>r[c]??''));saved[k]=rows.length;dirty.delete(k)}
 db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch(_){}console.error('save failed:',e.message)}}
let timer=null;const later=()=>{if(!timer)timer=setTimeout(()=>{timer=null;save()},400)};
save();setInterval(save,10000).unref();

/* ---------- HTTP ---------- */
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.csv':'text/csv'};
const send=(res,s,body,h={})=>{res.writeHead(s,{'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'",...(process.env.HTTPS_ONLY?{'Strict-Transport-Security':'max-age=31536000; includeSubDomains'}:{}),'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY',...h});res.end(body)};
const fails={};
async function api(req,res,url){
 const chunks=[];let n=0;for await(const c of req){n+=c.length;if(n>8e6)return send(res,413,'{"detail":"Request too large"}',{'Content-Type':'application/json'});chunks.push(c)}
 let b={};try{b=chunks.length?JSON.parse(Buffer.concat(chunks)):{}}catch(e){return send(res,400,'{"detail":"Invalid JSON"}',{'Content-Type':'application/json'})}
 const p=url.pathname.slice(4),m=req.method,tok=(req.headers.authorization||'').replace(/^Bearer /,''),ip=process.env.TRUST_PROXY?((req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress):req.socket.remoteAddress;purge();
 if(p=='/health')return send(res,200,JSON.stringify({ok:true,db:'sqlite',mode:DEMO?'demo':'real',defaults:!process.env.ADMIN_PASSWORD||!process.env.ADMIN_KEY}),{'Content-Type':'application/json'});
 if(['/login','/register/verify','/register'].includes(p)){const f=fails[ip]=(fails[ip]||[]).filter(t=>Date.now()-t<9e5);if(f.length>=10)return send(res,429,'{"detail":"Too many attempts. Try again in 15 minutes."}',{'Content-Type':'application/json'})}
 let r=p.startsWith('/sv/')?svRoute(m,p,b,tok):await E.route(m,p,b,tok);
 if(r.status>=400&&['/login','/register/verify','/register'].includes(p))fails[ip].push(Date.now());
 if(m=='POST'&&/^\/data\/(employees|customers|transactions|activity_events)$/.test(p))dirty.add(p.split('/')[2]);
 if(p=='/reset'&&r.status<400)Object.keys(IDK).forEach(k=>dirty.add(k));
 purge();if(m!='GET')later();
 send(res,r.status,JSON.stringify(await r.json()),{'Content-Type':'application/json','Cache-Control':'no-store'})}
http.createServer((req,res)=>{try{const url=new URL(req.url,'http://x');
 if(url.pathname.startsWith('/api/'))return api(req,res,url).catch(e=>{console.error(e);send(res,500,'{"detail":"Server error"}',{'Content-Type':'application/json'})});
 let f=path.normalize(path.join(PUB,url.pathname=='/'?'index.html':decodeURIComponent(url.pathname)));
 if(!f.startsWith(PUB)||!fs.existsSync(f)||fs.statSync(f).isDirectory())f=path.join(PUB,'index.html');
 send(res,200,fs.readFileSync(f),{'Content-Type':MIME[path.extname(f)]||'application/octet-stream','Cache-Control':'no-cache'})}
 catch(e){send(res,400,'Bad request')}}).listen(PORT,()=>console.log(`AI Sentinel running at http://localhost:${PORT}  [${DEMO?'DEMO mode: synthetic data':'REAL-DATA mode: starts empty'}]  (database: ${db.location?.()||'sqlite'})`));
for(const s of['SIGINT','SIGTERM'])process.on(s,()=>{save();try{db.close()}catch(e){}process.exit(0)});
