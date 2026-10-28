/* AI Sentinel server: static site + REST API + Neon PostgreSQL or local SQLite. */
const http=require('http'),fs=require('fs'),path=require('path'),{createStore}=require('./storage.js');
async function start(){
const PROD=process.env.NODE_ENV==='production',DEMO=process.env.SEED_DEMO!=='0'; /* SEED_DEMO=0 -> real-data mode: starts empty, no synthetic records, no simulator */
if(PROD&&!process.env.ALLOW_DEFAULTS&&(!process.env.ADMIN_PASSWORD||!process.env.ADMIN_KEY)){console.error('Refusing to start in production without ADMIN_PASSWORD and ADMIN_KEY set (use ALLOW_DEFAULTS=1 for a throw-away demo).');process.exit(1)}
const PORT=+process.env.PORT||3000,ROOT=__dirname,SEED=path.join(ROOT,'seed'),DATA=process.env.DATA_DIR||path.join(ROOT,'data'),PUB=path.join(ROOT,'public');
if(!process.env.DATABASE_URL)fs.mkdirSync(DATA,{recursive:true});
const db=createStore();
await db.check();
await db.exec('CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,name TEXT,role TEXT,hash TEXT)');
await db.exec('CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,username TEXT,created BIGINT)');
await db.exec('CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY,v TEXT)');
await db.exec('CREATE TABLE IF NOT EXISTS sv_records(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id))');
await db.exec(`CREATE TABLE IF NOT EXISTS sv_history(id ${db.kind=='postgres'?'BIGSERIAL PRIMARY KEY':'INTEGER PRIMARY KEY AUTOINCREMENT'},kind TEXT,ts TEXT,username TEXT,data TEXT)`);

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
 HEAD[k]=csvHead(k+'.csv');const cols=HEAD[k];
 await db.exec(`CREATE TABLE IF NOT EXISTS ds_${k}(${cols.map(c=>q(c)+' TEXT'+(c==IDK[k]?' PRIMARY KEY':'')).join(',')})`);
 const count=Number((await db.get(`SELECT COUNT(*) AS n FROM ds_${k}`)).n);
 if(count>0)RAW[k]=(await db.all(`SELECT ${cols.map(q).join(',')} FROM ds_${k} ORDER BY ${q(IDK[k])}`)).map(r=>({...r}));
 else if(DEMO){RAW[k]=csvObjs(k+'.csv');dirty.add(k)}
 else RAW[k]=[];
 saved[k]=0}
const E=require('./engine.js')(RAW,HEAD,DEMO);

/* ---------- users ---------- */
const ADMIN_PW=process.env.ADMIN_PASSWORD||'sentinel123';
if(!await db.get('SELECT 1 FROM users WHERE username=?',['admin']))
 await db.run('INSERT INTO users VALUES(?,?,?,?)',['admin','Fraud Investigator','admin',E.H.hash(ADMIN_PW)]);
for(const u of await db.all('SELECT * FROM users'))E.USERS[u.username]={name:u.name,role:u.role,hash:u.hash};
/* sessions: stored in the database, expire after SESSION_HOURS (default 12) */
const TTL=(+process.env.SESSION_HOURS||12)*36e5,SESS_T={};
for(const s of await db.all('SELECT * FROM sessions'))if(Date.now()-s.created<TTL&&E.USERS[s.username]){E.sessions[s.token]=s.username;SESS_T[s.token]=+s.created}
const purge=()=>{const n=Date.now();for(const t of Object.keys(SESS_T))if(!E.sessions[t]||n-SESS_T[t]>TTL){delete E.sessions[t];delete SESS_T[t]}for(const t of Object.keys(E.sessions))SESS_T[t]=SESS_T[t]||n};
const st0=await db.get("SELECT v FROM kv WHERE k='state'");
if(st0)try{E.st=JSON.parse(st0.v)}catch(e){console.error('Could not restore saved state:',e.message)}

/* ---------- verification datasets (message + loan) ---------- */
const SV={mv:{idk:'checkid',pre:'MSG',csv:'ai_sentinel_message_verification_400.csv',ok:r=>r.messagetext&&/^(susp|gen)/i.test(r.label||'')},
          dv:{idk:'applicationid',pre:'LOAN',csv:'ai_sentinel_loan_verification_400.csv',ok:r=>r.applicantname&&/^(review|cons)/i.test(r.label||'')}};
const svPut='INSERT INTO sv_records(kind,id,data) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data';
async function svSeed(k){const c=SV[k];let n=0;
 await db.transaction(async client=>{await db.tx.run('DELETE FROM sv_records WHERE kind=?',[k],client);
  for(const r of csvObjs(c.csv,true))if(c.ok(r)&&r[c.idk]){await db.tx.run(svPut,[k,r[c.idk],JSON.stringify(r)],client);n++}});
 return n}
if(DEMO)for(const k of Object.keys(SV))if(!await db.get('SELECT 1 FROM sv_records WHERE kind=?',[k]))await svSeed(k);
const J=(b,s=200)=>({status:s,json:()=>b}),bad=(s,d)=>J({detail:d},s);
async function svRoute(m,p,b,tok){
 const un=Object.entries(E.sessions).find(([t])=>t==tok);if(!un)return bad(401,'Login required');
 const x=p.match(/^\/sv\/(mv|dv)\/(records|import|reset|history)$/);if(!x)return bad(404,'Not found');const k=x[1],c=SV[k];
 if(x[2]=='records')return J({rows:(await db.all('SELECT data FROM sv_records WHERE kind=? ORDER BY id',[k])).map(r=>JSON.parse(r.data))});
 if(m!='POST')return bad(405,'POST required');
 if(x[2]=='reset'){if(!DEMO)return bad(403,'Disabled in real-data mode (it would delete your records)');return J({ok:true,records:await svSeed(k)})}
 if(x[2]=='import'){const rows=Array.isArray(b.rows)?b.rows.slice(0,5000):[];let added=0;
  await db.transaction(async client=>{for(const [i,row] of rows.entries()){const r=Object.fromEntries(Object.entries(row||{}).map(([a,v])=>[a.toLowerCase(),String(v).slice(0,2000)]));if(!c.ok(r))continue;
   r[c.idk]=r[c.idk]||c.pre+'-'+Date.now().toString(36).toUpperCase()+i;await db.tx.run(svPut,[k,r[c.idk],JSON.stringify(r)],client);added++}});
  return J({added,skipped:rows.length-added})}
 if(x[2]=='history'){await db.run('INSERT INTO sv_history(kind,ts,username,data) VALUES(?,?,?,?)',[k,new Date().toISOString(),un[1],JSON.stringify(b).slice(0,20000)]);return J({ok:true})}}

/* ---------- persistence ---------- */
async function save(){const lengths={};
 try{purge();await db.transaction(async client=>{
  await db.tx.run("INSERT INTO kv(k,v) VALUES('state',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",[JSON.stringify(E.st)],client);
  await db.tx.run('DELETE FROM sessions',[],client);
  for(const [t,u] of Object.entries(E.sessions))await db.tx.run('INSERT INTO sessions(token,username,created) VALUES(?,?,?)',[t,u,SESS_T[t]],client);
  for(const [u,v] of Object.entries(E.USERS))await db.tx.run('INSERT INTO users(username,name,role,hash) VALUES(?,?,?,?) ON CONFLICT(username) DO UPDATE SET name=excluded.name,role=excluded.role,hash=excluded.hash',[u,v.name,v.role,v.hash],client);
  for(const k of Object.keys(IDK)){const rows=E.DB[k];if(!rows.length)continue;const cols=Object.keys(rows[0]);
   const ins=`INSERT INTO ds_${k}(${cols.map(q).join(',')}) VALUES(${cols.map(()=>'?').join(',')}) ON CONFLICT(${q(IDK[k])}) DO UPDATE SET ${cols.filter(c=>c!=IDK[k]).map(c=>q(c)+'=excluded.'+q(c)).join(',')||q(IDK[k])+'=excluded.'+q(IDK[k])}`;
   for(const r of rows.slice(dirty.has(k)?0:saved[k]))await db.tx.run(ins,cols.map(c=>r[c]??''),client);
   lengths[k]=rows.length}
 });for(const [k,n] of Object.entries(lengths)){saved[k]=n;dirty.delete(k)}}catch(e){console.error('database save failed:',e.message);throw e}}
let timer=null;const later=()=>{if(!timer)timer=setTimeout(()=>{timer=null;save().catch(()=>{})},400)};
await save();setInterval(()=>save().catch(()=>{}),10000).unref();

/* ---------- HTTP ---------- */
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.csv':'text/csv'};
const send=(res,s,body,h={})=>{res.writeHead(s,{'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'",...(process.env.HTTPS_ONLY?{'Strict-Transport-Security':'max-age=31536000; includeSubDomains'}:{}),'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY',...h});res.end(body)};
const fails={};
async function api(req,res,url){
 const chunks=[];let n=0;for await(const c of req){n+=c.length;if(n>8e6)return send(res,413,'{"detail":"Request too large"}',{'Content-Type':'application/json'});chunks.push(c)}
 let b={};try{b=chunks.length?JSON.parse(Buffer.concat(chunks)):{}}catch(e){return send(res,400,'{"detail":"Invalid JSON"}',{'Content-Type':'application/json'})}
 const p=url.pathname.slice(4),m=req.method,tok=(req.headers.authorization||'').replace(/^Bearer /,''),ip=process.env.TRUST_PROXY?((req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress):req.socket.remoteAddress;purge();
 if(p=='/health'){try{await db.check();return send(res,200,JSON.stringify({ok:true,db:db.kind,mode:DEMO?'demo':'real',defaults:!process.env.ADMIN_PASSWORD||!process.env.ADMIN_KEY}),{'Content-Type':'application/json'})}
  catch(e){console.error('Database health check failed:',e.message);return send(res,503,JSON.stringify({ok:false,db:db.kind}),{'Content-Type':'application/json'})}}
 if(['/login','/register/verify','/register'].includes(p)){const f=fails[ip]=(fails[ip]||[]).filter(t=>Date.now()-t<9e5);if(f.length>=10)return send(res,429,'{"detail":"Too many attempts. Try again in 15 minutes."}',{'Content-Type':'application/json'})}
 let r=p.startsWith('/sv/')?await svRoute(m,p,b,tok):await E.route(m,p,b,tok);
 if(r.status>=400&&['/login','/register/verify','/register'].includes(p))fails[ip].push(Date.now());
 if(m=='POST'&&/^\/data\/(employees|customers|transactions|activity_events)$/.test(p))dirty.add(p.split('/')[2]);
 if(p=='/reset'&&r.status<400)Object.keys(IDK).forEach(k=>dirty.add(k));
 purge();if(m!='GET')later();
 send(res,r.status,JSON.stringify(await r.json()),{'Content-Type':'application/json','Cache-Control':'no-store'})}
const server=http.createServer((req,res)=>{try{const url=new URL(req.url,'http://x');
 if(url.pathname.startsWith('/api/'))return api(req,res,url).catch(e=>{console.error(e);send(res,500,'{"detail":"Server error"}',{'Content-Type':'application/json'})});
 let f=path.normalize(path.join(PUB,url.pathname=='/'?'index.html':decodeURIComponent(url.pathname)));
 if(!f.startsWith(PUB)||!fs.existsSync(f)||fs.statSync(f).isDirectory())f=path.join(PUB,'index.html');
 send(res,200,fs.readFileSync(f),{'Content-Type':MIME[path.extname(f)]||'application/octet-stream','Cache-Control':'no-cache'})}
 catch(e){send(res,400,'Bad request')}});
server.listen(PORT,()=>console.log(`AI Sentinel running at http://localhost:${PORT}  [${DEMO?'DEMO mode: synthetic data':'REAL-DATA mode: starts empty'}]  (database: ${db.location})`));
for(const s of['SIGINT','SIGTERM'])process.on(s,()=>server.close(async()=>{try{await save();await db.close();process.exit(0)}catch(e){console.error('Shutdown failed:',e.message);process.exit(1)}}));
}
start().catch(e=>{console.error('Startup failed:',e.message);process.exit(1)});
