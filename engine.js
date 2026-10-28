/* AI Sentinel engine: detection rules, honeypot, cases, graph, import. Runs on the server; state is persisted by server.js */
const crypto=require('crypto');
const H={hash:p=>{const s=crypto.randomBytes(16).toString('hex');return s+':'+crypto.scryptSync(String(p),s,32).toString('hex')},
 check:(u,p)=>{const[s,h]=String(u.hash||'').split(':');if(!h)return false;return crypto.timingSafeEqual(Buffer.from(crypto.scryptSync(String(p),s,32).toString('hex')),Buffer.from(h))}};
module.exports=function(RAW,HEAD,DEMO){
const DB=RAW;
const IDK={employees:'EmployeeID',customers:'CustomerID',transactions:'TransactionID',activity_events:'EventID'};
const COLS={};Object.keys(DB).forEach(k=>COLS[k]=(HEAD&&HEAD[k])||Object.keys(DB[k][0]));
const sid=(p,x)=>p+(+String(x).replace(/\D/g,'')),pad=(n,w)=>String(n).padStart(w,'0'),eid=e=>'EMP'+pad(e.slice(1),4),cid=c=>'CUS'+pad(c.slice(1),4);
const inr=n=>'₹'+Math.round(n).toLocaleString('en-IN'),hrOf=t=>{const m=String(t).match(/[T ](\d\d):(\d\d)/);return m?+m[1]+m[2]/60:12};
const clk12=h=>{const hh=Math.floor(h),m=Math.round((h-hh)*60);return((hh%12)||12)+':'+pad(m,2)+' '+(hh<12?'AM':'PM')};
const off=h=>h<6||h>=22,EXF=['Data Export','USB Connected','File Download','File Upload'];
let EM={},EVS={},TXS={},SHARED={};
function idx(){EM={};EVS={};TXS={};DB.employees.forEach(r=>EM[sid('E',r.EmployeeID)]=r);
 DB.activity_events.forEach(r=>{const e=sid('E',r.EmployeeID);(EVS[e]=EVS[e]||[]).push(r)});DB.transactions.forEach(r=>{const e=sid('E',r.EmployeeID);(TXS[e]=TXS[e]||[]).push(r)})}
const ename=e=>EM[e]?EM[e].EmployeeName:e;
function analyse(e){const m=EM[e]||{},ev=EVS[e]||[],tx=TXS[e]||[],rs=[],add=(i,t,p)=>p>0&&rs.push([i,t,Math.round(p)]);
 const night=ev.filter(x=>off(hrOf(x.EventTimestamp)));if(night.length){const x=night.slice().sort((a,b)=>a.EventTimestamp<b.EventTimestamp?1:-1)[0];add('🕑','Off-hours activity at '+clk12(hrOf(x.EventTimestamp)),Math.min(20,14+3*(night.length-1)))}
 const ex=ev.filter(x=>EXF.includes(x.EventType)&&['High','Critical'].includes(x.Severity));if(ex.length)add('💾',ex.length+' high-severity data event'+(ex.length>1?'s':'')+' ('+[...new Set(ex.map(x=>x.EventType))].slice(0,2).join(', ')+')',Math.min(26,10+8*ex.length));
 const fb=ev.filter(x=>['Failed','Blocked'].includes(x.EventStatus));if(fb.length>=2)add('⛔',fb.length+' failed or blocked actions',Math.min(15,5*fb.length));
 const pc=ev.filter(x=>x.EventType=='Permission Change'&&['High','Critical'].includes(x.Severity));if(pc.length)add('🔐','Privilege change flagged '+pc[0].Severity,12);
 const mob=ev.filter(x=>/Phone/.test(x.Device)&&['Database','CRM'].includes(x.Application));if(mob.length)add('💻','Unrecognised device: '+mob[0].Device+' on '+mob[0].Application,12);
 const loc=new Set(ev.map(x=>x.Location));if(loc.size>=3)add('📍','Activity from '+loc.size+' locations',10);
 const fl=tx.filter(x=>x.Flagged=='Yes'),big=Math.max(0,...fl.map(x=>+x.Amount));if(big>=45000)add('💸','Large flagged transaction '+inr(big),big>=65000?28:big>=55000?22:16);
 const hr=Math.max(0,...tx.map(x=>+x.RiskScore));if(hr>=85)add('⚠️','High-risk transaction (model risk '+Math.round(hr)+')',15);
 const rf=tx.filter(x=>['Refund','Refunded','Failed'].includes(x.TransactionType)||x.TransactionStatus=='Refunded');if(rf.length>=2)add('🔁',rf.length+' refunds / reversals handled',12);
 if(SHARED[e])add('🔗','Shared payee with '+SHARED[e],35);
 if(m.SecurityRisk=='High')add('🛡️','HR security rating: High',14);if(+m.AlertsCount>=7)add('🚩',m.AlertsCount+' prior alerts on record',8);
 if(['On Leave','Absent'].includes(m.AttendanceStatus)&&ev.length)add('🏖️','Activity while marked '+m.AttendanceStatus,15);
 const z=(ev.length-1.6)/.8+(tx.reduce((a,x)=>a+ +x.Amount,0)-38000)/22000;add('🤖','Behaviour model anomaly',Math.min(10,Math.max(0,2*z)));
 const score=Math.min(100,rs.reduce((a,r)=>a+r[2],0)),top=rs.reduce((a,b)=>b[2]>a[2]?b:a,['','',0]),last=ev.map(x=>x.EventTimestamp).sort().pop();
 return{score,rs,trig:top[1],t:last?clk12(hrOf(last)):'—'}}
function scan(){idx();SHARED={};const pre={};Object.keys(EM).forEach(e=>pre[e]=analyse(e).score);const own={};
 DB.transactions.filter(x=>x.Flagged=='Yes').forEach(x=>{(own[x.CustomerID]=own[x.CustomerID]||new Set()).add(sid('E',x.EmployeeID))});
 Object.values(own).forEach(s=>{const a=[...s].filter(e=>pre[e]>=35);if(a.length>1)a.forEach(e=>SHARED[e]=ename(a.find(o=>o!=e)))});
 const out={};Object.keys(EM).forEach(e=>out[e]=analyse(e));return out}
const ENG=(()=>{const out=scan(),ids=Object.keys(out).filter(e=>out[e].score>=35).sort((a,b)=>out[b].score-out[a].score).slice(0,60);
 const seed=ids.map((e,i)=>({id:'A-'+(2001+i),e,trig:out[e].trig,score:out[e].score,st:'New',t:out[e].t,r:out[e].rs.map(x=>x.join('|')).join(';')}));
 const emp={};Object.keys(EM).forEach(e=>emp[e]=[EM[e].EmployeeName,EM[e].Department]);const touch={};
 DB.transactions.filter(x=>x.Flagged=='Yes').forEach(x=>{const e=sid('E',x.EmployeeID),c=sid('C',x.CustomerID);(touch[e]=touch[e]||[]);if(!touch[e].includes(c))touch[e].push(c)});
 return{seed,emp,touch,seq:DEMO===false?1000:2001+seed.length,top:ids.slice(0,3),aid:seed.slice(0,2).map(a=>a.id)}})();

const SEED=ENG.seed,EMPD=ENG.emp,TOUCH=ENG.touch,KEY=process.env.ADMIN_KEY||'SENTINEL-2026';
const USERS={};
const HPD=[{id:'D1',name:'swift_beneficiaries_2019',kind:'Decoy table',sens:5},{id:'D2',name:'ceo_salary_ledger',kind:'Decoy table',sens:4},{id:'D3',name:'kyc_master_backup',kind:'Decoy table',sens:5},{id:'D4',name:'vip_accounts_archive',kind:'Decoy table',sens:4},{id:'D5',name:'Canary record CUST-9917',kind:'Canary record',sens:3}],HPW={SELECT:.3,EXPORT:.9,UPDATE:.6,DELETE:.8};
function hpFresh(){if(DEMO===false)return{auto:true,seq:3100,n:0,log:[],sess:[]};return{auto:true,seq:3102,n:3,log:[{id:'L-3',ts:'8:05 AM',emp:ENG.top[2],src:'Core DB',dec:null,obj:'customer_accounts',act:'SELECT',rows:12,score:6,alert:null,iso:0,sess:'',ms:0},{id:'L-2',ts:'1:12 AM',emp:ENG.top[1],src:'Decoy trigger',dec:'D2',act:'SELECT',rows:14,score:74,alert:ENG.aid[1],iso:0,sess:'S-3102',ms:0},{id:'L-1',ts:'2:31 AM',emp:ENG.top[0],src:'Decoy trigger',dec:'D1',act:'EXPORT',rows:5200,score:97,alert:ENG.aid[0],iso:1,sess:'S-3101',ms:900}],sess:[{id:'S-3102',emp:ENG.top[1],ip:'10.4.7.52',dev:'Known device',start:'1:05 AM',state:'Active',hits:1,sbq:0},{id:'S-3101',emp:ENG.top[0],ip:'10.4.2.17',dev:'Unknown device',start:'2:28 AM',state:'Isolated',hits:1,sbq:6}]}}
/* Layer 2: central log -> AI/ML risk score -> alert -> session isolation */
function hpHit(b,un){const d=HPD.find(x=>x.id==b.decoy);if(!st.emp[b.emp])return err(404,'Employee not found');if(!d)return err(404,'Decoy not found');if(!HPW[b.act])return err(422,'Invalid action');if(!(b.hour>=0&&b.hour<24))return err(422,'Invalid access time');
 const h=st.hp,rows=Math.max(1,Math.min(1e6,Math.round(+b.rows)||1)),dev=!!b.new_device,prior=h.log.filter(l=>l.emp==b.emp&&l.dec).length,prev=Math.max(0,...st.alerts.filter(a=>a.e==b.emp&&a.st!='Reviewed').map(a=>a.score))/100,off=b.hour<6||b.hour>=20;
 const f=[['🪤','Touched decoy '+d.name+' (no legitimate use)',1.2+d.sens*.28],['⚙️',b.act+' operation',HPW[b.act]*1.6],['📦',rows.toLocaleString()+' row(s) touched',Math.min(1.5,Math.log10(rows+1)*.45)],['🕑','Off-hours access at '+clk(b.hour),off?1.1:0],['💻','Unknown device',dev?.9:0],['🔁','Repeat decoy hits ('+(prior+1)+')',Math.min(prior,3)*.3],['📈','Already flagged by behaviour model',prev*.8]].filter(x=>x[2]>0),
 T=f.reduce((a,x)=>a+x[2],0),sc=Math.max(1,Math.min(100,Math.round(100/(1+Math.exp(2.4-T))))),rs=f.map(x=>[x[0],x[1],Math.max(1,Math.round(sc*x[2]/T))]);rs[0][2]=Math.max(1,rs[0][2]+sc-rs.reduce((a,x)=>a+x[2],0));
 let s=h.sess.find(x=>x.emp==b.emp&&(x.state=='Active'||x.state=='Isolated'));if(!s){s={id:'S-'+(++h.seq),emp:b.emp,ip:'10.4.'+RI(9)+'.'+(10+RI(200)),dev:dev?'Unknown device':'Known device',start:clk(b.hour),state:'Active',hits:0,sbq:0};h.sess.unshift(s)}
 const was=s.state=='Isolated';s.hits++;if(was)s.sbq++;if(dev)s.dev='Unknown device';
 const r=store({id:'A-'+(++st.seq),e:b.emp,trig:'Honeypot: '+d.name,score:sc,st:'New',t:clk(b.hour),r:rs.map(x=>x.join('|')).join(';')},un);
 let iso=was?1:0,ms=0;if(!was&&h.auto&&sc>=st.prefs.thr){s.state='Isolated';iso=1;ms=300+RI(2200);log(un,'auto-isolated session',s.id+' · '+st.emp[b.emp][0])}
 h.log.unshift({id:'L-'+(++h.n),ts:clk(b.hour),emp:b.emp,src:'Decoy trigger',dec:d.id,act:b.act,rows,score:sc,alert:r.alert.id,iso,sess:s.id,ms});if(h.log.length>80)h.log.length=80;log(un,'honeypot hit','#'+r.alert.id+' '+d.name+' score '+sc);
 return R({alert:r.alert,case:r.case,score:sc,isolated:iso,session:s.id,message:'Alert #'+r.alert.id+' created'+(iso?' · session '+s.id+' isolated automatically':'')})}
function hpNoise(){const k=Object.keys(st.emp);for(let i=1+RI(3);i>0;i--)st.hp.log.unshift({id:'L-'+(++st.hp.n),ts:now(),emp:k[RI(k.length)],src:RI(2)?'Core DB':'App gateway',dec:null,obj:['customer_accounts','txn_ledger','branch_report','loan_applications'][RI(4)],act:'SELECT',rows:1+RI(40),score:2+RI(12),alert:null,iso:0,sess:'',ms:0});if(st.hp.log.length>80)st.hp.log.length=80}
function hpRandom(){const k=Object.keys(st.emp);return hpHit({emp:k[RI(k.length)],decoy:HPD[RI(5)].id,act:['SELECT','SELECT','EXPORT','UPDATE','DELETE'][RI(5)],rows:[3,15,120,2500,9000][RI(5)],hour:RI(10)<6?RI(6)+RI(60)/60:10+RI(8),new_device:RI(2)==1},'system')}
const fresh=()=>({alerts:JSON.parse(JSON.stringify(SEED)),cases:[],prefs:{email:true,auto:false,thr:80,mask:false},audit:[],seq:ENG.seq,emp:JSON.parse(JSON.stringify(EMPD)),touch:JSON.parse(JSON.stringify(TOUCH)),hp:hpFresh()});
let st=fresh(),sessions={};
const now=()=>new Date().toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});
const clk=h=>{const hh=Math.floor(h),m=Math.round((h-hh)*60);return((hh%12)||12)+':'+String(m).padStart(2,'0')+' '+(hh<12?'AM':'PM')};
const log=(u,a,d='')=>st.audit.unshift({ts:new Date().toLocaleString([],{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}),user:u,action:a,detail:d});
const R=(b,s=200)=>({status:s,ok:s<400,json:()=>Promise.resolve(JSON.parse(JSON.stringify(b)))});
const err=(s,d)=>R({detail:d},s);
const ts=()=>new Date().toLocaleString([],{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
const cev=(c,kind,text,user)=>c.ev.unshift({ts:ts(),user,kind,text});
const cv=c=>{const a=st.alerts.find(x=>x.id==c.a);return{id:c.id,a:c.a,e:c.e,t:c.t,open:c.open,owner:c.owner,outcome:c.outcome,score:a?a.score:0,notes:c.ev.filter(x=>x.kind=='note').length}};
const OUT=['','Confirmed fraud','False positive','Inconclusive'];
const cdet=c=>({case:cv(c),alert:st.alerts.find(x=>x.id==c.a),emp:{id:c.e,name:st.emp[c.e][0],dept:st.emp[c.e][1]},customers:(st.touch[c.e]||[]).slice(),events:c.ev});
const openCase=(a,user='system')=>{if(st.cases.find(c=>c.a==a.id))return null;const c={id:'C-'+(101+st.cases.length),a:a.id,e:a.e,t:now(),open:1,owner:'',outcome:'',ev:[]};cev(c,'opened','Case opened from alert #'+a.id+' (risk '+a.score+')',user);st.cases.unshift(c);return cv(c)};
function graph(){const top={};st.alerts.forEach(a=>{if(a.st!='Reviewed'&&(a.score>=60||SHARED[a.e])&&(st.touch[a.e]||[]).length)top[a.e]=Math.max(top[a.e]||0,a.score)});
 const by={};Object.keys(top).forEach(e=>(st.touch[e]||[]).forEach(c=>(by[c]=by[c]||new Set()).add(e)));
 const links=[],adj={};Object.keys(top).forEach(e=>(st.touch[e]||[]).forEach(c=>{const s=by[c].size>1;links.push({source:e,target:c,suspicious:s});if(s){(adj[e]=adj[e]||new Set()).add(c);(adj[c]=adj[c]||new Set()).add(e)}}));
 const seen=new Set(),rings=[];Object.keys(adj).forEach(n=>{if(seen.has(n))return;const comp=[],q=[n];seen.add(n);while(q.length){const x=q.pop();comp.push(x);adj[x].forEach(y=>{if(!seen.has(y)){seen.add(y);q.push(y)}})}if(comp.length>=3)rings.push(comp.sort())});
 return{nodes:Object.entries(top).map(([id,score])=>({id,kind:'employee',score})).concat(Object.keys(by).map(id=>({id,kind:'customer',score:0}))),links,rings}}
const RI=n=>Math.floor(Math.random()*n);
const REASONS=[()=>['🕑','Unusual login at '+['1:35 AM','2:10 AM','11:40 PM'][RI(3)],20],()=>['💸','Large ₹'+(3+RI(37))+' Lakh transfer',30],()=>['💻','Unknown device',15],()=>['⭐','Accessed '+(4+RI(4))+' VIP accounts',20],()=>['👥','Accessed '+(40+RI(20))+' unusual customers',20],()=>['✏️','Repeated account modifications',25]];
const mk=(e,rs,t)=>{const sum=rs.reduce((a,r)=>a+r[2],0),top=rs.reduce((a,b)=>b[2]>a[2]?b:a);return{id:'A-'+(++st.seq),e,trig:top[1],score:Math.min(100,sum),st:'New',t,r:rs.map(x=>x.join('|')).join(';')}};
const HOOK=process.env.ALERT_WEBHOOK_URL||'';
function notify(text,alert){if(!HOOK)return Promise.resolve(false);return fetch(HOOK,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,content:text,alert:alert||null}),signal:AbortSignal.timeout(8000)}).then(r=>r.ok).catch(e=>{console.error('alert webhook failed:',e.message);return false})}
function store(a,user){if(st.prefs.auto&&a.score>=st.prefs.thr)a.st='Escalated';st.alerts.push(a);if(st.prefs.email&&a.score>=st.prefs.thr)notify('AI Sentinel alert #'+a.id+' - risk '+a.score+' - '+(st.emp[a.e]?st.emp[a.e][0]:a.e)+': '+a.trig,{id:a.id,employee:a.e,score:a.score,trigger:a.trig});const c=a.st=='Escalated'?openCase(a,user):null;log(user,'new alert','#'+a.id+' score '+a.score);return{alert:a,case:c}}
function simulate(){const e=Object.keys(EMPD)[RI(9)],pool=REASONS.slice().sort(()=>Math.random()-.5);let rs=[],sum=0;while(sum<30||rs.length<2){const r=pool.shift()();rs.push(r);sum+=r[2]}return store(mk(e,rs,now()),'system')}
function event(b,un){if(!st.emp[b.emp])return err(404,'Employee not found');if(!(b.login_hour>=0&&b.login_hour<24))return err(422,'Invalid login time');
 const z=(v,m,s)=>(v-m)/s,rs=[];if(Math.abs(z(b.login_hour,10,1.2))>3)rs.push(['🕑','Unusual login at '+clk(b.login_hour),20]);
 if(z(Math.log1p(b.amount),10.13,.35)>3)rs.push(['💸','Large '+(b.amount>=1e5?'₹'+Math.round(b.amount/1e5)+' Lakh':'₹'+Math.round(b.amount))+' transfer',30]);
 if(b.new_device)rs.push(['💻','Unknown device',15]);if(z(b.vip,.5,.7)>3)rs.push(['⭐','Accessed '+b.vip+' VIP accounts',20]);
 if(z(b.customers,22,4.3)>3)rs.push(['👥','Accessed '+b.customers+' unusual customers',20]);if(z(b.edits,2,1.4)>3)rs.push(['✏️','Repeated account modifications',25]);
 const cust=(b.customer||'').trim().toUpperCase();if(cust){if(!/^[A-Z0-9_-]{1,12}$/.test(cust))return err(422,'Customer ID: 1-12 letters/digits');
  const oth=Object.keys(st.touch).find(e=>e!=b.emp&&st.touch[e].includes(cust)&&st.alerts.some(a=>a.e==e&&a.st!='Reviewed'));if(oth)rs.push(['🔗','Shared payee with '+st.emp[oth][0],35]);(st.touch[b.emp]=st.touch[b.emp]||[]);if(!st.touch[b.emp].includes(cust))st.touch[b.emp].push(cust)}
 const sc=Math.min(100,rs.reduce((a,r)=>a+r[2],0));if(sc<30){log(un,'logged activity',b.emp+' score '+sc+' (no alert)');return R({alert:null,case:null,score:sc,message:'Within normal range (risk score '+sc+'). No alert created.'})}
 const r=store(mk(b.emp,rs,clk(b.login_hour)),un);return R({alert:r.alert,case:r.case,score:sc,message:'Alert #'+r.alert.id+' created'})}
function route(m,p,b,tok){
 if(p=='/login'){const u=USERS[b.username];if(!u||!H.check(u,b.password))return err(401,'Wrong username or password');const t=crypto.randomBytes(24).toString('hex');sessions[t]=b.username;log(b.username,'login');return R({token:t,user:{username:b.username,name:u.name,role:u.role}})}
 if(p=='/register/verify')return b.key==KEY?R({ok:true}):err(403,'Invalid access key');
 if(p=='/register'){if(b.key!=KEY)return err(403,'Invalid access key');if(!/^[A-Za-z0-9_.-]{3,30}$/.test(b.username||''))return err(422,'Username: 3-30 letters, digits, . _ -');if((b.password||'').length<6)return err(422,'Password must be at least 6 characters');if(USERS[b.username])return err(409,'Username already taken');
  USERS[b.username]={hash:H.hash(b.password),name:String(b.name||b.username).replace(/[<>&"]/g,'').slice(0,40),role:'analyst'};log(b.username,'registered');return R({ok:true})}
 if(p=='/health')return R({ok:true});
 const un=sessions[tok];if(!un)return err(401,'Login required');const u=USERS[un];
 if(p=='/logout'){delete sessions[tok];log(un,'logout');return R({ok:true})}
 if(p=='/bootstrap')return R({user:{username:un,name:u.name,role:u.role},emp:st.emp,alerts:st.alerts.slice().sort((x,y)=>y.score-x.score),cases:st.cases.map(cv),settings:st.prefs,graph:graph()});
 let x;if(x=p.match(/^\/alerts\/(.+)\/status$/)){const a=st.alerts.find(q=>q.id==x[1]);if(!a)return err(404,'Alert not found');if(!['New','Escalated','Reviewed'].includes(b.status))return err(422,'Invalid status');if(a.st=='New'){st.resp=st.resp||[];st.resp.push(Math.max(.1,(Date.now()-(a.ct||PAGE0))/6e4))}a.st=b.status;if(b.status=='Escalated')openCase(a,un);if(b.status=='Reviewed')st.cases.forEach(c=>{if(c.a==a.id&&c.open){c.open=0;cev(c,'closed','Closed because the alert was marked reviewed',un)}});log(un,b.status.toLowerCase(),'alert #'+a.id);return R(a)}
 if(p=='/employees'){const n=String(b.name||'').replace(/[<>&"]/g,'').trim(),d=String(b.dept||'').replace(/[<>&"]/g,'').trim();if(n.length<2||d.length<2)return err(422,'Name and department are required');let i=Object.keys(st.emp).length+1;while(st.emp['E'+i])i++;st.emp['E'+i]=[n,d];log(un,'added employee',n);return R({id:'E'+i,name:n,dept:d})}
 if(p=='/events')return addEvent(b,un);
 if(p=='/stats')return R(stats());
 {const d=dataRoute(m,p,b,un);if(d)return d}
 if(p=='/db/query')return dbQuery(b,un);
 if(p=='/email/test')return notify('AI Sentinel test notification from '+un).then(ok=>R({message:!HOOK?'No notification channel is configured. Set ALERT_WEBHOOK_URL on the server (Slack, Teams or Discord incoming webhook). Nothing was sent.':ok?'Test notification delivered to the webhook.':'Webhook call failed. Check ALERT_WEBHOOK_URL and the server log.'}));
 if(p=='/cases')return R(st.cases.map(cv));
 if(x=p.match(/^\/cases\/([^/]+)\/toggle$/)){const c=st.cases.find(q=>q.id==x[1]);if(!c)return err(404,'Case not found');const o=b.outcome;if(o!=null&&!OUT.includes(o))return err(422,'Invalid outcome');const a=st.alerts.find(q=>q.id==c.a);
  if(c.open){c.open=0;if(o!=null)c.outcome=o;if(a)a.st='Reviewed';cev(c,'closed',o?'Case closed — '+o:'Case closed',un)}else{c.open=1;c.outcome='';if(a)a.st='Escalated';cev(c,'reopened','Case reopened',un)}
  log(un,'toggled case',c.id);return R(st.cases.map(cv))}
 if(x=p.match(/^\/cases\/([^/]+)\/notes$/)){const c=st.cases.find(q=>q.id==x[1]);if(!c)return err(404,'Case not found');const tx=String(b.text||'').trim();if(!tx)return err(422,'Note cannot be empty');if(tx.length>1000)return err(422,'Invalid text: too long');cev(c,'note',tx,u.name);log(un,'case note',c.id);return R(cdet(c))}
 if(x=p.match(/^\/cases\/([^/]+)\/update$/)){const c=st.cases.find(q=>q.id==x[1]);if(!c)return err(404,'Case not found');
  if(b.assign!=null){if(!['me','none'].includes(b.assign))return err(422,'Invalid assignment');c.owner=b.assign=='me'?u.name:'';cev(c,'assigned',c.owner?'Assigned to '+c.owner:'Unassigned',un)}
  if(b.outcome!=null){if(!OUT.includes(b.outcome))return err(422,'Invalid outcome');c.outcome=b.outcome;cev(c,'outcome',b.outcome||'Outcome cleared',un)}
  log(un,'updated case',c.id);return R(cdet(c))}
 if(x=p.match(/^\/cases\/([^/]+)$/)){const c=st.cases.find(q=>q.id==x[1]);if(!c)return err(404,'Case not found');return R(cdet(c))}
 if(p=='/settings'){if(m=='PUT'){if(b.thr<40||b.thr>95)return err(422,'Threshold must be 40-95');st.prefs={email:!!b.email,auto:!!b.auto,thr:+b.thr,mask:!!b.mask};log(un,'saved settings','threshold '+b.thr)}return R(st.prefs)}
 if(p=='/graph')return R(graph());if(p=='/audit')return R(st.audit.slice(0,30));
 if(p=='/simulate'){hpNoise();return Math.random()<.3?hpRandom():R(simulate())}
 if(p=='/honeypot'){const h=st.hp,hit=h.log.filter(l=>l.dec),ms=h.log.filter(l=>l.ms);return R({auto:h.auto,decoys:HPD.map(d=>({...d,hits:hit.filter(l=>l.dec==d.id).length})),log:h.log.slice(0,40).map(l=>({...l,obj:l.dec?HPD.find(d=>d.id==l.dec).name:l.obj})),sess:h.sess.slice(0,12),stats:{events:h.n,hits:hit.length,isolated:h.sess.filter(q=>q.state=='Isolated').length,avg_ms:ms.length?Math.round(ms.reduce((a,l)=>a+l.ms,0)/ms.length):0}})}
 if(p=='/honeypot/trip')return hpHit({emp:b.emp,decoy:b.decoy,act:b.action,rows:b.rows,hour:b.hour,new_device:b.new_device},un);
 if(p=='/honeypot/policy'){st.hp.auto=!!b.auto;log(un,'honeypot policy','auto-isolate '+(st.hp.auto?'on':'off'));return R({auto:st.hp.auto})}
 if(x=p.match(/^\/honeypot\/sessions\/([^/]+)\/(isolate|release|terminate)$/)){const q=st.hp.sess.find(z=>z.id==x[1]);if(!q)return err(404,'Session not found');if(q.state=='Terminated'||q.state=='Released')return err(409,'Session is already '+q.state.toLowerCase());
  q.state={isolate:'Isolated',release:'Released',terminate:'Terminated'}[x[2]];st.hp.log.forEach(l=>{if(l.sess==q.id&&l.dec&&x[2]=='isolate')l.iso=1});log(un,x[2]+' session',q.id+' · '+st.emp[q.emp][0]);return R({ok:true})}
 if(p=='/reset'){if(u.role!='admin')return err(403,'Admin only');if(DEMO===false)return err(403,'Disabled in real-data mode: it would erase alerts, cases and the audit log');st=fresh();log(un,'reset demo data');return R({ok:true})}
 return err(404,'Not found')}
const PAGE0=Date.now();
/* ===== CSV-backed engine: live events, stats, import, gateway ===== */
const pick=a=>a[RI(a.length)],isoL=d=>{const p=n=>pad(n,2);return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':00'};
let NEV=0;
function upsert(e,an,un){let a=st.alerts.find(x=>x.e==e&&x.st!='Reviewed');const r=an.rs.map(x=>x.join('|')).join(';');
 if(a){const was=a.score;Object.assign(a,{score:an.score,trig:an.trig,r,t:an.t});if(st.prefs.auto&&a.st=='New'&&a.score>=st.prefs.thr){a.st='Escalated';openCase(a,un)}return{alert:a,case:null,fresh:false,was}}
 if(an.score<30)return{alert:null,case:null};const n={id:'A-'+(++st.seq),e,trig:an.trig,score:an.score,st:'New',t:an.t,r};n.ct=Date.now();const o=store(n,un);return{alert:o.alert,case:o.case,fresh:true}}
function addEvent(b,un){const e=b.emp;if(!st.emp[e])return err(404,'Employee not found');const d=b.timestamp?new Date(b.timestamp):new Date();if(isNaN(d))return err(422,'Invalid date & time');
 const row={EventID:'EVT'+pad(DB.activity_events.length+1,5),EmployeeID:eid(e),EventTimestamp:isoL(d),EventType:b.event_type||'Login',Application:b.application||'Browser',Device:b.device||'Office Desktop',IPAddress:b.ip||'192.168.1.1',Location:b.location||'Delhi',Severity:b.severity||'Low',EventStatus:b.status||'Success',Description:(b.event_type||'Event')+' event recorded; status '+String(b.status||'success').toLowerCase(),RequiresReview:['High','Critical'].includes(b.severity)||b.status=='Review Required'?'Yes':'No'};
 DB.activity_events.push(row);(EVS[e]=EVS[e]||[]).push(row);NEV++;const an=analyse(e),u=upsert(e,an,un);
 if(!u.alert){log(un,'logged activity',e+' score '+an.score+' (no alert)');return R({alert:null,case:null,score:an.score,message:'Within normal range (risk score '+an.score+'). No alert created.'})}
 log(un,u.fresh?'new alert':'alert updated','#'+u.alert.id+' score '+an.score);return R({alert:u.alert,case:u.case,score:an.score,message:'Alert #'+u.alert.id+(u.fresh?' created':' updated')})}
function tick(){const ks=Object.keys(st.emp),hot=st.alerts.filter(a=>a.st!='Reviewed').map(a=>a.e),bad=Math.random()<.4,e=bad&&hot.length&&Math.random()<.7?pick(hot):pick(ks);
 addEvent({emp:e,event_type:pick(bad?['Data Export','USB Connected','File Download','Permission Change','Failed Login']:['Login','File Access','Application Launch','Logout','Network Access']),application:pick(['Database','CRM','Spreadsheet','Email','Browser']),device:pick(['iPhone','Android Phone','MacBook','Windows Laptop','Office Desktop']),ip:'192.168.'+RI(255)+'.'+RI(255),location:pick(['Lucknow','Meerut','Noida','Mumbai','Delhi','Pune','Aligarh']),severity:pick(bad?['High','Critical','High','Medium']:['Info','Low','Low','Medium']),status:pick(bad?['Blocked','Review Required','Failed','Success']:['Success','Success','Failed'])},'system');
 if(RI(10)<4)hpNoise();if(RI(30)==0)hpRandom()}
if(DEMO!==false&&process.env.SIMULATE!=='0')setInterval(tick,6000).unref();
function evScore(x){return Math.min(100,{Info:0,Low:5,Medium:15,High:30,Critical:45}[x.Severity]+(EXF.includes(x.EventType)?15:x.EventType=='Permission Change'?10:0)+(off(hrOf(x.EventTimestamp))?15:0)+{Blocked:10,Failed:6,'Review Required':4,Success:0}[x.EventStatus])}
function bucket(n,ms,lab){const end=Date.now(),v=Array(n).fill(0),b=Array.from({length:n},()=>[]);DB.activity_events.forEach(x=>{const t=new Date(x.EventTimestamp.replace(' ','T')).getTime(),k=n-1-Math.floor((end-t)/ms);if(t<=end&&k>=0)b[k].push(evScore(x))});
 b.forEach((a,i)=>{a.sort((p,q)=>q-p);const t=a.slice(0,3);v[i]=t.length?Math.round(t.reduce((p,q)=>p+q,0)/t.length):0});return[v,lab]}
function stats(){const td=new Date().toDateString(),ft=Date.now(),H=36e5,D=24*H,fm=d=>new Date(ft-d).toLocaleTimeString([],{hour:'numeric'}),fd=d=>new Date(ft-d).toLocaleDateString([],{day:'numeric',month:'short'}),base={};
 Object.keys(EM).forEach(e=>{const ev=EVS[e]||[],tx=TXS[e]||[];if(!ev.length&&!tx.length)return;const l=ev.slice().sort((a,b)=>a.EventTimestamp<b.EventTimestamp?1:-1)[0],h=l?hrOf(l.EventTimestamp):12,amt=tx.reduce((a,x)=>a+ +x.Amount,0),fb=ev.filter(x=>['Failed','Blocked'].includes(x.EventStatus)).length,ex=ev.filter(x=>EXF.includes(x.EventType)).length,fg=tx.filter(x=>x.Flagged=='Yes').length;
  base[e]=[['Login hour',off(h)?92:h>=9&&h<=18?22:55,clk12(h)],['Txn value',Math.min(100,Math.round(amt/1500)),inr(amt)],['Events',Math.min(100,ev.length*30),String(ev.length)],['Failed/blocked',Math.min(100,fb*40),String(fb)],['Exports/USB',Math.min(100,ex*40),String(ex)],['Flagged txns',Math.min(100,fg*50),String(fg)]]});
 const rs=st.audit.length;return{mode:DEMO===false?'real':'demo',events:DB.activity_events.filter(x=>new Date(x.EventTimestamp.replace(' ','T')).toDateString()==td).length+NEV*0,resp:st.resp&&st.resp.length?Math.round(st.resp.reduce((a,b)=>a+b,0)/st.resp.length*10)/10:null,demo:false,
  timeline:{'24h':bucket(13,2*H,[fm(24*H),fm(16*H),fm(8*H),'Now']),'7d':bucket(7,D,[fd(6*D),fd(4*D),fd(2*D),'Today']),'30d':bucket(10,3*D,[fd(29*D),fd(20*D),fd(10*D),'Today'])},base,
  model:{l1:'Rules + behaviour scoring · '+Object.keys(EM).length+' employees',l2:'CSV data · '+DB.activity_events.length+' events · '+DB.transactions.length+' txns · live stream on'}}}
const TS=/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d/;
function VAL(t,id,r){const emp=(r.employeeid||'').trim();
 if(t=='employees'&&!/^EMP\d+$/.test(id))return 'EmployeeID "'+id.slice(0,20)+'" must look like EMP0001';
 if(t=='customers'&&!/^CUS\d+$/.test(id))return 'CustomerID "'+id.slice(0,20)+'" must look like CUS0001';
 if(t=='transactions'||t=='activity_events'){if(!/^EMP\d+$/.test(emp))return 'EmployeeID must look like EMP0001';
  if(t=='transactions'&&!(+r.amount>=0&&String(r.amount||'').trim()!==''))return 'Amount must be a number';
  if(t=='transactions'&&r.customerid&&!/^CUS\d+$/.test(r.customerid.trim()))return 'CustomerID must look like CUS0001';
  if(!TS.test((t=='transactions'?r.transactiondate:r.eventtimestamp)||''))return (t=='transactions'?'TransactionDate':'EventTimestamp')+' must look like 2026-10-28 14:30:00'}
 return''}
function dataRoute(m,p,b,un){let x;if(p=='/data/summary')return R(Object.fromEntries(Object.keys(DB).map(k=>[k,DB[k].length])));
 if(p=='/data/rescan'){idx();const o=scan();let n=0;Object.keys(o).forEach(e=>{if(o[e].score>=35){const u=upsert(e,o[e],un);if(u.fresh)n++}});log(un,'AI re-scan',n+' new alert(s)');return R({alerts:n})}
 if(x=p.match(/^\/data\/(\w+)$/)){const t=x[1];if(!DB[t])return err(404,'Unknown dataset');if(m!='POST')return R({rows:DB[t].slice(-50).reverse()});
  const k=IDK[t],er=[],IX=new Map(DB[t].map((q,i)=>[q[k],i]));let ld=0;(b.rows||[]).forEach((r,i)=>{const id=(r[k.toLowerCase()]||'').trim(),rn='Row '+(i+2)+': ',bd=VAL(t,id,r);if(!id){er.push(rn+k+' is required');return}if(bd){er.push(rn+bd);return}const row=Object.fromEntries(COLS[t].map(c=>[c,String(r[c.toLowerCase()]||'').trim()]));row[k]=id;const j=IX.has(id)?IX.get(id):-1;if(j>=0)Object.assign(DB[t][j],Object.fromEntries(Object.entries(row).filter(([c,v])=>v!=='')));else{IX.set(id,DB[t].length);DB[t].push(row)}ld++;
   if(t=='employees')st.emp[sid('E',id)]=[row.EmployeeName||id,row.Department||'—'];if(t=='transactions'&&row.Flagged=='Yes'){const e=sid('E',row.EmployeeID),c=sid('C',row.CustomerID);(st.touch[e]=st.touch[e]||[]);if(!st.touch[e].includes(c))st.touch[e].push(c)}});
  let n=0;if(ld){idx();const o=scan();Object.keys(o).forEach(e=>{const u=upsert(e,o[e],un);if(u.fresh)n++})}const unk=(t=='transactions'||t=='activity_events')?new Set((b.rows||[]).map(r=>(r.employeeid||'').trim()).filter(x=>/^EMP\d+$/.test(x)&&!st.emp[sid('E',x)])).size:0;log(un,'imported '+t,ld+' row(s)');return R({loaded:ld,errors:er,alerts:n,warning:unk?unk+' EmployeeID value(s) are not in the employees list, so those rows are stored but not scored. Import employees first.':''})}return null}
function fake(n){const F=['Arjun','Meera','Kabir','Isha','Vikram','Anaya','Rahul','Diya'],L=['Verma','Nair','Kapoor','Bose','Iyer','Khan'];return Array.from({length:Math.min(n,500)},(_,i)=>({record_id:'HP-'+pad(1000+i,5),holder:pick(F)+' '+pick(L),account:'XXXX'+pad(RI(9999),4),balance:'₹'+(RI(9e6)+1e5).toLocaleString('en-IN'),note:'honeypot record'}))}
function dbQuery(b,un){const e=b.emp;if(!st.emp[e])return err(404,'Employee not found');const n=Math.max(1,Math.min(500,+b.limit||10)),h=st.hp,dec=HPD.find(d=>d.name==b.table);
 if(dec)return hpHit({emp:e,decoy:dec.id,act:b.action,rows:n,hour:new Date().getHours()+new Date().getMinutes()/60,new_device:!!b.new_device},un).json().then(j=>R({served:'honeypot',rows:fake(n),message:'Decoy table touched — alert #'+j.alert.id+' raised, '+n+' row(s) served from the honeypot database'+(j.isolated?' · session isolated':'')}));
 const s=h.sess.find(z=>z.emp==e&&z.state=='Isolated');if(s){s.sbq++;h.log.unshift({id:'L-'+(++h.n),ts:now(),emp:e,src:'Sandbox',dec:null,obj:b.table,act:b.action,rows:n,score:60,alert:null,iso:1,sess:s.id,ms:0});return R({served:'honeypot',rows:fake(n),message:'Session '+s.id+' is isolated — '+n+' row(s) served from the honeypot database (query recorded)'})}
 const rows=b.table=='customers'?DB.customers.slice(0,n).map(c=>({CustomerID:c.CustomerID,CustomerName:c.CustomerName,City:c.City,Segment:c.CustomerSegment,Status:c.CustomerStatus,LifetimeValue:c.LifetimeValue})):DB.transactions.slice(0,n).map(t=>({TransactionID:t.TransactionID,CustomerID:t.CustomerID,Amount:t.Amount,Type:t.TransactionType,Status:t.TransactionStatus,RiskScore:t.RiskScore}));
 h.log.unshift({id:'L-'+(++h.n),ts:now(),emp:e,src:'App gateway',dec:null,obj:b.table,act:b.action,rows:n,score:3+RI(10)+(b.new_device?15:0),alert:null,iso:0,sess:'',ms:0});return R({served:'production',rows,message:'Served '+rows.length+' row(s) from the production database'})}

return{H,route:(m,p,body,t)=>route(m,p,body,t),get st(){return st},set st(v){st=v},DB,USERS,sessions,IDK,COLS};};
