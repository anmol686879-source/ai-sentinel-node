/* Real-data mode: empty start, strict import validation, guarded reset, webhook delivery. */
const {test,before,after}=require('node:test'),assert=require('node:assert'),{spawn}=require('child_process'),http=require('http'),path=require('path'),os=require('os'),fs=require('fs');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sent-real-')),PORT=3700+Math.floor(Math.random()*200),B=`http://localhost:${PORT}/api`;
const PW='Real#Pass2026',hooks=[];let srv,hookSrv,tok;
const call=(p,m='GET',b,t=tok)=>fetch(B+p,{method:m,headers:{'Content-Type':'application/json',...(t?{Authorization:'Bearer '+t}:{})},body:b?JSON.stringify(b):undefined}).then(async r=>({s:r.status,j:await r.json().catch(()=>null)}));
before(async()=>{
 hookSrv=http.createServer((q,r)=>{let d='';q.on('data',c=>d+=c);q.on('end',()=>{hooks.push(JSON.parse(d));r.end('ok')})});await new Promise(r=>hookSrv.listen(0,r));
 srv=spawn('node',['--no-warnings','server.js'],{cwd:path.join(__dirname,'..'),env:{...process.env,PORT,DATA_DIR:dir,SEED_DEMO:'0',NODE_ENV:'production',ADMIN_PASSWORD:PW,ADMIN_KEY:'k-real-1',TRUST_PROXY:'',ALERT_WEBHOOK_URL:'http://localhost:'+hookSrv.address().port+'/h'},stdio:'ignore'});
 for(let i=0;i<40;i++){try{if((await fetch(B+'/health')).ok)break}catch(e){}await new Promise(r=>setTimeout(r,250))}
 tok=(await call('/login','POST',{username:'admin',password:PW},null)).j.token});
after(async()=>{srv.kill('SIGTERM');hookSrv.close();await new Promise(r=>setTimeout(r,300));fs.rmSync(dir,{recursive:true,force:true})});
test('health reports real mode and no default credentials',async()=>{const r=await call('/health','GET',null,null);assert.equal(r.j.mode,'real');assert.equal(r.j.defaults,false)});
test('starts completely empty (no synthetic records, no demo alerts)',async()=>{const s=(await call('/data/summary')).j;assert.deepEqual(s,{employees:0,customers:0,transactions:0,activity_events:0});const b=(await call('/bootstrap')).j;assert.equal(b.alerts.length,0);assert.equal((await call('/sv/mv/records')).j.rows.length,0)});
test('demo reset buttons are disabled so real data cannot be wiped',async()=>{assert.equal((await call('/reset','POST',{})).s,403);assert.equal((await call('/sv/mv/reset','POST',{})).s,403)});
test('import rejects malformed IDs, dates and amounts with row messages',async()=>{
 let r=(await call('/data/employees','POST',{rows:[{employeeid:'EMP0001',employeename:'A',department:'Ops',securityrisk:'High',alertscount:'9',attendancestatus:'On Leave'},{employeeid:'HR-9'},{employeename:'x'}]})).j;assert.equal(r.loaded,1);assert.equal(r.errors.length,2);
 r=(await call('/data/activity_events','POST',{rows:[{eventid:'E1',employeeid:'EMP0001',eventtimestamp:'nope'},{eventid:'E2',employeeid:'EMP0001',eventtimestamp:'2026-10-27 02:10:00',eventtype:'Data Export',severity:'Critical',eventstatus:'Success'},{eventid:'E3',employeeid:'EMP0042',eventtimestamp:'2026-10-27 10:00:00'}]})).j;assert.equal(r.loaded,2);assert.equal(r.errors.length,1);assert.match(r.warning,/not in the employees list/);
 r=(await call('/data/transactions','POST',{rows:[{transactionid:'T1',employeeid:'EMP0001',customerid:'CUS0001',transactiondate:'2026-10-27 03:00:00',amount:'abc'}]})).j;assert.equal(r.loaded,0)});
test('imported data raises an alert, numbered from A-1001',async()=>{await call('/data/transactions','POST',{rows:[{transactionid:'T2',employeeid:'EMP0001',customerid:'CUS0001',transactiondate:'2026-10-27 03:00:00',amount:'70000',riskscore:'90',flagged:'Yes',transactiontype:'Refund'}]});
 const a=(await call('/bootstrap')).j.alerts;assert.ok(a.length>=1);assert.match(a[0].id,/^A-10\d\d$/)});
test('a NEW high-risk alert is delivered to the webhook',async()=>{await call('/settings','PUT',{email:true,auto:false,thr:50,mask:false});
 await call('/data/employees','POST',{rows:[{employeeid:'EMP0002',employeename:'B',department:'IT'}]});
 await call('/data/activity_events','POST',{rows:[{eventid:'E10',employeeid:'EMP0002',eventtimestamp:'2026-10-27 01:00:00',eventtype:'USB Connected',severity:'Critical',eventstatus:'Blocked',device:'Android Phone',application:'Database'},{eventid:'E11',employeeid:'EMP0002',eventtimestamp:'2026-10-27 01:30:00',eventtype:'Failed Login',severity:'High',eventstatus:'Failed'}]});
 for(let i=0;i<20&&!hooks.length;i++)await new Promise(r=>setTimeout(r,150));
 assert.ok(hooks.length>=1);assert.match(hooks[0].text,/AI Sentinel alert/);assert.ok(hooks[0].alert.score>=50)});
test('test-notification button reaches the webhook',async()=>{const n=hooks.length;const r=await call('/email/test','POST',{});assert.match(r.j.message,/delivered/);assert.equal(hooks.length,n+1)});
