const fs=require('fs'),path=require('path'),{createStore}=require('../storage.js');
async function reset(){
 if(process.env.DATABASE_URL){
  const db=createStore();
  try{await db.transaction(async client=>{for(const t of['ds_activity_events','ds_transactions','ds_customers','ds_employees','sv_history','sv_records','sessions','users','kv'])await db.tx.exec(`DROP TABLE IF EXISTS ${t}`,client)})}
  finally{await db.close()}
  console.log('Deleted all AI Sentinel tables from the configured PostgreSQL database.');
 }else{
  const f=process.env.DB_FILE||path.join(process.env.DATA_DIR||path.join(__dirname,'..','data'),'sentinel.db');
  for(const s of['','-wal','-shm'])fs.rmSync(f+s,{force:true});
  console.log('Deleted '+f+' (ALL data, users and alerts).');
 }
 console.log(process.env.SEED_DEMO==='0'?'Next start is EMPTY (real-data mode).':'Next start reloads the synthetic demo CSVs from seed/ (set SEED_DEMO=0 for an empty real-data start).');
}
reset().catch(e=>{console.error('Database reset failed:',e.message);process.exitCode=1});
