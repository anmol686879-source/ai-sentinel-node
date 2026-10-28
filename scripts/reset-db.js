const fs=require('fs'),path=require('path');
const f=process.env.DB_FILE||path.join(process.env.DATA_DIR||path.join(__dirname,'..','data'),'sentinel.db');
['','-wal','-shm'].forEach(s=>fs.rmSync(f+s,{force:true}));
console.log('Deleted '+f+' (ALL data, users and alerts).');
console.log(process.env.SEED_DEMO==='0'?'Next start is EMPTY (real-data mode).':'Next start reloads the synthetic demo CSVs from seed/ (set SEED_DEMO=0 for an empty real-data start).');
