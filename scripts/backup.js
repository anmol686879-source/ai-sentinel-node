/* Consistent online backup of the SQLite database: node scripts/backup.js [output-dir] */
if(process.env.DATABASE_URL){console.error('This script backs up local SQLite databases only. Use Neon backups or pg_dump for PostgreSQL.');process.exit(1)}
const {DatabaseSync}=require('node:sqlite'),path=require('path'),fs=require('fs');
const src=process.env.DB_FILE||path.join(process.env.DATA_DIR||path.join(__dirname,'..','data'),'sentinel.db');
const dir=process.argv[2]||path.join(path.dirname(src),'backups');fs.mkdirSync(dir,{recursive:true});
if(!fs.existsSync(src)){console.error('No database at '+src);process.exit(1)}
const out=path.join(dir,'sentinel-'+new Date().toISOString().replace(/[:.]/g,'-')+'.db'),db=new DatabaseSync(src);
db.exec(`VACUUM INTO '${out.replace(/'/g,"''")}'`);db.close();
const keep=+process.env.KEEP_BACKUPS||14,all=fs.readdirSync(dir).filter(f=>/^sentinel-.*\.db$/.test(f)).sort();
all.slice(0,Math.max(0,all.length-keep)).forEach(f=>fs.unlinkSync(path.join(dir,f)));
console.log('Backup written: '+out+'  (keeping the newest '+keep+')');
