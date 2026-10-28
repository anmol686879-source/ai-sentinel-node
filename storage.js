const path=require('path');

function placeholders(sql){let i=0;return sql.replace(/\?/g,()=>'$'+(++i))}

function sqliteStore(file){
 const {DatabaseSync}=require('node:sqlite'),db=new DatabaseSync(file);
 return{
  kind:'sqlite',
  location:file,
  exec:async(sql,client=db)=>client.exec(sql),
  all:async(sql,params=[],client=db)=>client.prepare(sql).all(...params),
  get:async(sql,params=[],client=db)=>client.prepare(sql).get(...params),
  run:async(sql,params=[],client=db)=>client.prepare(sql).run(...params),
  transaction:async work=>{db.exec('BEGIN');try{const result=await work(db);db.exec('COMMIT');return result}catch(e){try{db.exec('ROLLBACK')}catch(_){}throw e}},
  tx:{
   exec:async(sql,client)=>client.exec(sql),
   all:async(sql,params=[],client)=>client.prepare(sql).all(...params),
   get:async(sql,params=[],client)=>client.prepare(sql).get(...params),
   run:async(sql,params=[],client)=>client.prepare(sql).run(...params)
  },
  close:async()=>db.close(),
  check:async()=>{db.prepare('SELECT 1').get();return true}
 };
}

function postgresStore(connectionString){
 const {Pool}=require('pg'),pool=new Pool({connectionString,max:5,idleTimeoutMillis:30000,connectionTimeoutMillis:10000});
 pool.on('error',e=>console.error('Neon PostgreSQL pool error:',e.message));
 const query=(sql,params=[],client=pool)=>client.query(placeholders(sql),params);
 const tx={
  exec:async(sql,client)=>client.query(sql),
  all:async(sql,params=[],client)=>(await query(sql,params,client)).rows,
  get:async(sql,params=[],client)=>(await query(sql,params,client)).rows[0],
  run:async(sql,params=[],client)=>query(sql,params,client)
 };
 return{
  kind:'postgres',
  location:'Neon PostgreSQL',
  exec:async sql=>pool.query(sql),
  all:async(sql,params=[])=>tx.all(sql,params,pool),
  get:async(sql,params=[])=>tx.get(sql,params,pool),
  run:async(sql,params=[])=>tx.run(sql,params,pool),
  transaction:async work=>{const client=await pool.connect();try{await client.query('BEGIN');const result=await work(client);await client.query('COMMIT');return result}catch(e){try{await client.query('ROLLBACK')}catch(_){}throw e}finally{client.release()}},
  tx,
  close:async()=>pool.end(),
  check:async()=>{await pool.query('SELECT 1');return true}
 };
}

function createStore(){
 const url=process.env.DATABASE_URL;
 if(url)return postgresStore(url);
 const file=process.env.DB_FILE||path.join(process.env.DATA_DIR||path.join(__dirname,'data'),'sentinel.db');
 return sqliteStore(file);
}

module.exports={createStore,placeholders,sqliteStore};
