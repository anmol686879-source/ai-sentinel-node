const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),os=require('os'),path=require('path');
const {placeholders,sqliteStore}=require('../storage.js');

test('PostgreSQL placeholders are numbered in query order',()=>{
 assert.equal(placeholders('SELECT * FROM users WHERE username=? AND role=?'),'SELECT * FROM users WHERE username=$1 AND role=$2');
});

test('SQLite storage adapter commits and rolls back transactions',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sent-storage-')),db=sqliteStore(path.join(dir,'test.db'));
 try{
  await db.exec('CREATE TABLE records(id TEXT PRIMARY KEY,value TEXT)');
  await db.transaction(async client=>db.tx.run('INSERT INTO records VALUES(?,?)',['a','kept'],client));
  assert.equal((await db.get('SELECT value FROM records WHERE id=?',['a'])).value,'kept');
  await assert.rejects(db.transaction(async client=>{await db.tx.run('INSERT INTO records VALUES(?,?)',['b','rolled back'],client);throw new Error('test rollback')}));
  assert.equal(await db.get('SELECT value FROM records WHERE id=?',['b']),undefined);
 }finally{await db.close();fs.rmSync(dir,{recursive:true,force:true})}
});
