const express=require('express');
const path=require('path');
const crypto=require('crypto');
const {Pool}=require('pg');

const app=express();
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false,checkServerIdentity:()=>undefined}});

async function initDB(){
  await pool.query(`CREATE TABLE IF NOT EXISTS practitioners(
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    practice_name TEXT,
    splose_api_key TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS phone TEXT`).catch(()=>{});
  await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS email TEXT`).catch(()=>{});
  await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS last_appt DATE`).catch(()=>{});
  await pool.query(`CREATE TABLE IF NOT EXISTS clients(
    id TEXT PRIMARY KEY,
    practitioner_id TEXT,
    name TEXT,
    splose_id TEXT,
    last_appt DATE,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS chat_tokens(
    id SERIAL PRIMARY KEY,
    client_id TEXT,
    practitioner_id TEXT,
    token TEXT UNIQUE,
    pin_hash TEXT,
    last_read TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS messages(
    id SERIAL PRIMARY KEY,
    client_id TEXT,
    practitioner_id TEXT,
    from_type TEXT,
    body TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS tasks(
    id TEXT PRIMARY KEY,
    client_id TEXT,
    practitioner_id TEXT,
    note TEXT,
    done BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS note TEXT`).catch(()=>{});
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS done BOOLEAN DEFAULT FALSE`).catch(()=>{});
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`).catch(()=>{});
  console.log('DB ready');
}

function hashPassword(pw){return crypto.createHash('sha256').update(pw+'held2026').digest('hex');}
function hashPin(pin){return crypto.createHash('sha256').update(pin+'heldpin2026').digest('hex');}
function makeToken(){return crypto.randomBytes(32).toString('hex');}

// Health check
app.get('/api/health',function(req,res){res.json({ok:true,name:'Tracks'});});


// Signup
app.post('/api/auth/signup',async function(req,res){
  const{name,practice,email,password}=req.body;
  if(!name||!practice||!email||!password)return res.status(400).json({error:'All fields required'});
  if(password.length<8)return res.status(400).json({error:'Password must be at least 8 characters'});
  try{
    const exists=await pool.query('SELECT id FROM practitioners WHERE email=$1',[email.toLowerCase()]);
    if(exists.rows.length)return res.status(400).json({error:'An account with this email already exists'});
    const id='prac_'+require('crypto').randomBytes(8).toString('hex');
    const hash=hashPassword(password);
    await pool.query('INSERT INTO practitioners(id,name,email,password_hash,practice_name) VALUES($1,$2,$3,$4,$5)',[id,name,email.toLowerCase(),hash,practice]);
    res.json({ok:true,id,name,email:email.toLowerCase(),practice});
  }catch(err){console.error('Signup error:',err.message);res.status(500).json({error:'Something went wrong. Please try again.'});}
});

// Login
app.post('/api/auth/login',async function(req,res){
  const{email,password}=req.body;
  if(!email||!password)return res.status(400).json({error:'Please fill in all fields'});
  try{
    const r=await pool.query('SELECT id,name,email,password_hash,practice_name FROM practitioners WHERE email=$1',[email.toLowerCase()]);
    if(!r.rows.length)return res.status(401).json({error:'No account found with this email'});
    const p=r.rows[0];
    if(p.password_hash!==hashPassword(password))return res.status(401).json({error:'Incorrect password'});
    res.json({ok:true,id:p.id,name:p.name,email:p.email,practice:p.practice_name});
  }catch(err){console.error('Login error:',err.message);res.status(500).json({error:'Something went wrong. Please try again.'});}
});


// Get clients for a practitioner
app.get('/api/clients',async function(req,res){
  const practitionerId=req.query.practitionerId;
  if(!practitionerId)return res.status(400).json({error:'practitionerId required'});
  try{
    const r=await pool.query('SELECT * FROM clients WHERE practitioner_id=$1 ORDER BY created_at DESC',[practitionerId]);
    res.json({clients:r.rows});
  }catch(err){res.status(500).json({error:err.message});}
});

// Add a client manually
app.post('/api/clients',async function(req,res){
  const{practitionerId,name,phone,email,lastAppt}=req.body;
  if(!practitionerId||!name)return res.status(400).json({error:'practitionerId and name required'});
  try{
    const id='client_'+require('crypto').randomBytes(8).toString('hex');
    await pool.query(
      'INSERT INTO clients(id,practitioner_id,name,phone,email,last_appt) VALUES($1,$2,$3,$4,$5,$6)',
      [id,practitionerId,name,phone||null,email||null,lastAppt||null]
    );
    res.json({ok:true,id});
  }catch(err){res.status(500).json({error:err.message});}
});

// Update a client
app.put('/api/clients/:id',async function(req,res){
  const{name,phone,email,lastAppt,status}=req.body;
  try{
    await pool.query(
      'UPDATE clients SET name=$1,phone=$2,email=$3,last_appt=$4,status=$5 WHERE id=$6',
      [name,phone||null,email||null,lastAppt||null,status||'active',req.params.id]
    );
    res.json({ok:true});
  }catch(err){res.status(500).json({error:err.message});}
});

// Delete a client
app.delete('/api/clients/:id',async function(req,res){
  try{
    await pool.query('DELETE FROM clients WHERE id=$1',[req.params.id]);
    res.json({ok:true});
  }catch(err){res.status(500).json({error:err.message});}
});


// Get tasks for a client
app.get('/api/tasks',async function(req,res){
  const clientId=req.query.clientId;
  if(!clientId)return res.status(400).json({error:'clientId required'});
  try{
    const r=await pool.query('SELECT * FROM tasks WHERE client_id=$1 ORDER BY created_at ASC',[clientId]);
    res.json({tasks:r.rows});
  }catch(err){res.status(500).json({error:err.message});}
});

// Add a task
app.post('/api/tasks',async function(req,res){
  const{clientId,note,practitionerId}=req.body;
  if(!clientId||!note)return res.status(400).json({error:'clientId and note required'});
  try{
    const id='task_'+require('crypto').randomBytes(8).toString('hex');
    await pool.query(
      'INSERT INTO tasks(id,client_id,practitioner_id,note,done) VALUES($1,$2,$3,$4,$5)',
      [id,clientId,practitionerId||null,note,false]
    );
    res.json({ok:true,id});
  }catch(err){console.error('Tasks GET error:',err.message);res.status(500).json({error:err.message});}
});

// Update a task
app.put('/api/tasks/:id',async function(req,res){
  const{done,note}=req.body;
  try{
    if(done!==undefined)await pool.query('UPDATE tasks SET done=$1 WHERE id=$2',[done,req.params.id]);
    if(note!==undefined)await pool.query('UPDATE tasks SET note=$1 WHERE id=$2',[note,req.params.id]);
    res.json({ok:true});
  }catch(err){res.status(500).json({error:err.message});}
});

// Delete a task
app.delete('/api/tasks/:id',async function(req,res){
  try{
    await pool.query('DELETE FROM tasks WHERE id=$1',[req.params.id]);
    res.json({ok:true});
  }catch(err){res.status(500).json({error:err.message});}
});

app.listen(process.env.PORT||3000,async function(){
  await initDB();
  console.log('Held running on port '+(process.env.PORT||3000));
});
