const express=require('express');
const path=require('path');
const crypto=require('crypto');
const {Pool}=require('pg');

const app=express();
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}});

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
    id SERIAL PRIMARY KEY,
    client_id TEXT,
    practitioner_id TEXT,
    data TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  console.log('DB ready');
}

function hashPassword(pw){return crypto.createHash('sha256').update(pw+'held2026').digest('hex');}
function hashPin(pin){return crypto.createHash('sha256').update(pin+'heldpin2026').digest('hex');}
function makeToken(){return crypto.randomBytes(32).toString('hex');}

// Health check
app.get('/api/health',function(req,res){res.json({ok:true,name:'Held'});});

app.listen(process.env.PORT||3000,async function(){
  await initDB();
  console.log('Held running on port '+(process.env.PORT||3000));
});
