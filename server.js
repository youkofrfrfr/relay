const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { createServer } = require('http');
const WebSocket = require('ws');
const net = require('net');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const SUPA_URL = process.env.SUPABASE_URL;
const SUPA_KEY = process.env.SUPABASE_SECRET_KEY;

if (!SUPA_URL) { console.error('missing SUPABASE_URL'); process.exit(1); }
if (!SUPA_KEY) { console.error('missing SUPABASE_SECRET_KEY'); process.exit(1); }

console.log('SUPABASE_URL set:', SUPA_URL.slice(0, 40));
console.log('SUPABASE_SECRET_KEY set, prefix:', SUPA_KEY.slice(0, 12));

const supabase = createClient(SUPA_URL, SUPA_KEY);

app.get('/', (req, res) => {
  res.json({ status: 'relay up', time: new Date().toISOString() });
});

app.get('/login', (req, res) => {
  res.json({ ok: true, note: 'GET works. POST with JSON body to log in.' });
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    console.log('LOGIN body:', JSON.stringify(req.body));
    console.log('LOGIN pw length:', password ? password.length : 0);

    if (!username || !password) {
      return res.status(400).json({ error: 'missing fields' });
    }

    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !data) {
      console.log('LOGIN user lookup failed:', error && error.message);
      return res.status(401).json({ error: 'bad creds' });
    }

    console.log('LOGIN row id:', data.id, 'hash prefix:', data.password_hash.slice(0, 12));

    const ok = await bcrypt.compare(password, data.password_hash);
    console.log('LOGIN bcrypt result:', ok);

    if (!ok) return res.status(401).json({ error: 'bad creds' });

    res.cookie('auth', 'ok', { httpOnly: true, sameSite: 'none', secure: true });
    res.json({ ok: true, host: data.windows_host, port: data.windows_port });
  } catch (err) {
    console.log('LOGIN error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const server = createServer(app);
const wss = new WebSocket.Server({ server, path: '/vnc' });

wss.on('connection', async (ws, req) => {
  const cookies = req.headers.cookie || '';
  if (!cookies.includes('auth=ok')) {
    ws.close(1008, 'unauthorized');
    return;
  }

  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', 'mar')
    .single();

  if (error || !data) {
    ws.close(1011, 'no target');
    return;
  }

  const target = net.connect(data.windows_port, data.windows_host);

  ws.on('message', (d) => target.write(d));
  target.on('data', (d) => ws.send(d));
  target.on('error', () => ws.close(1011, 'target error'));
  target.on('close', () => ws.close(1000, 'target closed'));
  ws.on('close', () => target.end());
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('listening on port', PORT);
});
