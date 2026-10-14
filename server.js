const express = require('express');
const cookieParser = require('cookie-parser');
const { createServer } = require('http');
const WebSocket = require('ws');
const net = require('net');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(cookieParser());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .single();
  if (error || !data) return res.status(401).json({ error: 'bad creds' });
  const ok = await bcrypt.compare(password, data.password_hash);
  if (!ok) return res.status(401).json({ error: 'bad creds' });
  res.cookie('auth', 'ok', { httpOnly: true, sameSite: 'none', secure: true });
  res.json({ ok: true, host: data.windows_host, port: data.windows_port });
});

const server = createServer(app);
const wss = new WebSocket.Server({ server, path: '/vnc' });

wss.on('connection', async (ws, req) => {
  const cookies = req.headers.cookie || '';
  if (!cookies.includes('auth=ok')) return ws.close(1008, 'unauthorized');

  const { data } = await supabase.from('users').select('*').eq('username', 'mar').single();
  if (!data) return ws.close(1011, 'no target');

  const target = net.connect(data.windows_port, data.windows_host);
  ws.on('message', d => target.write(d));
  target.on('data', d => ws.send(d));
  target.on('error', () => ws.close(1011, 'target error'));
  target.on('close', () => ws.close(1000, 'target closed'));
  ws.on('close', () => target.end());
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log('listening', PORT));
