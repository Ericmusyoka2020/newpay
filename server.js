// index.js  (or server.js — main entry file)

const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');

const app = express();

app.use(express.json());

// Minimal CORS – allow all for dev; tighten in production
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Supabase setup (use environment variables!)
const supabaseUrl  = process.env.SUPABASE_URL  || 'https://otbkvllvqgmfkepdchho.supabase.co';
const supabaseKey  = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im90Ymt2bGx2cWdtZmtlcGRjaGhvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njg0ODE1ODcsImV4cCI6MjA4NDA1NzU4N30.EXjC1ZWzctQB5Udr5jIa7m7uGBbBXzo9XrXYAY2I2h4';

const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// ────────────────────────────────────────────────
//  Helper
// ────────────────────────────────────────────────
function respond(res, status, data) {
  res.status(status).json(data);
}

// ────────────────────────────────────────────────
//  Routes
// ────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || password.length < 4) {
      return respond(res, 400, { success: false, error: 'Username and password (min 4 chars) required' });
    }

    const hash = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert([{ username, password_hash: hash, created_at: new Date().toISOString() }])
      .select()
      .single();

    if (error) {
      return respond(res, 400, { success: false, error: 'Username already exists' });
    }

    return respond(res, 201, { success: true, message: 'Account created successfully' });
  } catch (err) {
    console.error('Signup error:', err.message);
    return respond(res, 500, { success: false, error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return respond(res, 400, { success: false, error: 'Username and password required' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !user) {
      return respond(res, 401, { success: false, error: 'Account not found' });
    }

    const oneWeekAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
    if (new Date(user.created_at) < new Date(oneWeekAgo)) {
      await supabase.from('users').delete().eq('id', user.id);
      return respond(res, 401, { success: false, error: 'Account expired' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return respond(res, 401, { success: false, error: 'Account expired create new one please' });
    }

    return respond(res, 200, {
      success: true,
      message: 'Login successful',
      userId: user.id,
      username: user.username
    });
  } catch (err) {
    console.error('Login error:', err.message);
    return respond(res, 500, { success: false, error: 'Server error' });
  }
});

app.get('/api/status', async (req, res) => {
  try {
    const { count } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });

    return respond(res, 200, { status: 'ok', userCount: count || 0 });
  } catch {
    return respond(res, 200, { status: 'ok' });
  }
});

// Health check (useful for Render / platforms)
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// ────────────────────────────────────────────────
//  Vercel vs Traditional server detection
// ────────────────────────────────────────────────
const isVercel = !!process.env.VERCEL;

if (isVercel) {
  // Vercel serverless – just export the Express app
  module.exports = app;
} else {
  // Local / Render / Railway / Fly.io etc.
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Running on port ${PORT}`);
  });
}
