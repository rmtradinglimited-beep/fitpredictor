const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const Datastore = require('nedb-promises');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fitpredictor_secret_2026';

// Ensure data directory exists
if (!fs.existsSync('./data')) fs.mkdirSync('./data');

const db = Datastore.create({ filename: './data/users.db', autoload: true });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/register', async (req, res) => {
  const { name, username, email, password } = req.body;
  if (!name || !username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const existing = await db.findOne({ $or: [{ email: email.toLowerCase() }, { username }] });
  if (existing)
    return res.status(400).json({ error: 'Username or email already taken' });
  const hash = await bcrypt.hash(password, 10);
  const user = await db.insert({ name, username, email: email.toLowerCase(), password: hash, createdAt: new Date() });
  const token = jwt.sign({ id: user._id, username: user.username, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({ success: true, user: { name: user.name, username: user.username, email: user.email } });
});

app.post('/api/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password)
    return res.status(400).json({ error: 'All fields required' });
  const user = await db.findOne({ $or: [{ email: identifier.toLowerCase() }, { username: identifier }] });
  if (!user) return res.status(400).json({ error: 'Invalid username/email or password' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid username/email or password' });
  const token = jwt.sign({ id: user._id, username: user.username, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({ success: true, user: { name: user.name, username: user.username, email: user.email } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(PORT, () => console.log('FitPredictor running on port ' + PORT));
