const express = require('express');
const { execFile } = require('child_process');
const path = require('path');
const app = express();

app.get('/ping', (req, res) => {
  const host = String(req.query.host || '');
  if (!/^[0-9.]+$/.test(host)) return res.status(400).end();
  execFile('ping', ['-c', '1', host], (err, out) => res.send(out));
});

app.get('/user', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
  res.json(rows);
});

app.get('/file', (req, res) => {
  res.sendFile(path.basename(req.params.name), { root: '/srv/files' });
});

app.get('/go', (req, res) => {
  res.redirect('/dashboard');
});
