const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const app = express();

app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.get('/user', async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
  res.json(rows);
});

app.get('/file', (req, res) => {
  res.sendFile('/srv/files/' + req.params.name);
});

app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

app.get('/calc', (req, res) => {
  res.send(String(eval(req.query.expr)));
});

const client = https.request({ host: 'api.internal', rejectUnauthorized: false });
