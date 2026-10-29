'use strict';

const express = require('express');
const crypto = require('node:crypto');

const app = express();
app.disable('x-powered-by');

const PORT = Number(process.env.PORT) || 10000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const META_APP_SECRET = process.env.META_APP_SECRET;

// Fail closed if required secrets are missing.
if (!VERIFY_TOKEN || !META_APP_SECRET) {
  console.error('Missing VERIFY_TOKEN or META_APP_SECRET');
  process.exit(1);
}

// Meta verifies webhook subscriptions via GET.
app.get('/', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN && typeof challenge === 'string') {
    console.info('Webhook subscription verified');
    return res.status(200).type('text/plain').send(challenge);
  }
  return res.sendStatus(403);
});

// Keep the exact bytes from Meta: do not put express.json() before this handler.
app.post('/', express.raw({ type: 'application/json', limit: '256kb' }), (req, res) => {
  const signature = req.get('x-hub-signature-256') || '';
  if (!Buffer.isBuffer(req.body) || !/^sha256=[a-f0-9]{64}$/i.test(signature)) {
    console.warn('Rejected webhook: missing or malformed signature');
    return res.sendStatus(403);
  }

  const received = Buffer.from(signature.slice(7), 'hex');
  const expected = crypto.createHmac('sha256', META_APP_SECRET).update(req.body).digest();

  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
    console.warn('Rejected webhook: invalid signature');
    return res.sendStatus(403);
  }

  let event;
  try {
    event = JSON.parse(req.body.toString('utf8'));
  } catch {
    return res.sendStatus(400);
  }

  if (event.object !== 'whatsapp_business_account' || !Array.isArray(event.entry)) {
    return res.sendStatus(400);
  }

  // Log metadata only; never log names, phone numbers, or message bodies.
  const changes = event.entry.flatMap(entry => Array.isArray(entry.changes) ? entry.changes : []);
  const messageCount = changes.reduce((n, change) => n + (Array.isArray(change.value?.messages) ? change.value.messages.length : 0), 0);
  const statusCount = changes.reduce((n, change) => n + (Array.isArray(change.value?.statuses) ? change.value.statuses.length : 0), 0);
  console.info(`Authenticated WhatsApp webhook: changes=${changes.length} messages=${messageCount} statuses=${statusCount}`);

  // Acknowledge quickly; process business logic asynchronously when added later.
  return res.sendStatus(200);
});

app.get('/health', (_req, res) => res.status(200).send('ok'));

app.use((err, _req, res, _next) => {
  console.error('Webhook request error:', err.type || 'unexpected');
  return res.sendStatus(err.status === 413 ? 413 : 400);
});

app.listen(PORT, '0.0.0.0', () => {
  console.info(`Solutions WhatsApp webhook listening on port ${PORT}`);
});
