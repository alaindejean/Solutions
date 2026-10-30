
'use strict';

// Solutions S.A. - Secure WhatsApp webhook
// Automatic welcome: once per customer session

const express = require('express');
const crypto = require('node:crypto');
const Redis = require('ioredis');

const app = express();
app.disable('x-powered-by');

const PORT = Number(process.env.PORT) || 10000;

const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const META_APP_SECRET = process.env.META_APP_SECRET;
const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const REDIS_URL = process.env.REDIS_URL;

const WELCOME_ENABLED =
  process.env.WELCOME_ENABLED === 'true';

const GRAPH_API_VERSION = 'v26.0';

const SESSION_TTL_SECONDS = 24 * 60 * 60;
const MESSAGE_DEDUP_TTL_SECONDS = 8 * 24 * 60 * 60;

// Automatic welcome message
const WELCOME_MESSAGE = [
  'Bonjour 👋',
  '',
  'Bienvenue chez *Solutions S.A.* !',
  '',
  'Merci de nous avoir contactés. Nous avons bien reçu votre message.',
  '',
  'Notre équipe prendra connaissance de votre demande et vous répondra dès que possible.',
  '',
  '*Solutions S.A.*',
  'Votre partenaire technologique en Haïti.',
  '🌐 www.solutions.ht',
  '',
  '_Ceci est un accusé de réception automatique._'
].join('\n');

// Required webhook security settings
if (!VERIFY_TOKEN || !META_APP_SECRET) {
  console.error(
    'Configuration error: missing VERIFY_TOKEN or META_APP_SECRET'
  );
  process.exit(1);
}

// Welcome feature remains disabled until activated
if (
  WELCOME_ENABLED &&
  (!ACCESS_TOKEN || !PHONE_NUMBER_ID || !REDIS_URL)
) {
  console.error(
    'Configuration error: missing welcome settings'
  );
  process.exit(1);
}

// Atomic Redis operation:
// - Deduplicate webhook messages
// - Track customer inactivity
// - Allow only one welcome per session
const CLAIM_WELCOME_LUA = `
  local isNewMessage = redis.call(
    'SET', KEYS[2], '1', 'EX', ARGV[2], 'NX'
  )

  if not isNewMessage then
    return 0
  end

  local isNewConversation = redis.call(
    'SET', KEYS[1], '1', 'EX', ARGV[1], 'NX'
  )

  if isNewConversation then
    return 1
  end

  redis.call('EXPIRE', KEYS[1], ARGV[1])
  return 0
`;

let redis;

if (WELCOME_ENABLED) {
  redis = new Redis(REDIS_URL, {
    lazyConnect: true,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
    connectTimeout: 5000
  });

  redis.on('error', () => {
    console.error('Key Value connection error');
  });
}

// GET - Meta webhook verification
app.get('/', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (
    mode === 'subscribe' &&
    token === VERIFY_TOKEN &&
    typeof challenge === 'string'
  ) {
    console.info('Webhook subscription verified');

    return res
      .status(200)
      .type('text/plain')
      .send(challenge);
  }

  return res.sendStatus(403);
});

// Verify HMAC SHA256 signature
function signatureValid(req) {
  const signature =
    req.get('x-hub-signature-256') || '';

  if (
    !Buffer.isBuffer(req.body) ||
    !/^sha256=[a-f0-9]{64}$/i.test(signature)
  ) {
    return false;
  }

  const received = Buffer.from(
    signature.slice(7),
    'hex'
  );

  const expected = crypto
    .createHmac('sha256', META_APP_SECRET)
    .update(req.body)
    .digest();

  return (
    received.length === expected.length &&
    crypto.timingSafeEqual(received, expected)
  );
}

// Protect customer identifiers in Redis
function protectedSenderKey(sender) {
  const digest = crypto
    .createHmac('sha256', META_APP_SECRET)
    .update(sender)
    .digest('hex');

  return `solutions:wa:welcome:session:${digest}`;
}

// Register first message of a session
async function claimFirstMessage(sender, messageId) {
  const sessionKey = protectedSenderKey(sender);

  const eventHash = crypto
    .createHash('sha256')
    .update(messageId)
    .digest('hex');

  const eventKey =
    `solutions:wa:welcome:event:${eventHash}`;

  const result = await redis.eval(
    CLAIM_WELCOME_LUA,
    2,
    sessionKey,
    eventKey,
    String(SESSION_TTL_SECONDS),
    String(MESSAGE_DEDUP_TTL_SECONDS)
  );

  return result === 1;
}

// Send automatic welcome using Meta Cloud API
async function sendWelcome(to) {
  const payload = {
    messaging_product: 'whatsapp',
    recipient_type: 'individual',
    to,
    type: 'text',
    text: {
      preview_url: false,
      body: WELCOME_MESSAGE
    }
  };

  const url =
    `https://graph.facebook.com/${GRAPH_API_VERSION}/${PHONE_NUMBER_ID}/messages`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${ACCESS_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000)
    });

    if (!response.ok) {
      let metaCode = 'unknown';

      try {
        const result = await response.json();

        if (Number.isInteger(result?.error?.code)) {
          metaCode = result.error.code;
        }
      } catch (_) {
        // Do not log personal message content
      }

      console.error(
        `Welcome send rejected: http=${response.status}, meta_code=${metaCode}`
      );

      return;
    }

    console.info('Welcome accepted by Meta');

  } catch (_) {
    console.error(
      'Welcome send failed: network or timeout'
    );
  }
}

// Process incoming WhatsApp messages
async function processWhatsAppEvent(event) {
  for (const entry of event.entry) {
    const changes = Array.isArray(entry.changes)
      ? entry.changes
      : [];

    for (const change of changes) {
      if (change.field !== 'messages') {
        continue;
      }

      const value = change.value;

      if (
        String(value?.metadata?.phone_number_id || '') !==
        PHONE_NUMBER_ID
      ) {
        continue;
      }

      const messages = Array.isArray(value?.messages)
        ? value.messages
        : [];

      for (const message of messages) {
        // Ignore reactions and system notifications
        if (
          message?.type === 'reaction' ||
          message?.type === 'system'
        ) {
          continue;
        }

        const sender = message?.from;
        const messageId = message?.id;

        if (
          typeof sender !== 'string' ||
          !/^[1-9][0-9]{6,14}$/.test(sender)
        ) {
          continue;
        }

        if (
          typeof messageId !== 'string' ||
          !messageId.startsWith('wamid.')
        ) {
          continue;
        }

        const shouldWelcome =
          await claimFirstMessage(sender, messageId);

        if (shouldWelcome) {
          console.info(
            'New customer session; attempting welcome'
          );

          await sendWelcome(sender);

        } else {
          console.info(
            'Welcome suppressed (active session or duplicate event)'
          );
        }
      }
    }
  }
}

// POST - Receive Meta webhook events
// Preserve original request bytes for HMAC validation
app.post(
  '/',
  express.raw({
    type: 'application/json',
    limit: '256kb'
  }),
  async (req, res) => {

    if (!signatureValid(req)) {
      console.warn(
        'Rejected webhook: missing or invalid signature'
      );

      return res.sendStatus(403);
    }

    let event;

    try {
      event = JSON.parse(
        req.body.toString('utf8')
      );
    } catch (_) {
      return res.sendStatus(400);
    }

    if (
      event?.object !== 'whatsapp_business_account' ||
      !Array.isArray(event.entry)
    ) {
      return res.sendStatus(400);
    }

    const changes = event.entry.flatMap(entry =>
      Array.isArray(entry.changes)
        ? entry.changes
        : []
    );

    const messageCount = changes.reduce(
      (n, change) =>
        n + (
          Array.isArray(change.value?.messages)
            ? change.value.messages.length
            : 0
        ),
      0
    );

    const statusCount = changes.reduce(
      (n, change) =>
        n + (
          Array.isArray(change.value?.statuses)
            ? change.value.statuses.length
            : 0
        ),
      0
    );

    console.info(
      `Authenticated WhatsApp webhook: changes=${changes.length} messages=${messageCount} statuses=${statusCount}`
    );

    // Safe deployment mode
    if (!WELCOME_ENABLED) {
      return res.sendStatus(200);
    }

    try {
      await processWhatsAppEvent(event);

      return res.sendStatus(200);

    } catch (_) {
      console.error(
        'Webhook processing error: Key Value unavailable'
      );

      return res.sendStatus(503);
    }
  }
);

// Render health check
app.get('/health', (_req, res) => {
  return res
    .status(200)
    .type('text/plain')
    .send('ok');
});

// Express error handler
app.use((err, _req, res, _next) => {
  console.error(
    'Webhook request error:',
    err.type || 'unexpected'
  );

  return res.sendStatus(
    err.status === 413 ? 413 : 400
  );
});

// Start service
async function start() {
  if (WELCOME_ENABLED) {
    await redis.connect();

    console.info(
      'Welcome feature enabled (Render Key Value connected)'
    );

  } else {
    console.info(
      'Welcome feature disabled (safe deployment mode)'
    );
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.info(
      `Solutions WhatsApp webhook listening on port ${PORT}`
    );
  });
}

start().catch(() => {
  console.error(
    'Startup failed: unable to connect to Key Value'
  );

  process.exit(1);
});
