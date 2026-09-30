require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { WebClient } = require('@slack/web-api');
const crypto = require('crypto');
const path = require('path');

const app = express();

// Trust reverse proxy headers (Required for Render, Heroku, Cloudflare, etc.)
app.set('trust proxy', true);

// Parse IP Whitelist from environment
const allowedIps = (process.env.ALLOWED_IPS || '')
  .split(',')
  .map(ip => ip.trim())
  .filter(Boolean);

// IP Whitelisting Middleware
app.use((req, res, next) => {
  if (allowedIps.length === 0) return next();

  const clientIp = req.ip || req.headers['x-forwarded-for']?.split(',')[0].trim();

  // Allow localhost during local development
  if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1' || allowedIps.includes(clientIp)) {
    return next();
  }

  res.status(403).json({ error: `Access denied: IP address ${clientIp} is not whitelisted.` });
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

const botClient = new WebClient(process.env.SLACK_BOT_TOKEN);
const USER_SCOPES = ['channels:read', 'groups:read', 'channels:write'].join(',');

// 1. Redirect to Slack OAuth
app.get('/auth/slack', (req, res) => {
  const url = `https://slack.com/oauth/v2/authorize?client_id=${process.env.SLACK_CLIENT_ID}&user_scope=${USER_SCOPES}&redirect_uri=${encodeURIComponent(process.env.SLACK_REDIRECT_URI)}`;
  res.redirect(url);
});

// 2. OAuth Callback
app.get('/auth/slack/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('No code provided.');

  try {
    const response = await botClient.oauth.v2.access({
      client_id: process.env.SLACK_CLIENT_ID,
      client_secret: process.env.SLACK_CLIENT_SECRET,
      code,
      redirect_uri: process.env.SLACK_REDIRECT_URI
    });

    req.session.userToken = response.authed_user.access_token;
    req.session.userId = response.authed_user.id;
    res.redirect('/');
  } catch (error) {
    console.error('OAuth error:', error);
    res.status(500).send('Authentication failed.');
  }
});

// Check Session Status
app.get('/api/status', (req, res) => {
  res.json({ 
    authenticated: !!req.session.userToken,
    userId: req.session.userId || null
  });
});

// Logout
app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// 3. EXPORT CHANNELS (HMAC Signed)
app.get('/api/export-channels', async (req, res) => {
  if (!req.session.userToken) return res.status(401).json({ error: 'Unauthorized' });

  const client = new WebClient(req.session.userToken);

  try {
    const authTest = await client.auth.test();
    const result = await client.users.conversations({
      types: 'public_channel,private_channel',
      exclude_archived: true,
      limit: 1000
    });

    const channels = result.channels.map(ch => ({
      name: ch.name,
      is_private: ch.is_private
    }));

    const payload = {
      source_team_id: authTest.team_id,
      channels
    };

    // Generate HMAC SHA-256 signature
    const signature = crypto
      .createHmac('sha256', process.env.SESSION_SECRET)
      .update(JSON.stringify(payload))
      .digest('hex');

    const exportFile = { ...payload, signature };

    res.setHeader('Content-disposition', `attachment; filename=slack-channels-${authTest.team_id}.json`);
    res.setHeader('Content-type', 'application/json');
    res.send(JSON.stringify(exportFile, null, 2));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. IMPORT CHANNELS (Signature Validation & Auto-Join)
app.post('/api/import-channels', async (req, res) => {
  if (!req.session.userToken || !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { source_team_id, channels, signature } = req.body;

  if (!signature || !Array.isArray(channels)) {
    return res.status(400).json({ error: 'Invalid file format or missing signature.' });
  }

  // Recalculate signature to verify file integrity
  const expectedSignature = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(JSON.stringify({ source_team_id, channels }))
    .digest('hex');

  const isValid = crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );

  if (!isValid) {
    return res.status(403).json({ error: 'Security Exception: File signature is invalid or modified.' });
  }

  const userClient = new WebClient(req.session.userToken);
  const targetUserId = req.session.userId;
  const results = [];

  try {
    const [targetPublic, targetPrivate] = await Promise.all([
      userClient.conversations.list({ types: 'public_channel', exclude_archived: true, limit: 1000 }),
      botClient.conversations.list({ types: 'private_channel', exclude_archived: true, limit: 1000 })
    ]);

    const publicMap = new Map(targetPublic.channels.map(c => [c.name, c.id]));
    const privateMap = new Map(targetPrivate.channels.map(c => [c.name, c.id]));

    for (const item of channels) {
      const { name, is_private } = item;

      if (!is_private) {
        const targetId = publicMap.get(name);
        if (!targetId) {
          results.push({ name, type: 'Public', status: 'Skipped (Channel does not exist in target workspace)' });
          continue;
        }

        try {
          await userClient.conversations.join({ channel: targetId });
          results.push({ name, type: 'Public', status: 'Joined successfully' });
        } catch (err) {
          const msg = err.data?.error === 'already_in_channel' ? 'Already a member' : `Failed: ${err.message}`;
          results.push({ name, type: 'Public', status: msg });
        }

      } else {
        const targetId = privateMap.get(name);
        if (!targetId) {
          results.push({ name, type: 'Private', status: 'Skipped (Private channel not found or Bot is not in it)' });
          continue;
        }

        try {
          await botClient.conversations.invite({ channel: targetId, users: targetUserId });
          results.push({ name, type: 'Private', status: 'Invited by Bot successfully' });
        } catch (err) {
          const msg = err.data?.error === 'already_in_channel' ? 'Already a member' : `Failed: ${err.message}`;
          results.push({ name, type: 'Private', status: msg });
        }
      }
    }

    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));