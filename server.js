require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
const archiver = require('archiver');
const { PassThrough } = require('stream');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Config ──────────────────────────────────────────────────────────────────
const ONSHAPE_BASE = 'https://cad.onshape.com';
const OAUTH_BASE   = 'https://oauth.onshape.com';

const CLIENT_ID     = process.env.ONSHAPE_CLIENT_ID;
const CLIENT_SECRET = process.env.ONSHAPE_CLIENT_SECRET;
const REDIRECT_URI  = process.env.REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'onshape-exporter-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ── Auth helpers ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.accessToken) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

function onshapeHeaders(token) {
  return { Authorization: `Bearer ${token}`, Accept: 'application/json;charset=UTF-8' };
}

async function refreshIfNeeded(req) {
  if (!req.session.expiresAt || Date.now() < req.session.expiresAt - 60000) return;
  const r = await axios.post(`${OAUTH_BASE}/oauth/token`, new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: req.session.refreshToken,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
  }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  req.session.accessToken = r.data.access_token;
  req.session.refreshToken = r.data.refresh_token;
  req.session.expiresAt = Date.now() + r.data.expires_in * 1000;
}

// ── OAuth routes ─────────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'OAuth2Read OAuth2Write',
  });
  res.redirect(`${OAUTH_BASE}/oauth/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=no_code');
  try {
    const r = await axios.post(`${OAUTH_BASE}/oauth/token`, new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

    req.session.accessToken  = r.data.access_token;
    req.session.refreshToken = r.data.refresh_token;
    req.session.expiresAt    = Date.now() + r.data.expires_in * 1000;
    res.redirect('/app');
  } catch (e) {
    console.error('OAuth callback error:', e.response?.data || e.message);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/auth/status', (req, res) => {
  res.json({ authenticated: !!req.session.accessToken });
});

// ── API routes ────────────────────────────────────────────────────────────────

// Get current user profile
app.get('/api/user', requireAuth, async (req, res) => {
  try {
    await refreshIfNeeded(req);
    const r = await axios.get(`${ONSHAPE_BASE}/api/v10/users/sessioninfo`,
      { headers: onshapeHeaders(req.session.accessToken) });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

// List documents
app.get('/api/documents', requireAuth, async (req, res) => {
  try {
    await refreshIfNeeded(req);
    const { q = '', offset = 0, limit = 20 } = req.query;
    console.log('Fetching docs, token exists:', !!req.session.accessToken);
    const params = { sortColumn: 'modifiedAt', sortOrder: 'desc', offset, limit, filter: 0 };
    if (q) params.q = q;
    const r = await axios.get(`${ONSHAPE_BASE}/api/v10/documents`, {
      params,
      headers: onshapeHeaders(req.session.accessToken)
    });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

// Get elements in a document
app.get('/api/documents/:did/elements', requireAuth, async (req, res) => {
  try {
    await refreshIfNeeded(req);
    const { did } = req.params;
    // Get the default workspace
    const docR = await axios.get(`${ONSHAPE_BASE}/api/v10/documents/${did}`,
      { headers: onshapeHeaders(req.session.accessToken) });
    const wid = docR.data.defaultWorkspace.id;
    const elR = await axios.get(`${ONSHAPE_BASE}/api/v10/documents/${did}/w/${wid}/elements`,
      { headers: onshapeHeaders(req.session.accessToken) });
    res.json({ elements: elR.data, workspaceId: wid });
  } catch (e) {
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

// Initiate a translation (export) for one element
async function startTranslation(token, did, wid, element, format) {
  const { id: eid, elementType } = element;
  let url;
  const body = {
    formatName: format,
    storeInDocument: false,
    resolution: 'FINE',
    unit: 'MILLIMETER',
  };

  if (elementType === 'PARTSTUDIO') {
    url = `${ONSHAPE_BASE}/api/v10/partstudios/d/${did}/w/${wid}/e/${eid}/translations`;
  } else if (elementType === 'ASSEMBLY') {
    url = `${ONSHAPE_BASE}/api/v10/assemblies/d/${did}/w/${wid}/e/${eid}/translations`;
  } else if (elementType === 'DRAWING') {
    url = `${ONSHAPE_BASE}/api/v10/drawings/d/${did}/w/${wid}/e/${eid}/translations`;
    body.formatName = 'PDF'; // override for drawings
  } else {
    return null; // skip blob / other types
  }

  const r = await axios.post(url, body, {
    headers: { ...onshapeHeaders(token), 'Content-Type': 'application/json;charset=UTF-8' }
  });
  return r.data;
}

// Poll translation until done
async function pollTranslation(token, translationId, maxWait = 120000) {
  const start = Date.now();
  while (Date.now() - start < maxWait) {
    const r = await axios.get(`${ONSHAPE_BASE}/api/v10/translations/${translationId}`,
      { headers: onshapeHeaders(token) });
    if (r.data.requestState === 'DONE') return r.data;
    if (r.data.requestState === 'FAILED') throw new Error(`Translation failed: ${r.data.failureReason}`);
    await new Promise(ok => setTimeout(ok, 3000));
  }
  throw new Error('Translation timed out');
}

// Download external data (translated file)
async function downloadExternalData(token, did, externalDataId) {
  const r = await axios.get(
    `${ONSHAPE_BASE}/api/v10/documents/${did}/externaldata/${externalDataId}`,
    { headers: onshapeHeaders(token), responseType: 'arraybuffer', maxRedirects: 5 }
  );
  return Buffer.from(r.data);
}

// Export all elements in a document as a ZIP
app.get('/api/export/:did', requireAuth, async (req, res) => {
  const { did } = req.params;
  const format = (req.query.format || 'STEP').toUpperCase();

  try {
    await refreshIfNeeded(req);
    const token = req.session.accessToken;

    // Get workspace
    const docR = await axios.get(`${ONSHAPE_BASE}/api/v10/documents/${did}`,
      { headers: onshapeHeaders(token) });
    const docName = docR.data.name || did;
    const wid = docR.data.defaultWorkspace.id;

    // Get elements
    const elR = await axios.get(`${ONSHAPE_BASE}/api/v10/documents/${did}/w/${wid}/elements`,
      { headers: onshapeHeaders(token) });
    const elements = elR.data.filter(e =>
      ['PARTSTUDIO', 'ASSEMBLY', 'DRAWING'].includes(e.elementType));

    if (elements.length === 0) {
      return res.status(400).json({ error: 'No exportable elements found in this document.' });
    }

    // Set up streaming ZIP response
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition',
      `attachment; filename="${encodeURIComponent(docName)}_export.zip"`);

    const archive = archiver('zip', { zlib: { level: 6 } });
    archive.pipe(res);

    for (const el of elements) {
      try {
        const translation = await startTranslation(token, did, wid, el, format);
        if (!translation) continue;

        const done = await pollTranslation(token, translation.id);
        const externalIds = done.resultExternalDataIds || [];

        for (let i = 0; i < externalIds.length; i++) {
          const buf = await downloadExternalData(token, did, externalIds[i]);
          const ext = format === 'STEP' ? 'step' :
                      format === 'STL'  ? 'stl'  :
                      format === 'PDF'  ? 'pdf'  : format.toLowerCase();
          const safeName = el.name.replace(/[^a-zA-Z0-9_\- ]/g, '_');
          const suffix = externalIds.length > 1 ? `_${i + 1}` : '';
          archive.append(buf, { name: `${safeName}${suffix}.${ext}` });
        }
      } catch (elErr) {
        // Add a text error file instead of crashing
        archive.append(`Export failed: ${elErr.message}`, {
          name: `${el.name.replace(/[^a-zA-Z0-9_\- ]/g, '_')}_ERROR.txt`
        });
      }
    }

    archive.finalize();
  } catch (e) {
    console.error('Export error:', e.response?.data || e.message);
    if (!res.headersSent) {
      res.status(500).json({ error: e.response?.data?.message || e.message });
    }
  }
});

// Export progress check (SSE endpoint for real-time updates)
app.get('/api/export/:did/progress', requireAuth, async (req, res) => {
  const { did } = req.params;
  const format = (req.query.format || 'STEP').toUpperCase();

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    await refreshIfNeeded(req);
    const token = req.session.accessToken;

    const docR = await axios.get(`${ONSHAPE_BASE}/api/v10/documents/${did}`,
      { headers: onshapeHeaders(token) });
    const wid = docR.data.defaultWorkspace.id;

    const elR = await axios.get(`${ONSHAPE_BASE}/api/v10/documents/${did}/w/${wid}/elements`,
      { headers: onshapeHeaders(token) });
    const elements = elR.data.filter(e =>
      ['PARTSTUDIO', 'ASSEMBLY', 'DRAWING'].includes(e.elementType));

    send({ type: 'start', total: elements.length });

    const results = [];
    for (let i = 0; i < elements.length; i++) {
      const el = elements[i];
      send({ type: 'progress', index: i, name: el.name, elementType: el.elementType, status: 'translating' });
      try {
        const translation = await startTranslation(token, did, wid, el, format);
        if (!translation) {
          send({ type: 'progress', index: i, name: el.name, status: 'skipped' });
          continue;
        }
        await pollTranslation(token, translation.id);
        results.push({ elementId: el.id, name: el.name, elementType: el.elementType, status: 'done' });
        send({ type: 'progress', index: i, name: el.name, status: 'done' });
      } catch (err) {
        results.push({ name: el.name, status: 'failed', error: err.message });
        send({ type: 'progress', index: i, name: el.name, status: 'failed', error: err.message });
      }
    }

    send({ type: 'complete', results });
    res.end();
  } catch (e) {
    send({ type: 'error', error: e.message });
    res.end();
  }
});

// Serve the SPA for /app too
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`✅ Onshape Exporter running → http://localhost:${PORT}`));
