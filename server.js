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
    const { q = '', offset = 0, limit = 50 } = req.query;
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
    // Use documents/d/ prefix and get workspaces
    console.log('Fetching workspaces for doc:', did);
    const wsR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/workspaces`,
      { headers: onshapeHeaders(req.session.accessToken) });
    console.log('Workspaces:', JSON.stringify(wsR.data?.slice(0,2)));
    const wid = wsR.data[0]?.id;
    if (!wid) return res.status(404).json({ error: 'No workspace found' });
    const elR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/w/${wid}/elements`,
      { headers: onshapeHeaders(req.session.accessToken) });
    // Log element types to help debug
    console.log('Element types:', elR.data.map(e => e.elementType + ':' + e.name).join(', '));
    // Onshape sometimes returns drawings as type APPLICATION — normalise it
    const elements = elR.data.map(e => {
      if (e.elementType === 'APPLICATION' && e.dataType && e.dataType.includes('drawing')) {
        return { ...e, elementType: 'DRAWING' };
      }
      return e;
    });
    res.json({ elements, workspaceId: wid });
  } catch (e) {
    console.error('Elements error:', e.response?.data || e.message);
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

// Formats supported per element type
const DRAWING_FORMATS = ['PDF','DWG','DXF','DWT','SVG','PNG','JPEG','TIFF'];
const PART_FORMATS    = ['STEP','STL','IGES','PARASOLID','ACIS','SOLIDWORKS','JT','COLLADA','GLTF','OBJ','3MF'];

function getExtension(fmt) {
  const map = { STEP:'step', STL:'stl', IGES:'igs', PARASOLID:'x_t', ACIS:'sat',
    SOLIDWORKS:'sldprt', JT:'jt', COLLADA:'dae', GLTF:'glb', OBJ:'obj', '3MF':'3mf',
    PDF:'pdf', DWG:'dwg', DXF:'dxf', DWT:'dwt', SVG:'svg', PNG:'png', JPEG:'jpg', TIFF:'tif' };
  return map[fmt] || fmt.toLowerCase();
}

// Initiate a translation (export) for one element
async function startTranslation(token, did, wid, element, format) {
  const { id: eid, elementType } = element;
  let url;

  // Base body — resolution/unit only valid for PARTSTUDIO
  const body = { formatName: format, storeInDocument: false };

  // Formats that NEVER accept resolution or unit
  const NO_RES_FORMATS = ['GLTF','OBJ','3MF','COLLADA','JT','SOLIDWORKS','ACIS','PARASOLID'];

  if (elementType === 'PARTSTUDIO') {
    url = `${ONSHAPE_BASE}/api/v10/partstudios/d/${did}/w/${wid}/e/${eid}/translations`;
    // Only STL/STEP/IGES accept resolution+unit; others reject them
    if (!NO_RES_FORMATS.includes(format)) {
      body.resolution = 'fine';
      body.unit = 'millimeter';
    }
  } else if (elementType === 'ASSEMBLY') {
    url = `${ONSHAPE_BASE}/api/v10/assemblies/d/${did}/w/${wid}/e/${eid}/translations`;
    // Assemblies NEVER accept resolution or unit — remove them regardless of format
    delete body.resolution;
    delete body.unit;
    if (format === 'STL') { body.flattenAssemblies = true; body.yAxisIsUp = false; }
    // Assemblies only support STEP/IGES/PARASOLID/ACIS/GLTF/COLLADA/STL/3MF
    const assemblyFmts = ['STEP','IGES','PARASOLID','ACIS','GLTF','COLLADA','STL','3MF','OBJ','JT'];
    if (!assemblyFmts.includes(format)) body.formatName = 'STEP';
  } else if (elementType === 'DRAWING') {
    url = `${ONSHAPE_BASE}/api/v10/drawings/d/${did}/w/${wid}/e/${eid}/translations`;
    // Drawings don't accept resolution or unit
    if (!DRAWING_FORMATS.includes(format)) body.formatName = 'PDF';
  } else {
    return null;
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
    `${ONSHAPE_BASE}/api/v6/documents/d/${did}/externaldata/${externalDataId}`,
    { headers: onshapeHeaders(token), responseType: 'arraybuffer', maxRedirects: 5 }
  );
  return Buffer.from(r.data);
}

// On-demand STL preview — fetches a single element as STL without storing in doc
app.get('/api/preview/:did/:eid', requireAuth, async (req, res) => {
  const { did, eid } = req.params;
  try {
    await refreshIfNeeded(req);
    const token = req.session.accessToken;

    const wsR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/workspaces`,
      { headers: onshapeHeaders(token) });
    const wid = wsR.data[0]?.id;
    if (!wid) return res.status(404).json({ error: 'No workspace' });

    // Find the element type
    const elR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/w/${wid}/elements`,
      { headers: onshapeHeaders(token) });
    const el = elR.data.find(e => e.id === eid);
    if (!el) return res.status(404).json({ error: 'Element not found' });

    // Only PARTSTUDIO and ASSEMBLY support STL preview
    if (!['PARTSTUDIO','ASSEMBLY'].includes(el.elementType)) {
      return res.status(400).json({ error: 'Preview only available for Part Studios and Assemblies' });
    }

    // resolution/unit only valid for PARTSTUDIO
    const body = { formatName: 'STL', storeInDocument: false };
    if (el.elementType === 'PARTSTUDIO') { body.resolution = 'coarse'; body.unit = 'millimeter'; } // preview always STL so this is safe
    if (el.elementType === 'ASSEMBLY') { body.flattenAssemblies = true; body.yAxisIsUp = false; }

    const apiPath = el.elementType === 'PARTSTUDIO' ? 'partstudios' : 'assemblies';
    const tR = await axios.post(
      `${ONSHAPE_BASE}/api/v10/${apiPath}/d/${did}/w/${wid}/e/${eid}/translations`,
      body,
      { headers: { ...onshapeHeaders(token), 'Content-Type': 'application/json;charset=UTF-8' } }
    );

    const done = await pollTranslation(token, tR.data.id, 60000);
    const externalIds = done.resultExternalDataIds || [];
    if (!externalIds.length) return res.status(500).json({ error: 'No STL produced' });

    const buf = await downloadExternalData(token, did, externalIds[0]);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${el.name}.stl"`);
    res.send(buf);
  } catch (e) {
    console.error('Preview error:', e.response?.data || e.message);
    res.status(500).json({ error: e.response?.data?.message || e.message });
  }
});

// Drawing preview — return the drawing as PDF for inline display
app.get('/api/preview-drawing/:did/:eid', requireAuth, async (req, res) => {
  const { did, eid } = req.params;
  try {
    await refreshIfNeeded(req);
    const token = req.session.accessToken;
    const wsR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/workspaces`, { headers: onshapeHeaders(token) });
    const wid = wsR.data[0]?.id;
    if (!wid) return res.status(404).json({ error: 'No workspace' });
    // Translate to PDF
    const tR = await axios.post(
      `${ONSHAPE_BASE}/api/v10/drawings/d/${did}/w/${wid}/e/${eid}/translations`,
      { formatName: 'PDF', storeInDocument: false },
      { headers: { ...onshapeHeaders(token), 'Content-Type': 'application/json;charset=UTF-8' } }
    );
    const done = await pollTranslation(token, tR.data.id, 60000);
    const externalIds = done.resultExternalDataIds || [];
    if (!externalIds.length) return res.status(500).json({ error: 'No PDF produced' });
    const buf = await downloadExternalData(token, did, externalIds[0]);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.send(buf);
  } catch (e) {
    console.error('Drawing preview error:', e.response?.data || e.message);
    res.status(500).json({ error: e.response?.data?.message || e.message });
  }
});

// Export all elements in a document as a ZIP
app.get('/api/export/:did', requireAuth, async (req, res) => {
  const { did } = req.params;
  const format = (req.query.format || 'STEP').toUpperCase();

  try {
    await refreshIfNeeded(req);
    const token = req.session.accessToken;

    // Get workspace using v6 API
    const wsR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/workspaces`,
      { headers: onshapeHeaders(token) });
    const wid = wsR.data[0]?.id;
    const docName = wsR.data[0]?.name || did;
    if (!wid) return res.status(404).json({ error: 'No workspace found' });

    // Get elements
    const elR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/w/${wid}/elements`,
      { headers: onshapeHeaders(token) });
    const selectedIds = req.query.ids ? req.query.ids.split(',') : null;
    const fmtDwg = (req.query.fmtDwg || 'PDF').toUpperCase();
    const elements = elR.data.filter(e =>
      ['PARTSTUDIO', 'ASSEMBLY', 'DRAWING'].includes(e.elementType) &&
      (!selectedIds || selectedIds.includes(e.id)));

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
      // Use drawing format for drawings, 3D format for everything else
      const elFormat = el.elementType === 'DRAWING' ? fmtDwg : format;
      try {
        const translation = await startTranslation(token, did, wid, el, elFormat);
        if (!translation) continue;

        const done = await pollTranslation(token, translation.id);
        console.log('Translation done:', JSON.stringify({ 
          state: done.requestState, 
          externalIds: done.resultExternalDataIds,
          documentIds: done.resultDocumentId,
          elementIds: done.resultElementIds
        }));
        const externalIds = done.resultExternalDataIds || [];
        const ext = getExtension(elFormat);
        const safeName = el.name.replace(/[^a-zA-Z0-9_\- ]/g, '_');

        if (externalIds.length > 0) {
          for (let i = 0; i < externalIds.length; i++) {
            const buf = await downloadExternalData(token, did, externalIds[i]);
            const suffix = externalIds.length > 1 ? `_${i + 1}` : '';
            archive.append(buf, { name: `${safeName}${suffix}.${ext}` });
          }
        } else {
          throw new Error('No result data from translation');
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

    const wsR3 = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/workspaces`,
      { headers: onshapeHeaders(token) });
    const wid = wsR3.data[0]?.id;
    if (!wid) { send({ type: 'error', message: 'No workspace found' }); return res.end(); }

    const elR = await axios.get(`${ONSHAPE_BASE}/api/v6/documents/d/${did}/w/${wid}/elements`,
      { headers: onshapeHeaders(token) });
    const selectedIds2 = req.query.ids ? req.query.ids.split(',') : null;
    const fmtDwg2 = (req.query.fmtDwg || 'PDF').toUpperCase();
    const elements = elR.data.filter(e =>
      ['PARTSTUDIO', 'ASSEMBLY', 'DRAWING'].includes(e.elementType) &&
      (!selectedIds2 || selectedIds2.includes(e.id)));

    send({ type: 'start', total: elements.length });

    const results = [];
    for (let i = 0; i < elements.length; i++) {
      const el = elements[i];
      const elFormat2 = el.elementType === 'DRAWING' ? fmtDwg2 : format;
      send({ type: 'progress', index: i, name: el.name, elementType: el.elementType, status: 'translating' });
      try {
        const translation = await startTranslation(token, did, wid, el, elFormat2);
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
