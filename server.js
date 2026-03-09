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
    const token = req.session.accessToken;
    const params = { sortColumn: 'modifiedAt', sortOrder: 'desc', offset, limit, filter: 0 };
    if (q) params.q = q;
    const r = await axios.get(`${ONSHAPE_BASE}/api/v10/documents`, { params, headers: onshapeHeaders(token) });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

// Fetch top-level folders (projects) from Onshape home tree
app.get('/api/projects', requireAuth, async (req, res) => {
  try {
    await refreshIfNeeded(req);
    const token = req.session.accessToken;
    // globaltreenodes/magic/1 returns the top-level home items (folders + docs)
    const r = await axios.get(`${ONSHAPE_BASE}/api/globaltreenodes/magic/1`, {
      params: { getPathToRoot: false, includeApplications: false },
      headers: onshapeHeaders(token)
    });
    // Filter to only folders (type 2 = folder in Onshape tree)
    const items = (r.data.items || []).filter(i => i.jsonType === 'folder-info' || i.resourceType === 'folder');
    res.json({ items });
  } catch (e) {
    console.error('Projects error:', e.response?.data || e.message);
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

// Fetch documents inside a project folder
app.get('/api/projects/:fid/documents', requireAuth, async (req, res) => {
  try {
    await refreshIfNeeded(req);
    const token = req.session.accessToken;
    const { fid } = req.params;
    // globaltreenodes/folder/{fid} returns folder contents
    const r = await axios.get(`${ONSHAPE_BASE}/api/globaltreenodes/folder/${fid}`, {
      params: { getPathToRoot: false, includeApplications: false },
      headers: onshapeHeaders(token)
    });
    // Filter to only documents (not sub-folders), map to match our doc format
    const items = (r.data.items || []).filter(i =>
      i.jsonType !== 'folder-info' && i.resourceType !== 'folder'
    ).map(i => ({
      id: i.id,
      name: i.name,
      modifiedAt: i.modifiedAt || i.createdAt,
      resourceType: i.resourceType
    }));
    res.json({ items });
  } catch (e) {
    console.error('Project docs error:', e.response?.data || e.message);
    res.status(500).json({ error: e.response?.data || e.message });
  }
});

// Normalise element types — Onshape returns drawings as APPLICATION type
function normaliseElements(elements) {
  return elements.map(e => {
    if (e.elementType === 'APPLICATION') {
      return { ...e, elementType: 'DRAWING' };
    }
    return e;
  });
}

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
    console.log('Element types:', elR.data.map(e => e.elementType + ':' + e.name).join(', '));
    res.json({ elements: normaliseElements(elR.data), workspaceId: wid });
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

  // GLTF/OBJ/3MF use tessellation params. STL uses resolution+unit. Others use neither.
  const TESSELLATION_FORMATS = ['GLTF','OBJ','3MF'];

  if (elementType === 'PARTSTUDIO') {
    url = `${ONSHAPE_BASE}/api/v10/partstudios/d/${did}/w/${wid}/e/${eid}/translations`;
    if (format === 'STL') {
      body.resolution = 'fine';
      body.unit = 'millimeter';
    } else if (TESSELLATION_FORMATS.includes(format)) {
      body.angularTolerance = 0.1;
      body.distanceTolerance = 0.00012;
      body.maximumChordLength = 10;
    }
  } else if (elementType === 'ASSEMBLY') {
    url = `${ONSHAPE_BASE}/api/v10/assemblies/d/${did}/w/${wid}/e/${eid}/translations`;
    if (format === 'STL') {
      body.flattenAssemblies = true;
      body.yAxisIsUp = false;
    } else if (TESSELLATION_FORMATS.includes(format)) {
      body.angularTolerance = 0.1;
      body.distanceTolerance = 0.00012;
      body.maximumChordLength = 10;
    }
  } else if (elementType === 'DRAWING') {
    url = `${ONSHAPE_BASE}/api/v10/drawings/d/${did}/w/${wid}/e/${eid}/translations`;
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
    const elements = normaliseElements(elR.data).filter(e =>
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

    // Start ALL translations in parallel, then download results
    const jobs = await Promise.all(elements.map(async el => {
      const elFormat = el.elementType === 'DRAWING' ? fmtDwg : format;
      const safeName = el.name.replace(/[^a-zA-Z0-9_\- ]/g, '_');
      try {
        const translation = await startTranslation(token, did, wid, el, elFormat);
        if (!translation) return { el, elFormat, safeName, skip: true };
        return { el, elFormat, safeName, translationId: translation.id };
      } catch (err) {
        return { el, elFormat, safeName, error: err.message };
      }
    }));

    // Poll all translations in parallel
    const settled = await Promise.all(jobs.map(async job => {
      if (job.skip || job.error) return job;
      try {
        const done = await pollTranslation(token, job.translationId);
        return { ...job, done };
      } catch (err) {
        return { ...job, error: err.message };
      }
    }));

    // Append files to ZIP
    for (const job of settled) {
      if (job.skip) continue;
      if (job.error) {
        archive.append(`Export failed: ${job.error}`, { name: `${job.safeName}_ERROR.txt` });
        continue;
      }
      const externalIds = job.done.resultExternalDataIds || [];
      const ext = getExtension(job.elFormat);
      if (externalIds.length > 0) {
        for (let i = 0; i < externalIds.length; i++) {
          const buf = await downloadExternalData(token, did, externalIds[i]);
          const suffix = externalIds.length > 1 ? `_${i + 1}` : '';
          archive.append(buf, { name: `${job.safeName}${suffix}.${ext}` });
        }
      } else {
        archive.append('No result data from translation', { name: job.safeName + '_ERROR.txt' });
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
    const elements = normaliseElements(elR.data).filter(e =>
      ['PARTSTUDIO', 'ASSEMBLY', 'DRAWING'].includes(e.elementType) &&
      (!selectedIds2 || selectedIds2.includes(e.id)));

    send({ type: 'start', total: elements.length });

    const results = [];

    // Start all translations in parallel
    elements.forEach((el, i) => {
      send({ type: 'progress', index: i, name: el.name, elementType: el.elementType, status: 'translating' });
    });

    const sseJobs = await Promise.all(elements.map(async (el, i) => {
      const elFormat2 = el.elementType === 'DRAWING' ? fmtDwg2 : format;
      try {
        const translation = await startTranslation(token, did, wid, el, elFormat2);
        if (!translation) return { i, el, skip: true };
        return { i, el, translationId: translation.id };
      } catch (err) {
        return { i, el, error: err.message };
      }
    }));

    // Poll all in parallel, send progress as each finishes
    await Promise.all(sseJobs.map(async job => {
      const { i, el } = job;
      if (job.skip) {
        send({ type: 'progress', index: i, name: el.name, status: 'skipped' });
        return;
      }
      if (job.error) {
        results.push({ name: el.name, status: 'failed', error: job.error });
        send({ type: 'progress', index: i, name: el.name, status: 'failed', error: job.error });
        return;
      }
      try {
        await pollTranslation(token, job.translationId);
        results.push({ elementId: el.id, name: el.name, elementType: el.elementType, status: 'done' });
        send({ type: 'progress', index: i, name: el.name, status: 'done' });
      } catch (err) {
        results.push({ name: el.name, status: 'failed', error: err.message });
        send({ type: 'progress', index: i, name: el.name, status: 'failed', error: err.message });
      }
    }));

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
