const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function normalizeUrl(url) {
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  return url;
}

// Core scan logic — runs on the server, so no browser CORS limits apply.
async function scanSite(rawUrl) {
  const url = normalizeUrl(rawUrl);
  const issues = [];
  const add = (category, severity, title, desc, fix) => {
    issues.push({ category, severity, title, desc, fix });
  };

  let response;
  let responseTimeMs;
  const startTime = Date.now();

  try {
    response = await axios.get(url, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: () => true, // we want to inspect any status ourselves
      headers: { 'User-Agent': 'SiteVitals-Scanner/1.0' }
    });
    responseTimeMs = Date.now() - startTime;
  } catch (err) {
    // Site is unreachable, timed out, or connection failed — this is the
    // "site is down / crashing" case.
    let reason = 'The site could not be reached.';
    if (err.code === 'ECONNABORTED') reason = 'The site took too long to respond (timed out after 10 seconds).';
    else if (err.code === 'ENOTFOUND') reason = 'The domain name could not be resolved. Check the URL is correct.';
    else if (err.code === 'ECONNREFUSED') reason = 'The server refused the connection.';
    else if (err.code === 'CERT_HAS_EXPIRED') reason = 'The SSL certificate has expired.';

    return {
      url,
      reachable: false,
      statusCode: null,
      responseTimeMs: null,
      score: 0,
      issues: [{
        category: 'uptime',
        severity: 'critical',
        title: 'Site is down or unreachable',
        desc: reason,
        fix: 'Check server status, DNS records, and hosting provider dashboard.'
      }],
      html: null
    };
  }

  const statusCode = response.status;
  const html = response.data;

  // --- UPTIME / SERVER HEALTH ---
  if (statusCode >= 500) {
    add('uptime', 'critical', 'Server error (' + statusCode + ')', 'The server responded with a ' + statusCode + ' error, meaning something is broken on the backend.', 'Check server logs for the crashing request or process.');
  } else if (statusCode >= 400) {
    add('uptime', 'critical', 'Client error (' + statusCode + ')', 'The page returned a ' + statusCode + ' error (e.g. not found or forbidden).', 'Verify the URL and that the page exists and is publicly accessible.');
  } else if (statusCode >= 300) {
    add('uptime', 'warning', 'Redirect (' + statusCode + ')', 'This URL redirects elsewhere before loading.', 'Confirm the redirect target is intentional and not a redirect loop.');
  } else {
    add('uptime', 'pass', 'Site responded normally (' + statusCode + ')', 'The server returned a healthy status code.', '');
  }

  if (responseTimeMs > 3000) {
    add('uptime', 'warning', 'Slow server response (' + responseTimeMs + 'ms)', 'Server took over 3 seconds to respond, which risks visitors leaving.', 'Investigate slow database queries, unoptimized backend code, or under-resourced hosting.');
  } else {
    add('uptime', 'pass', 'Fast server response (' + responseTimeMs + 'ms)', 'Server responded quickly.', '');
  }

  if (typeof html !== 'string' || html.trim().length === 0) {
    add('uptime', 'critical', 'Empty page response', 'The server responded but sent back no content.', 'Check the application server / route handler for silent failures.');
    return { url, reachable: true, statusCode, responseTimeMs, score: 10, issues, html: '' };
  }

  const $ = cheerio.load(html);

  // --- CODE ---
  const title = $('title').first().text().trim();
  if (!title) {
    add('code', 'critical', 'Missing page title', 'The <title> tag is empty or missing, which hurts SEO and browser tabs.', 'Add a descriptive <title> tag.');
  } else {
    add('code', 'pass', 'Page title present', 'Title tag found: "' + title.slice(0, 50) + '"', '');
  }

  const imgs = $('img');
  const missingAlt = imgs.filter((i, el) => !$(el).attr('alt')).length;
  if (missingAlt > 0) {
    add('code', 'warning', missingAlt + ' image(s) missing alt text', 'Images without alt attributes are invisible to screen readers and hurt image SEO.', 'Add descriptive alt="" text to each image.');
  } else if (imgs.length > 0) {
    add('code', 'pass', 'All images have alt text', imgs.length + ' image(s) checked, all have alt attributes.', '');
  }

  const deadLinks = $('a[href="#"], a[href=""], a[href="javascript:void(0)"]').length;
  if (deadLinks > 0) {
    add('code', 'warning', deadLinks + ' placeholder or dead link(s)', 'Links pointing to "#" or empty href go nowhere for users.', 'Replace with real destinations or remove the link.');
  }

  // --- SECURITY ---
  const isHttps = url.startsWith('https://');
  if (!isHttps) {
    add('security', 'critical', 'Site not using HTTPS', 'Traffic is unencrypted, exposing user data and hurting search ranking.', 'Install an SSL certificate and force redirect to HTTPS.');
  } else {
    add('security', 'pass', 'HTTPS in use', 'Connection is encrypted.', '');
  }

  const headers = response.headers || {};
  if (!headers['content-security-policy']) {
    add('security', 'warning', 'No Content-Security-Policy header', 'CSP headers reduce the risk of script-injection attacks (XSS).', 'Add a Content-Security-Policy header at the server or CDN level.');
  } else {
    add('security', 'pass', 'Content-Security-Policy header present', 'CSP header found.', '');
  }
  if (!headers['x-frame-options'] && !headers['content-security-policy']) {
    add('security', 'warning', 'No clickjacking protection', 'Missing X-Frame-Options or frame-ancestors CSP directive lets the site be embedded in a hidden iframe.', 'Add X-Frame-Options: SAMEORIGIN or a CSP frame-ancestors directive.');
  }
  if (!headers['strict-transport-security'] && isHttps) {
    add('security', 'warning', 'No HSTS header', 'Strict-Transport-Security tells browsers to always use HTTPS for this site.', 'Add Strict-Transport-Security: max-age=31536000 to server responses.');
  }

  const mixedContent = $('img[src^="http://"], script[src^="http://"], link[href^="http://"]').length;
  if (isHttps && mixedContent > 0) {
    add('security', 'warning', 'Mixed content detected', mixedContent + ' resource(s) load over plain HTTP on an HTTPS page.', 'Change those resource URLs to https://.');
  }

  const insecureForms = $('form').filter((i, el) => ($(el).attr('action') || '').startsWith('http://')).length;
  if (insecureForms > 0) {
    add('security', 'critical', 'Form submits over HTTP', 'User-submitted data (possibly passwords) would travel unencrypted.', 'Point the form action to an https:// endpoint.');
  }

  // --- PERFORMANCE ---
  const unsizedImgs = imgs.filter((i, el) => !$(el).attr('width') && !$(el).attr('height')).length;
  if (unsizedImgs > 3) {
    add('performance', 'warning', 'Images missing width/height', unsizedImgs + ' image(s) have no explicit size, causing layout shift while loading.', 'Add width and height attributes to each image tag.');
  }

  const sizeKb = Math.round(Buffer.byteLength(html, 'utf8') / 1024);
  if (sizeKb > 300) {
    add('performance', 'warning', 'Heavy HTML document (' + sizeKb + ' KB)', 'Large HTML payloads slow down first paint, especially on mobile.', 'Minify HTML and split large embedded content into separate files.');
  } else {
    add('performance', 'pass', 'Reasonable page weight (' + sizeKb + ' KB)', 'HTML document size is within a healthy range.', '');
  }

  if (!headers['content-encoding']) {
    add('performance', 'warning', 'No compression detected', 'Response is not gzip/brotli compressed, making transfers larger than necessary.', 'Enable gzip or brotli compression on the server.');
  }

  // --- SEO ---
  const metaDesc = $('meta[name="description"]').attr('content');
  if (!metaDesc) {
    add('seo', 'critical', 'Missing meta description', 'Search engines use this to build the snippet shown in results.', 'Add <meta name="description" content="..."> with a 1-2 sentence summary.');
  } else {
    add('seo', 'pass', 'Meta description present', 'Found: "' + metaDesc.slice(0, 60) + '"', '');
  }

  const viewport = $('meta[name="viewport"]').attr('content');
  if (!viewport) {
    add('seo', 'critical', 'Missing viewport meta tag', 'Without this, the site will not render properly on mobile devices.', 'Add <meta name="viewport" content="width=device-width, initial-scale=1.0">.');
  } else {
    add('seo', 'pass', 'Viewport tag present', 'Mobile rendering is configured correctly.', '');
  }

  const h1Count = $('h1').length;
  if (h1Count === 0) {
    add('seo', 'warning', 'No H1 heading found', 'Search engines use the H1 to understand the page main topic.', 'Add one clear <h1> describing the page.');
  } else if (h1Count > 1) {
    add('seo', 'warning', h1Count + ' H1 tags found', 'Multiple H1s can dilute topical relevance for search engines.', 'Keep a single H1 per page; demote others to H2/H3.');
  } else {
    add('seo', 'pass', 'Single H1 heading found', 'One clear H1 tag detected.', '');
  }

  const critical = issues.filter(i => i.severity === 'critical').length;
  const warning = issues.filter(i => i.severity === 'warning').length;
  const score = Math.max(0, Math.round(100 - critical * 20 - warning * 8));

  return { url, reachable: true, statusCode, responseTimeMs, score, issues, html };
}

app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Provide a "url" field in the request body.' });
  }
  try {
    const result = await scanSite(url);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Scan failed unexpectedly: ' + err.message });
  }
});

// Returns an auto-fixed version of the scanned HTML for download.
app.post('/api/fix', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Provide a "url" field.' });

  try {
    const result = await scanSite(url);
    if (!result.reachable || !result.html) {
      return res.status(400).json({ error: 'Could not fetch page content to fix.' });
    }
    const $ = cheerio.load(result.html);

    $('img').each((i, el) => {
      if (!$(el).attr('alt')) $(el).attr('alt', 'Description needed');
    });
    if (!$('meta[name="viewport"]').length) {
      $('head').append('<meta name="viewport" content="width=device-width, initial-scale=1.0">');
    }
    if (!$('meta[name="description"]').length) {
      $('head').append('<meta name="description" content="Add a short description of this page here.">');
    }

    const fixedHtml = '<!DOCTYPE html>\n' + $.html();
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', 'attachment; filename="fixed-site.html"');
    res.send(fixedHtml);
  } catch (err) {
    res.status(500).json({ error: 'Fix failed: ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log('SiteVitals backend running on http://localhost:' + PORT);
});
