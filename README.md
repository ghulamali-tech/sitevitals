# SiteVitals — website health scanner (backend)

Scans any public website's uptime, security, performance, code quality and SEO — server-side, so there's no browser CORS restriction. Reports what's wrong and can generate an auto-fixed HTML file.

## Run it locally

```bash
npm install
npm start
```

Then open http://localhost:3000 in your browser.

## What it checks

- **Uptime** — is the site up, is it returning a server error (500), a client error (404), timing out, or refusing the connection. This is the "site crashed / has an error" check.
- **Code** — missing page title, images without alt text, dead placeholder links.
- **Security** — HTTPS in use, mixed content, missing security headers (CSP, X-Frame-Options, HSTS), forms submitting over plain HTTP.
- **Performance** — response time, page weight, missing compression, images without explicit dimensions.
- **SEO** — meta description, viewport tag, heading structure.

## API

`POST /api/scan` with JSON body `{ "url": "example.com" }` → returns a JSON report.

`POST /api/fix` with the same body → returns a downloadable HTML file with the safe, automatic fixes applied (missing alt text, missing meta tags).

## Deploying for free so anyone can use it

Any of these have a free tier that's enough for a demo or small-scale real use:

1. **Render.com** — connect your GitHub repo, pick "Web Service," it auto-detects Node and runs `npm install && npm start`. Free tier sleeps after inactivity but wakes on request.
2. **Railway.app** — similar flow, connects to GitHub, free trial credit monthly.
3. **Fly.io** — `fly launch` in this folder, free allowance for small apps.
4. **Cyclic.sh** or **Glitch.com** — good for very quick, no-config Node hosting.

Steps for Render (most common free choice):
1. Push this folder to a GitHub repo.
2. On Render, "New +" → "Web Service" → connect the repo.
3. Build command: `npm install`. Start command: `npm start`.
4. Deploy — you'll get a public URL like `https://sitevitals.onrender.com` anyone can use.

## Notes on scope

- This scans publicly available information only (HTTP responses, HTML, response headers) — it does not attempt to access private data, exploit vulnerabilities, or modify anyone's live site. It's a read-only diagnostic tool.
- The "fix" endpoint only edits the fetched HTML and returns it as a download — it never writes back to the original site. Applying fixes to a live site requires the site owner to upload the corrected file, or your own edits pushed to their codebase.
