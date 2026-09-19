# WASM demo front end

Webpack app that loads the `wasm-pack` output from [`../pkg`](../pkg) and calls the
Rust `sign` export in the browser.

**Setup and run instructions are in the parent [`../README.md`](../README.md).** Do not
use older `npm init wasm-app` / Travis-oriented templates; this directory is maintained
as part of the fips204 repo.

## Scripts

- `npm install` — install devDependencies (see `package-lock.json`)
- `npm run start` — `webpack-dev-server` at http://localhost:8080/
- `npm run build` — production webpack bundle into `dist/`

## Files

- `index.html` / `index.js` / `bootstrap.js` — page UI and wasm glue
- `webpack.config.js` — bundles JS and copies `index.html`
- `package.json` / `package-lock.json` — pinned toolchain (kept under version control
  for reproducible, audit-clean installs)
