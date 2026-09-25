# PRAHARI frontend

React 19 + Vite interface for the analysis backend. See the repository README for how the pieces fit together.

```bash
npm ci
npm run dev -- --host 127.0.0.1   # proxies /api to the backend on port 8010
npm run build                     # bundle served by the backend on the same origin
npx oxlint src                    # lint
```

`src/App.jsx` holds the main workspace and routing between views; each panel (evidence, relay map, quarantine, investigator leads, and so on) is its own component in `src/`. API calls and the optional role-token handling live in `src/api.js`.
