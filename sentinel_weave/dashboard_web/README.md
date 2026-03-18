# SentinelWeave Dashboard (Vite + React)

This is the new professional dashboard UI. It consumes the existing Flask APIs:

- GET /api/summary
- GET /api/events
- GET /api/stream (SSE)

## Development

```bash
cd sentinel_weave/dashboard_web
npm install
npm run dev
```

The dev server proxies `/api/*` to `http://127.0.0.1:5000`.

## Production Build

```bash
npm run build
```

Copy `dist/` to a static host or configure Flask to serve it at `/ui`.
