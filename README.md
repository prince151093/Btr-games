# CrashZone — Final shared-round files

## What's included
- `server.js` — authoritative round engine; all clients receive the same round, multiplier and crash point.
- `public/index.html` — responsive mobile-friendly interface.
- `package.json` — Render start configuration.

## Multiplier timing
- 1.00× → 2.00×: 5 seconds
- 2.00× → 5.00×: 7 seconds
- 5.00× → 10.00×: 6 seconds
- 10.00× → 50.00×: 25 seconds
- 50.00× → 100.00×: 30 seconds

A 10-second waiting/registration phase follows each crash. Crash points are chosen on the server from the project's planned weighted outcome buckets; the server, not the browser, decides the result.

## Deploy on Render
1. Upload these files to the root of your existing `crash-zone` GitHub repository, preserving the `public` folder.
2. Commit the changes and wait for Render to redeploy.
3. Use **Build Command** `npm install` and **Start Command** `npm start`.
4. Check `https://YOUR-SERVICE.onrender.com/health`; it should return JSON with `"status":"ok"`.

Node.js 18 or newer is recommended. No environment variables are required; Render supplies `PORT` automatically.
