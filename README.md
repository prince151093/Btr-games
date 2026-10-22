# CrashZone Aviator (Virtual Credits)

A multiplayer Aviator-style crash-game demo built with Express and Socket.IO. It uses virtual credits only and has no deposits, withdrawals, or real-money value.

## Render setup
- Build command: `npm install`
- Start command: `npm start`
- Node: 18 or newer

Project layout:
```
server.js
package.json
src/public/index.html
```

## Important limitations
- Player balances are in-memory and reset when the server restarts.
- This is a prototype, not a certified gambling system or audited random-number generator.
- There is no real-money payment, deposit, or withdrawal code.
- Do not use this prototype to accept real-money wagers.
