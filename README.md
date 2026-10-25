# CrashZone Aviator

CrashZone is a Node.js/Express + Socket.IO demo game with phone/password accounts and Supabase PostgreSQL storage. It uses virtual credits only.

## Supabase setup

1. Create a project at https://supabase.com.
2. In Supabase, open **SQL Editor**, create a query, paste all of `supabase-schema.sql`, and run it.
3. In Supabase **Project Settings → API** (or **Connect**), copy the Project URL and the server-side `service_role` key/secret.
4. Add these environment variables to your host (for example Render → your service → Environment):
   - `SUPABASE_URL` = your project URL
   - `SUPABASE_SERVICE_ROLE_KEY` = the service-role secret/key
   - `NODE_ENV` = `production`
5. Redeploy. The server loads accounts from `public.crashzone_users` at startup.

**Security:** Never put `SUPABASE_SERVICE_ROLE_KEY` in `src/public`, frontend JavaScript, a mobile app, or a public repository. Keep it only in the server's environment variables. Row Level Security is enabled and no browser access policies are created; requests must go through this server.

## Run locally

Requires Node.js 18 or newer.

```sh
npm install
cp .env.example .env
# Edit .env with your real Supabase values; do not commit .env
npm start
```

The server expects `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` at startup and will not start without them.

## Account behavior

- Sign up and log in with phone number + password; no OTP flow.
- Passwords are salted and hashed with Node.js `scrypt`; they are not stored as plain text.
- User numbers are assigned by a PostgreSQL sequence. Default username is `user<number>` and immutable UID is `1000000000 + number` (for example user 5 receives UID `1000000005`).
- Users may change their username from the profile endpoint; the UID and account number are not editable.
- Balances are persisted to Supabase by the game server.

## Notes

- A PostgreSQL sequence guarantees unique account numbers under concurrent sign-ups, but sequence numbers can have gaps if an account insert fails; never assume there are no gaps.
- Existing accounts in a previous local `users.json` file are **not automatically migrated**. Import them deliberately if needed; do not upload password hashes or account data to a public location.
- This is a demo virtual-credit game, not a production-grade real-money gambling platform. Before public launch, add rate limiting, monitoring, robust balance transactions, and a review of game fairness and account recovery.

## Mini-game payout and bet rules

- Big/Small direct picks return 1.9x the stake when correct (gross return includes the stake).
- Exact-number Big/Small bets share an 8x total-return pool multiplier divided by the count of exact-number selections in that round (1 pick = 8x, 2 = 4x, 3 = 2.67x, 4 = 2x, 5 = 1.6x). Direct BIG/SMALL picks do not change this count.
- Color Prediction returns 7x on a correct color; Lucky Number returns 8x on a correct number. Multipliers are gross returns including the stake.
- A maximum of five distinct selections is enforced per player per round. Each selection has its own stake; all accepted stakes are deducted up front and wins are credited at settlement.
- Prediction-game balances use virtual credits only. The listed multipliers imply different house edges: approximately 5% for BIG/SMALL, 12.5% for an equally likely eight-color game, and 20% for exact-number picks.

## Result animation and queued demo outcomes

- The player app shows one 3-second win/loss/break-even overlay for each settled Big Small, Color Prediction, or Lucky Number round with bets, using the server's authoritative round summary (total payout minus total stake). Aviator retains its own bet-result display.
- Admin → Game Management includes **Next-round result · Demo / QA only**. Queue a one-shot test outcome for Aviator (1.00×–1000.00×), Big Small (digit 0–9), Color Prediction (listed color), or Lucky Number (digit 0–9). It is consumed by the next round start and recorded in the audit log.
- Queued outcomes are stored in server memory and are lost on restart. This is for transparent virtual-credit testing only; do not use forced outcomes to misrepresent the fairness of a game.


## Independent BIG SMALL rounds

The lobby includes three independent BIG SMALL virtual-coin games:

- `big_small_30s` — 30-second rounds
- `big_small_1m` — 60-second rounds
- `big_small_5m` — 300-second rounds

Each identifier owns a separate in-memory round state and result history, and uses the existing server-authoritative Socket.IO round flow and virtual-credit ledger. Existing `bigsmall` compatibility remains in place. Admin duration settings for these IDs can be saved through the existing `/api/admin/settings/:game` endpoint; the built-in defaults are 30, 60, and 300 seconds.

**Icon note:** The supplied ZIP contained no separate icon image files, so the three lobby cards currently use matching inline BIG SMALL artwork with the duration shown on each card. Replace these card SVGs with the supplied icon assets when those files are available.

## Validation performed for this update

- `node --check server.js` passed.
- Both inline JavaScript blocks in `src/public/index.html` passed `node --check`.
- Full live server/database and multi-client integration tests were not run because this project requires configured Supabase environment variables and a reachable Supabase project.


## Game lobby update
- Lobby is grouped into three rows: Big Small (30s, 1m, 5m), Lucky Number (30s, 1m, 5m), and Aviator + Mines.
- Lucky Number has three independent server-side round streams (`lucky_30s`, `lucky_1m`, `lucky_5m`), each with its own round duration and result history.
- Supplied Lucky Number, Aviator, and Mines icons are stored in `src/public/assets/`.
- Big Small selection/history uses the professional number-ball assets.
- Admin > Game Management includes the new duration-specific modes.


## Color Prediction icon update

The lobby now includes a Color Prediction game card alongside Aviator and Mines, using `src/public/assets/color-prediction-icon.png`. The card opens the existing Color Prediction mode (`color`) and keeps its existing result/history flow.
