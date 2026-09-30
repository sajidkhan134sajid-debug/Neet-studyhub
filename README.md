# NEET StudyHub — Final Build

A guest-first NEET study community web app with real authentication, live study rooms, realtime chat/presence, optional LiveKit SFU video, focus timer, study history, streaks, leaderboard and admin moderation.

## Included
- Public homepage — no login required to browse
- Student signup/login with bcrypt password hashing + JWT
- Biology, Chemistry and Physics live rooms
- Realtime room chat + online presence
- LiveKit SFU/TURN-ready camera/mic video
- 25-minute focus timer and saved study sessions
- 7-day activity + recent study history
- Real consecutive-day study streak
- Leaderboard
- Profile editing
- Report system
- Admin dashboard, report review and user ban/unban
- Security headers, rate limits, validation and production JWT-secret check
- Premium/creator/partner UI with no fake payments

## Run locally
1. Install Node.js 18+.
2. `npm install`
3. Copy `.env.example` to `.env` and set `JWT_SECRET`.
4. `npm start`
5. Open `http://localhost:3000`

For local development, `CLIENT_ORIGIN` can be omitted because the app serves its own frontend.

## Live video
Set all three variables:
- `LIVEKIT_URL`
- `LIVEKIT_API_KEY`
- `LIVEKIT_API_SECRET`

Without them, chat/presence still work and the room explains that video is not configured.

## Admin
Set `ADMIN_EMAIL` before first signup. If an account is created with that email, it receives the admin role. If the account already exists, startup promotes the matching email to admin.

## Free launch / earning
The product is free to start. The UI contains placeholders for approved ad/sponsor inventory and future Plus/creator offerings. No fake payment gateway or fake ad revenue is included.

Before public launch, configure HTTPS, a strong JWT secret, a real database strategy/backup, a managed LiveKit deployment, privacy/community rules, and any ad/payment provider accounts you actually obtain.
