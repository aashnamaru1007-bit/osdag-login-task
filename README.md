# Secure Login System — Flask + PostgreSQL

Osdag FOSSEE Screening Task: a secure login/registration/logout system with protected user profile and file-access routes.

## Scope

This submission implements the **custom backend** (Flask + PostgreSQL) fully and in depth. Given the timeline, I prioritized building one implementation thoroughly — with correct password hashing, JWT-based auth, server-side logout invalidation, rate limiting, and verified user data isolation — over rushing a second (Appwrite) implementation. This is explicitly allowed by the task brief ("where requirements are left open, use your judgment and document your reasoning"). See the **Appwrite** section below for how I would approach it given more time.

## Setup Instructions

1. Clone the repo and install dependencies:
   ```
   pip install -r requirements.txt
   ```
2. Create a PostgreSQL database (e.g. `login_db`).
3. Copy `.env.example` to `.env` and fill in your own values:
   ```
   SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
   DATABASE_URL=postgresql://<username>:<password>@localhost:5432/login_db
   ```
4. Run the app:
   ```
   python app.py
   ```
   The server starts on `http://127.0.0.1:5000` and auto-creates all tables (`user`, `files`, `token_blocklist`) on first run.

## Seeded / Test Users

Three test accounts were registered via `POST /register` for testing user isolation. To recreate them, POST to `/register` with:
```json
{ "email_id": "user1@test.com", "password": "test123" }
```
(repeat for `user2@test.com`, `user3@test.com`, or your own choice of credentials).

Each user then has sample files added via `POST /files` (see below), while authenticated as that user.

## API Routes

| Route | Method | Auth required | Description |
|---|---|---|---|
| `/register` | POST | No | Register with email + password |
| `/login` | POST | No | Returns a JWT access token |
| `/logout` | POST | Yes | Invalidates the current token server-side |
| `/me` | GET | Yes | Returns the logged-in user's own profile |
| `/files` | GET | Yes | Returns only the logged-in user's files |
| `/files` | POST | Yes | Adds a file to the logged-in user's account |
| `/files/:id` | GET | Yes | Returns one file; rejects access to another user's file |

## Reasoning on JWT vs. Session-Based Authentication

I chose **JWT** over server-side session cookies for stateless, cross-client authentication that doesn't require server-side session storage to verify every request — the token's signature alone proves its validity. This also keeps testing simple across tools (Postman, the provided `index.html` client) since the token is just passed via an `Authorization: Bearer <token>` header, without depending on cookie/browser-specific behavior (SameSite, CORS, domains).

The trade-off: JWTs are valid until expiry by default, so logout isn't "free" the way deleting a session record would be — I addressed this with a token blocklist (see below).

## How Logout Is Implemented

Each JWT includes a unique `jti` (JWT ID) claim, generated automatically by `flask_jwt_extended`. On `/logout`, the current token's `jti` is stored in a `token_blocklist` table. A `token_in_blocklist_loader` callback runs automatically on every `@jwt_required()`-protected route and checks whether the incoming token's `jti` is in that table — if so, the request is rejected with `401`, even if the token hasn't expired yet. This satisfies server-side invalidation rather than relying on the client to simply discard the token.

The blocklist is backed by a database table (rather than an in-memory store) specifically so that revoked tokens stay revoked even if the server restarts an in-memory blocklist would silently reset on every restart, allowing previously logged-out tokens to become valid again.

Access tokens are also configured to expire after a fixed window (`JWT_ACCESS_TOKEN_EXPIRES`) as a secondary safeguard.

## How User Data Isolation Is Enforced

- Every protected route identifies the user from the **verified JWT payload** (`get_jwt_identity()`), never from a client-supplied ID in the URL or request body.
- `GET /files` filters strictly by `user_id` derived from the token.
- `GET /files/:id` fetches the file, then explicitly checks `file.user_id == current_user_id`. Two distinct failure cases are returned:
  - File exists but belongs to another user → `403 Forbidden`
  - File does not exist at all → `404 Not Found`

  This distinction was deliberately implemented per the task requirement, and verified by testing: user1 attempting to access user2's file ID receives `403`; requesting a nonexistent ID receives `404`.
- `POST /files` attaches the new file to the `user_id` from the JWT, never a client-supplied value — preventing a user from creating files under someone else's account.

## General Security Practices

- Passwords are hashed with **bcrypt** (`flask-bcrypt`), which salts automatically — never stored in plaintext or reversibly encrypted.
- Failed login returns a single generic error (`"login failed"`) regardless of whether the email doesn't exist or the password is wrong, so the API doesn't leak which emails are registered.
- Rate limiting via `flask-limiter`: `/login` is limited to 5 attempts per minute per IP address, returning `429` (as JSON) once exceeded.
- All protected routes consistently use the `@jwt_required()` decorator, which validates signature, expiry, and blocklist status before any route logic executes.
- Secrets (`SECRET_KEY`, database credentials) are loaded from environment variables via `.env` (excluded from version control), not hardcoded.

## Appwrite (Second Backend) — Not Implemented, Given More Time

Given the timeline, I focused on delivering one secure, well-tested implementation rather than a second, rushed one. If I were to build the Appwrite version:
- **Appwrite would handle automatically:** password hashing and storage, session/JWT issuance, email uniqueness validation, and built-in rate limiting on auth endpoints.
- **I would still need to configure myself:** the `files` collection/permissions model scoped per-user (Appwrite's permission system would need to be set to owner-only read access per document), the equivalent of the `/me` and `/files/:id` isolation checks (largely enforced via Appwrite's document-level permissions rather than manual `user_id` filtering), and wiring the same `index.html` test client to Appwrite's SDK instead of my custom Flask routes.

## What I Would Improve Given More Time

- Implement the Appwrite backend as a direct comparison to the custom implementation.
- Move from a fixed-expiry access token to a short-lived access token + refresh token pattern, reducing the window a stolen token remains valid without requiring the user to re-login as frequently.
- Add automated tests (e.g. pytest) covering the isolation and auth-failure cases currently verified manually via Postman.
- Add real file storage/upload (currently files are seeded as text records with a `content` field, per the task's allowance for "seeded sample files").
