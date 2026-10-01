# Hasba (حَسبة)

Arabic-first subscription tracker for users in Oman: wallet, payday strip (what will be charged before salary day), review queue, assistant, reports.

This is an early local build. Accounts and data live in a local SQLite file. Email, WhatsApp and AI integrations are not implemented yet; message extraction and the assistant run on simple rules in the browser.

## Run with Node (24+)

```bash
node server.js
```

Open http://localhost:3000.

## Run with Docker

```bash
docker compose up --build
```

Data is kept in the `hasba-data` volume.

## What is implemented

- Sign up, log in, log out (scrypt password hashing, httpOnly session cookie, login throttling)
- Consent records, data export (JSON) and account deletion
- Per-user data stored in SQLite (`data/hasba.db`)
- RTL/LTR, light/dark themes

## Not implemented

Gmail/Outlook sync, WhatsApp, real AI extraction, email verification, 2FA, admin tools. Legal pages are placeholders.
