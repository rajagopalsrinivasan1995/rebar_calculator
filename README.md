# Rebar Calculator Portal

This project provides one portal page for the Standee Calculator and Add'l Bar Calculator, with a separate Node.js backend for account authentication and login history. The original calculator files remain unchanged outside this project; the portal uses copies in `public/calculators`.

## Supabase setup

1. Create a Supabase project and open its **SQL Editor**.
2. Run the contents of [`supabase-schema.sql`](./supabase-schema.sql) to create the portal tables and indexes. These tables have row-level security enabled and are not granted to the `anon` or `authenticated` API roles.
3. In **Project Settings → Database**, copy a PostgreSQL connection string. Use the direct connection when the host supports IPv6; otherwise use Supabase's session pooler. Keep the password private.
4. Set `DATABASE_URL` to that connection string in your deployment environment. Include `sslmode=require` in the connection string so the connection uses TLS.

## First run

1. Install Node.js 20 or newer and create the Supabase tables as described above.
2. Open PowerShell in this folder, set `DATABASE_URL` to the copied connection string, and run:

   ```powershell
   $env:DATABASE_URL = "postgresql://postgres:YOUR_PASSWORD@db.PROJECT_REF.supabase.co:5432/postgres?sslmode=require"
   npm.cmd install
   npm.cmd start
   ```

3. The server prints a one-time setup token in the PowerShell window. Open `http://127.0.0.1:10000`, enter that token, keep the username `rajagopal` (or choose another), and set a private password with at least 4 characters.
4. After setup, sign in with that account. Use **Manage users & logins** to add or disable accounts and review the latest 200 successful and failed sign-in attempts.

The setup token is not saved in the project. It is shown only while no account exists and is invalidated after the first administrator is created. Passwords are stored as salted scrypt hashes. Session tokens are random, stored only as hashes in PostgreSQL, and sent in HttpOnly, SameSite cookies.

## Data and security

Supabase PostgreSQL stores user hashes, active sessions, and login history. Keep `DATABASE_URL` private, use a backend database connection (never a Supabase anon key), and back up the Supabase project securely. `App_Data` and `node_modules` are excluded by `.gitignore`.

By default the server listens on port `10000` on all network interfaces; set the `PORT` environment variable to use a different port. You can open it on the same computer at `http://127.0.0.1:10000`, but do not expose it to other devices over plain HTTP. The included Docker deployment runs the app on port `3000` behind Caddy, which provides HTTPS.

The calculator pages are served through authenticated routes; their files are not exposed by the portal's static file handler. The PDF.js dependency in the Add'l Bar Calculator continues to load from its existing CDN URL and therefore requires internet access.

## Deploy on a public VPS

You need an Ubuntu VPS with a public IP address, a domain name, and Docker Engine with the Docker Compose plugin. On the domain's DNS settings, create an `A` record pointing your chosen subdomain (for example, `calculators.example.com`) to the VPS public IP. Allow inbound TCP ports 80 and 443 in both the VPS firewall and provider firewall; do not expose port 3000.

Copy this project folder to the VPS, open a terminal in it, and set the domain before starting the services:

```sh
export DOMAIN=calculators.example.com
export DATABASE_URL='postgresql://postgres:YOUR_PASSWORD@db.PROJECT_REF.supabase.co:5432/postgres?sslmode=require'
docker compose up -d --build
```

## Deploy on Render

In the Render service's **Environment** settings, set:

- `DATABASE_URL` to the Supabase PostgreSQL connection string
- `TRUST_PROXY` to `1`

Save the changes and deploy. Then open the latest deploy's logs, copy the one-time setup token printed by the server, and use it to create the administrator. Do not share the token. Data persists in Supabase across Render deploys.

For other hosting providers that put one trusted reverse proxy in front of the app, set `TRUST_PROXY=1` in the service's environment variables and restart or redeploy the service.

Check that the containers are running and read the first-run setup token:

```sh
docker compose ps
docker compose logs portal
```

Open `https://calculators.example.com`. Enter the one-time token printed in the portal logs, create the `rajagopal` administrator account, and set its private password. Caddy obtains and renews the HTTPS certificate automatically when the domain resolves to this VPS and ports 80 and 443 are reachable.

Use Supabase's database backup and point-in-time recovery features where available. Existing `App_Data/portal.sqlite` files are not migrated automatically; export/import the existing users and login history separately if you need to retain them. Existing SQLite session tokens should not be migrated.

## Tests

```powershell
npm.cmd test
```
