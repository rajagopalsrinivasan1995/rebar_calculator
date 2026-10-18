# Rebar Calculator Portal

This project provides one portal page for the Standee Calculator and Add'l Bar Calculator, with a separate Node.js backend for account authentication and login history. The original calculator files remain unchanged outside this project; the portal uses copies in `public/calculators`.

## First run

1. Install Node.js 20 or newer.
2. Open PowerShell in this folder and run:

   ```powershell
   npm install
   npm start
   ```

3. The server prints a one-time setup token in the PowerShell window. Open `http://127.0.0.1:10000`, enter that token, keep the username `rajagopal` (or choose another), and set a private password with at least 4 characters.
4. After setup, sign in with that account. Use **Manage users & logins** to add or disable accounts and review the latest 200 successful and failed sign-in attempts.

The setup token is not saved in the project. It is shown only while no account exists and is invalidated after the first administrator is created. Passwords are stored as salted scrypt hashes. Session tokens are random, stored only as hashes in SQLite, and sent in HttpOnly, SameSite cookies.

## Data and security

`App_Data/portal.sqlite` contains user hashes, active sessions, and login history. Keep this file private and back it up securely. `App_Data` and `node_modules` are excluded by `.gitignore`.

By default the server listens on port `10000` on all network interfaces; set the `PORT` environment variable to use a different port. You can open it on the same computer at `http://127.0.0.1:10000`, but do not expose it to other devices over plain HTTP. The included Docker deployment runs the app on port `3000` behind Caddy, which provides HTTPS and keeps the SQLite database in a persistent Docker volume.

The calculator pages are served through authenticated routes; their files are not exposed by the portal's static file handler. The PDF.js dependency in the Add'l Bar Calculator continues to load from its existing CDN URL and therefore requires internet access.

## Deploy on a public VPS

You need an Ubuntu VPS with a public IP address, a domain name, and Docker Engine with the Docker Compose plugin. On the domain's DNS settings, create an `A` record pointing your chosen subdomain (for example, `calculators.example.com`) to the VPS public IP. Allow inbound TCP ports 80 and 443 in both the VPS firewall and provider firewall; do not expose port 3000.

Copy this project folder to the VPS, open a terminal in it, and set the domain before starting the services:

```sh
export DOMAIN=calculators.example.com
docker compose up -d --build
```

Check that the containers are running and read the first-run setup token:

```sh
docker compose ps
docker compose logs portal
```

Open `https://calculators.example.com`. Enter the one-time token printed in the portal logs, create the `rajagopal` administrator account, and set its private password. Caddy obtains and renews the HTTPS certificate automatically when the domain resolves to this VPS and ports 80 and 443 are reachable.

The SQLite database is kept in the `portal-data` Docker volume when containers are updated or recreated. Back it up regularly; for example, while the app is running, create a consistent SQLite backup with:

```sh
docker compose exec portal node -e "const D=require('better-sqlite3'); const d=new D('/app/App_Data/portal.sqlite'); d.backup('/app/App_Data/portal-backup.sqlite').then(()=>d.close())"
docker compose cp portal:/app/App_Data/portal-backup.sqlite ./portal-backup.sqlite
```

Keep database backups private. Do not commit them or upload them to a public location.

## Tests

```powershell
npm test
```
