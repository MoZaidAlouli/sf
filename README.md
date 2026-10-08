# SOUL OS: Access Registration Portal

A standalone form where the president of SOUL Club lists everyone who should get access to SOUL OS. Submissions are stored in Supabase for the Digital Entity to review. The site never creates accounts, issues passwords, or grants access.

## How it works

```
Browser (static page)  ->  POST /api/submit  ->  Supabase RPC submit_registration()
public/                    Cloudflare Pages       SECURITY DEFINER function
no keys, no secrets        Function (server)      RLS on, no public policies
```

The browser holds no database key at all. The Cloudflare Pages Function checks the request, then calls one database function with the service-role key, which exists only as a Cloudflare secret. Only `service_role` may run that function. The public `anon` and `authenticated` roles have no access to any table, view, or function, and RLS is enabled on every table as a second barrier.

This is the "secure server-side alternative" the brief asks for: a public anon-key insert policy cannot enforce rate limits or CAPTCHA, so it was not used.

## Files

| Path | Purpose |
|---|---|
| `public/index.html`, `styles.css`, `app.js` | The form (no build step) |
| `public/assets/soul-logo.svg` | **Placeholder logo. Replace with the official SOUL logo file** |
| `public/_headers` | Security headers and CSP for Cloudflare Pages |
| `functions/api/submit.js` | Validates, checks origin/honeypot/Turnstile, calls Supabase |
| `functions/api/config.js` | Hands the public Turnstile site key to the browser |
| `functions/_lib/validate.js` | Server-side validation and normalisation |
| `supabase/schema.sql` | Tables, constraints, RLS, grants, submit function, export view |
| `supabase/tests/` | Database security tests and local runner |
| `tests/` | Validation, server-function, and form tests |
| `.env.example` | Environment variables (no real values) |

To edit the entity dropdown, change the `ENTITIES` list at the top of `public/app.js`. The access-level descriptions are in the `ACCESS` list in the same file.

## Environment variables

Set these in Cloudflare Pages under Settings, Variables and Secrets (Production and Preview). Add the keys as **encrypted secrets**.

| Name | Required | Notes |
|---|---|---|
| `SUPABASE_URL` | yes | Project URL, like `https://abcd1234.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | yes | Server only. Secret. Never commit it |
| `HASH_SALT` | recommended | Long random string; salts the hashed IP used for rate limiting |
| `TURNSTILE_SITE_KEY` | optional | Public key for Cloudflare Turnstile |
| `TURNSTILE_SECRET_KEY` | optional | Turns on server-side bot verification when set |

## Supabase setup (free plan)

1. Go to supabase.com, create a project, and save the database password.
2. Open **SQL Editor**, then **New query**. Paste the whole of `supabase/schema.sql` and press **Run**. It should finish with "Success. No rows returned."
3. Open **Table Editor**. `registration_submissions` and `registration_people` should both show RLS enabled.
4. Open **Project Settings, API Keys**. Copy the **Project URL** and the **service_role** key (or a **Secret** key). You do not need the anon key.

Free projects pause after about a week without activity. If submissions start failing with "We could not save", restore the project from the dashboard.

Reviewing submissions: **Table Editor** (two tables), or **SQL Editor** with `select * from public.registration_export;` and then **Download CSV**. The view has one row per person with the submission details attached.

## GitHub setup

```bash
cd soul-os-registration
npm install            # creates package-lock.json (commit it)
git init -b main
git add .
git commit -m "SOUL OS access registration portal"
# create an empty PRIVATE repo named soul-os-registration on github.com, then:
git remote add origin https://github.com/YOUR-USER/soul-os-registration.git
git push -u origin main
```

`.gitignore` already excludes `.env`, `.dev.vars`, and `node_modules`.

## Cloudflare Pages deployment

1. Cloudflare dashboard, **Workers & Pages**, **Create**, **Pages**, **Connect to Git**. Pick the repo.
2. Settings: **Framework preset** None. **Build command** leave empty. **Build output directory** `public`. **Root directory** leave as `/`. The `functions/` folder at the repo root is detected automatically.
3. Before the first deploy (or after, then redeploy), add the variables above under **Settings, Variables and Secrets**.
4. Recommended: dashboard, **Turnstile**, **Add widget**, hostname = your `*.pages.dev` domain (and any custom domain), mode Managed. Put the site key in `TURNSTILE_SITE_KEY` and the secret in `TURNSTILE_SECRET_KEY`, then redeploy.
5. Optional: **Security, WAF, Rate limiting rules** (free plan includes one) on path `/api/submit`.

Local run: copy `.env.example` to `.dev.vars`, fill it in, then `npx wrangler pages dev public`.

## Tests

```bash
npm install && npm test                                    # validation, server function, form behaviour
sudo -u postgres bash supabase/tests/run_local.sh          # database security tests (needs local PostgreSQL 15+)
```

## Verify that submissions are received securely

Replace the placeholders. `ANON_KEY` is the project's public anon key.

- [ ] Submit one real test registration with two people on the live site. The confirmation screen appears.
- [ ] Table Editor shows 1 row in `registration_submissions` and 2 in `registration_people`, linked by `submission_id`.
- [ ] Anonymous read is refused:
  `curl -s "$SUPABASE_URL/rest/v1/registration_people?select=*" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"`
  expects `permission denied` (code 42501), not rows or `[]`.
- [ ] Anonymous insert is refused:
  `curl -s -X POST "$SUPABASE_URL/rest/v1/registration_submissions" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" -H "Content-Type: application/json" -d '{}'`
  expects 42501.
- [ ] Anonymous call of the function is refused:
  `curl -s -X POST "$SUPABASE_URL/rest/v1/rpc/submit_registration" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" -H "Content-Type: application/json" -d '{"payload":{},"p_client_hash":"x"}'`
  expects 42501.
- [ ] Update and delete are refused the same way (`-X PATCH` and `-X DELETE` on the tables).
- [ ] Open the live site, View Source, and search the HTML, CSS, and JS for `supabase`, `service_role`, and `eyJ`. Nothing is found.
- [ ] Network tab during a submit shows one request, to `/api/submit` on your own domain.
- [ ] Rate limit: a sixth submission from the same connection within an hour is refused with "Too many submissions" (the idempotent retry of an already-saved submission is not counted).
- [ ] Delete your test rows: SQL Editor, `delete from public.registration_submissions;` (people rows go with them).
