# Examples

## Setup

```bash
npm install
```

## Device Authorization Flow

CLI demo using RFC 8628. Opens a browser for the user to approve, then polls until authorized.

```bash
npm run device
```

Requires a `test-client` registered on the server (created automatically in development mode).

## OpenID Connect (Authorization Code)

A minimal Express app demonstrating the authorization code + OIDC flow.

```bash
npm run openid
```

Register the client first using the admin UI or the API:

```bash
curl -X POST http://localhost:3000/api/clients \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "OpenID Connect Example",
    "redirectUris": ["http://localhost:8080/callback"],
    "allowedScopes": ["openid", "profile", "email"],
    "persistent": true
  }'
```

Then set `CLIENT_ID` and `CLIENT_SECRET` in `openid-client.ts` to match.

## Create a Persistent Client (curl)

Edit `create-persistent-client.sh` with your API key, then:

```bash
bash create-persistent-client.sh
```
