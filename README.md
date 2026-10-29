# PDF Invoice OAuth Worker

Authorization-server starter for the PDF Invoice Reader MCP connection.

## Important

This Worker only implements the OAuth authorization-server side. The existing `pdf-invoice-bridge` must separately be changed to validate tokens from this Worker through a Cloudflare Service Binding and an OAuth resource-server wrapper. Do not connect ChatGPT until that second change is deployed and tested.

## Files

- `package.json` — OAuth Provider dependency and Wrangler.
- `wrangler.jsonc` — Worker settings and KV binding.
- `src/index.js` — OAuth discovery/token routes and passphrase-protected authorization page.

## Before deployment

1. In `wrangler.jsonc`, replace `REPLACE_WITH_YOUR_PDF_INVOICE_OAUTH_KV_NAMESPACE_ID` with the ID of your existing `PDF_INVOICE_OAUTH` namespace.
2. Confirm the Worker name is `pdf-invoice-oauth`, matching `ISSUER`.
3. In Cloudflare Worker Settings → Variables and Secrets, create `ADMIN_PASSWORD` as a **Secret**. Use a long unique passphrase. Never commit it to GitHub or send it in chat.
4. Configure the GitHub-connected Cloudflare project with root directory `/`, build command `npm install`, deploy command `npx wrangler deploy`.
5. Deploy and inspect the build logs.

## Security

The authorization page uses a shared passphrase. Anyone who knows it can grant read-only access, so keep it private and rotate it if exposed. This starter grants only `mcp:read`.

## Full integration still required

The MCP resource Worker must verify the issued token with a Cloudflare Service Binding. This repository alone does not complete the connection to ChatGPT.
