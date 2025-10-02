# Deploy to Vercel (Serverless API)
- Static: `/public`
- SPA entry: `/index.html` (rewrite for all non-API routes)
- API: `/api/contact` and `/api/join`

## CLI
```bash
npm i -g vercel
vercel
vercel env add MONGODB_URI
vercel env add MAIL_FROM
vercel env add SMTP_HOST
vercel env add SMTP_PORT
vercel env add SMTP_SECURE
vercel env add SMTP_USER
vercel env add SMTP_PASS
vercel deploy --prod
```