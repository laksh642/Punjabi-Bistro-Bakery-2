# ☁️ Deploying to Cloudflare Pages & Cloudflare Workers
### Punjabi Bistro & Bakery Dharamkot

This project is fully optimized and pre-configured for **Cloudflare Pages** and **Cloudflare Workers**. All single-page application (SPA) routes, asset caching headers, edge API functions, and Supabase cloud persistence work out-of-the-box.

---

## ⚡ Quick Summary of Pre-Configured Cloudflare Files

| File | Purpose |
|------|---------|
| `wrangler.json` & `wrangler.toml` | Cloudflare Pages configuration declaring `pages_build_output_dir = "dist"` and `nodejs_compat`. |
| `.nvmrc` & `.node-version` | Pins Node.js runtime to `22` for modern Vite 6, React 19 & Supabase compatibility. |
| `public/_redirects` | Rewrites all routes (`/* /index.html 200`) so `/admin`, `/orders/:token`, and `/tracking` load on page refresh without 404s. |
| `public/_headers` | Adds security headers and 1-year immutable caching for `/assets/*` with instant-fresh `index.html`. |
| `functions/api/[[catchall]].ts` | Serverless Edge API router for Cloudflare Pages Functions (`/api/*`). |

---

## 🚀 Deployment Options

### Method 1: Cloudflare Pages via GitHub / Git (Recommended)

1. **Push your code to GitHub / GitLab**.
2. Go to the [Cloudflare Dashboard](https://dash.cloudflare.com/) and navigate to **Workers & Pages**.
3. Click **Create Application** → **Pages** → **Connect to Git**.
4. Select your repository and choose the `main` branch.
5. In **Build Settings**:
   - **Framework preset:** `Vite`
   - **Build command:** `npm run build` (or `npm run build:cloudflare`)
   - **Build output directory:** `dist`
   - **Root directory:** `/`
   - **Deploy command:** *(Leave empty/blank! If Cloudflare requires one, use `npx wrangler pages deploy dist`)*
6. (Optional) Set **Environment Variables** under **Settings > Environment Variables**:
   - `VITE_SUPABASE_URL`: `https://mlbjulhzbhnqkzzohgcm.supabase.co`
   - `VITE_SUPABASE_ANON_KEY`: `sb_publishable_wepmD-cYmB4FyuoS2EByeA_pzfVNM_c`
7. Click **Save and Deploy**.
8. Cloudflare will build the site in ~30 seconds and provide you with a live `*.pages.dev` URL!

---

### Method 2: 1-Command CLI Deploy with Wrangler

You can deploy directly to Cloudflare from your terminal using Cloudflare's official `wrangler` CLI:

```bash
# 1. Build production static bundle
npm run build:cloudflare

# 2. Deploy to Cloudflare Pages (you will be prompted to login to Cloudflare once)
npx wrangler pages deploy dist --project-name=punjabi-bistro-dharamkot
```

---

### Method 3: Direct Upload (Drag & Drop)

If you do not want to connect Git:
1. Run local build:
   ```bash
   npm run build:cloudflare
   ```
2. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages** → **Create application** → **Pages** → **Upload assets**.
3. Drag and drop the generated `dist` folder into Cloudflare.
4. Click **Deploy site**!

---

## 🔒 Administrator Portal Access

- **Portal URL**: `https://<your-site>.pages.dev/admin`
- **Default Username**: `admin`
- **Persistence**: Full cloud synchronization with Supabase. Order statuses, kitchen delay notices, menu pricing, reviews, and custom cake inquiries synchronize instantly.

---

## 🌐 Custom Domain Setup on Cloudflare

1. Inside your Cloudflare Pages project, go to **Custom domains**.
2. Click **Set up a custom domain**.
3. Enter your domain (e.g., `punjabibistro.in` or `orders.punjabibistro.in`).
4. Cloudflare will automatically provision a free SSL/TLS certificate and route traffic worldwide through Cloudflare's global edge network.
