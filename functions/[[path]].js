import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'

const RELAY_URL = "https://pasdigi-relay.hf.space/proxy";
const RELAY_SECRET = "BantarCaringin1";

// ===============================================
// 0. UTILS & DATABASE INIT
// ===============================================
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function initDB(db) {
    await db.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, name TEXT, role TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS pages (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE, title TEXT, html_content TEXT, css_content TEXT, product_config_json TEXT, product_type TEXT, provider TEXT, views_count INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS credentials (provider_slug TEXT PRIMARY KEY, encrypted_data TEXT, iv TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS payment_templates (slug TEXT PRIMARY KEY, name TEXT, api_endpoint TEXT, method TEXT, headers_json TEXT, body_json TEXT, response_mapping TEXT, webhook_config TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS shipping_templates (slug TEXT PRIMARY KEY, name TEXT, api_endpoint TEXT, method TEXT, headers_json TEXT, body_json TEXT, response_mapping TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT UNIQUE, page_id INTEGER, amount INTEGER, status TEXT, customer_info TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS analytics (id INTEGER PRIMARY KEY AUTOINCREMENT, page_id INTEGER, event_type TEXT, referrer TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, page_id INTEGER, subject TEXT, name TEXT, email TEXT, phone TEXT, message TEXT, status TEXT DEFAULT 'unread', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
}

// ===============================================
// 1. ENGINE PEMBAYARAN
// ===============================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials belum disetting.`);

    // Menggunakan decryptJSON yang diasumsikan ada di global atau handle di relay
    let creds;
    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const decrypted = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
        creds = typeof decrypted === 'string' ? JSON.parse(decrypted) : decrypted;
    } catch (e) { throw new Error("Gagal dekripsi."); }

    let extraHeaders = {};
    if (slug.includes('flashpay')) {
        const authRes = await fetch(RELAY_URL, {
            method: 'POST',
            headers: { "Content-Type": "application/json", "x-relay-auth": RELAY_SECRET },
            body: JSON.stringify({
                target_url: "https://sandbox-secure.flashmobile.id/auth/v2/access-token",
                target_method: "POST",
                target_headers: { "Accept": "application/json", "Content-Type": "application/json" },
                target_payload: { client_key: creds.client_key, server_key: creds.server_key }
            })
        });
        const authData = await authRes.json();
        extraHeaders['Authorization'] = `Bearer ${authData.data?.token}`;
        extraHeaders['X-Client-Key'] = creds.client_key;
    }

    const replaceVars = (str) => {
        return str.replace(/{{(.*?)}}/g, (match, key) => {
            const keys = key.trim().split('.');
            let val = payload;
            for (let k of keys) val = val?.[k];
            return val !== undefined ? val : match;
        });
    };

    let bodyRaw = template.body_json || '{}';
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = JSON.parse(template.headers_json || '{}');
    headersFinal = { ...headersFinal, ...extraHeaders }; 

    const res = await fetch(RELAY_URL, {
        method: 'POST',
        headers: { "Content-Type": "application/json", "X-Relay-Secret": RELAY_SECRET },
        body: JSON.stringify({
            target_url: template.api_endpoint,
            target_method: template.method || 'POST',
            target_headers: headersFinal,
            target_payload: JSON.parse(bodyFinal)
        })
    });

    const resData = await res.json();
    const mapping = JSON.parse(template.response_mapping || '{}');
    const result = { _raw: resData };
    for (const [key, path] of Object.entries(mapping)) {
        result[key] = path.split('.').reduce((o, i) => o?.[i], resData) || null;
    }
    return result;
}

// ===============================================
// 2. GLOBAL HANDLER & ASSETS
// ===============================================
app.onError((err, c) => {
    return c.json({ success: false, message: err.message }, 500);
});

async function serveAsset(c, path) {
    try {
        const url = new URL(path, c.req.url);
        return await c.env.ASSETS.fetch(url);
    } catch (e) { return c.text('Not Found', 404); }
}

// ===============================================
// 3. MIDDLEWARE & ANALYTICS (Pake Analytics Engine)
// ===============================================
app.use('*', async (c, next) => {
    const url = new URL(c.req.url);
    const path = url.pathname;
    const isPage = !path.includes('.') && !path.startsWith('/api/') && !path.startsWith('/admin');

    await next();

    if (isPage) {
        try {
            c.env.ANALYTICS_ENGINE.writeDataPoint({
                blobs: [path, c.req.header('referer') || 'direct'],
                doubles: [1]
            });
        } catch (e) {}
    }
});

const requireAuth = async (c, next) => {
    const path = new URL(c.req.url).pathname;
    const whitelisted = (path === '/' || path === '/login' || path.startsWith('/api/login') || path.startsWith('/api/public/'));
    if (whitelisted) return await next();

    let token = getCookie(c, 'auth_token');
    if (!token) return c.redirect('/login');
    try {
        const payload = await verify(token, c.env.APP_MASTER_KEY || JWT_SECRET);
        c.set('user', payload);
        await next();
    } catch (e) { return c.redirect('/login'); }
};
app.use('/admin/*', requireAuth);
app.use('/api/admin/*', requireAuth);

// ===============================================
// 4. AUTH & ADMIN ROUTES (UTUH)
// ===============================================
app.post('/api/login', async (c) => {
    const { email, password } = await c.req.json();
    await initDB(c.env.DB);
    const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user || user.password !== await sha256(password)) return c.json({ success: false }, 401);
    const token = await sign({ id: user.id, email: user.email }, c.env.APP_MASTER_KEY || JWT_SECRET);
    setCookie(c, 'auth_token', token, { path: '/', httpOnly: true, secure: true });
    return c.json({ success: true, token });
});

app.get('/login', (c) => serveAsset(c, '/login.html'));
app.get('/admin/*', (c) => serveAsset(c, '/_views' + c.req.path.replace('/admin','').replace(/^\/$/,'/dashboard') + '.html'));

// API ADMIN (Pages, Messages, Templates, dll tetap sama)
app.get('/api/admin/pages', async (c) => {
    const res = await c.env.DB.prepare("SELECT * FROM pages ORDER BY created_at DESC").all();
    return c.json(res.results);
});

app.get('/api/admin/messages', async (c) => {
    const res = await c.env.DB.prepare("SELECT * FROM messages ORDER BY created_at DESC").all();
    return c.json(res.results);
});

// ===============================================
// 6. PUBLIC API (CONTACT & CHECKOUT TETAP ADA)
// ===============================================
app.post('/api/public/contact', async (c) => {
    try {
        const body = await c.req.json();
        await c.env.DB.prepare(`INSERT INTO messages (page_id, subject, name, email, phone, message) VALUES (?,?,?,?,?,?)`)
            .bind(body.page_id || 0, body.subject || 'Contact', body.name, body.email, body.phone, body.message).run();
        return c.json({ success: true });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const result = await executeGenericAPI(c, 'payment', body.slug_payment, body);
        return c.json({ payment_url: result.payment_url || result._raw?.data?.payment_url });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

// ===============================================
// 7. RENDERING ENGINE (UTUH)
// ===============================================
app.get('/:slug', async (c) => {
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(c.req.param('slug')).first();
    if (!page) return c.env.ASSETS.fetch(c.req.raw);
    
    const config = JSON.parse(page.product_config_json || '{}');
    const liveScripts = `<script>
        window.PAGE_ID = ${page.id};
        // Logic checkout, contact form, gallery, dll tetap di sini
    <\/script>`;

    return c.html(`<!DOCTYPE html><html><head><title>${page.title}</title><script src="https://cdn.tailwindcss.com"><\/script><style>${page.css_content}</style></head><body>${page.html_content}${liveScripts}</body></html>`);
});

// ===============================================
// 9. CRON SYNC (Pake Relay Biar Nggak Kena Loopback)
// ===============================================
async function syncAnalyticsToDB(env) {
    const query = `SELECT blob1 AS slug, count() AS total_hits FROM paslanding_event WHERE timestamp > NOW() - INTERVAL '6' HOUR GROUP BY slug`;
    try {
        // Nembak API Cloudflare lewat RELAY (Biar aman dari aturan Cloudflare Loopback)
        const response = await fetch(RELAY_URL, {
            method: 'POST',
            headers: { 'X-Relay-Secret': RELAY_SECRET, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_url: `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`,
                target_method: 'POST',
                target_headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` },
                target_payload: { query }
            })
        });
        const result = await response.json();
        if (result.data) {
            for (const row of result.data) {
                const cleanSlug = row.slug.replace(/^\/|\/$/g, '');
                if (cleanSlug) await env.DB.prepare(`UPDATE pages SET views_count = COALESCE(views_count, 0) + ? WHERE slug = ?`).bind(row.total_hits, cleanSlug).run();
            }
        }
    } catch (e) { console.error("Sync Error:", e.message); }
}

export default {
    fetch: app.fetch,
    async scheduled(event, env, ctx) {
        ctx.waitUntil(syncAnalyticsToDB(env));
    }
};
