import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import { sha256, encryptJSON, decryptJSON } from '../src/utils'
import { uploadImage } from '../src/modules/cloudinary'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'

// --- KONFIGURASI RELAY PROXY ---
const RELAY_URL = "https://pasdigi-relay.hf.space/proxy";
const RELAY_SECRET = "BantarCaringin1";

// =============================================================
// 1. INTERNAL ENGINE (Handling FlashPay via Relay & Generic API)
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    
    // Ambil Template
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    // Ambil Credentials (Decrypted)
    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare("SELECT * FROM credentials WHERE provider_slug = ?").bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials untuk '${providerSlug}' belum disetting.`);
    
    const creds = await decryptJSON(credRow.encrypted_data, credRow.iv, c.env.APP_MASTER_KEY || JWT_SECRET);

    let extraHeaders = {};
    
    // --- LOGIKA KHUSUS FLASHPAY (AUTO AUTH VIA RELAY) ---
    if (slug.includes('flashpay')) {
        const authPayload = {
            target_url: "https://sandbox-secure.flashmobile.id/auth/v2/access-token",
            target_method: "POST",
            target_headers: { "Accept": "application/json", "Content-Type": "application/json" },
            target_payload: { client_key: creds.client_key, server_key: creds.server_key }
        };

        const authRes = await fetch(RELAY_URL, {
            method: 'POST',
            headers: { "Content-Type": "application/json", "X-Relay-Secret": RELAY_SECRET },
            body: JSON.stringify(authPayload)
        });
        
        const authData = await authRes.json();
        const token = authData?.data?.token;
        if (!token) throw new Error("Gagal ambil Token FlashPay via Relay: " + JSON.stringify(authData));
        
        extraHeaders['Authorization'] = `Bearer ${token}`;
        extraHeaders['X-Client-Key'] = creds.client_key;
    }

    // Replace Variable {{...}}
    const replaceVars = (str) => {
        return str.replace(/{{(.*?)}}/g, (match, key) => {
            const keys = key.trim().split('.');
            let val = payload;
            for (let k of keys) val = val?.[k];
            return val !== undefined ? val : match;
        });
    };

    let bodyRaw = template.body_json || '{}';
    if (slug.includes('flashpay')) {
        payload.customer.phone_clean = payload.customer?.phone?.replace(/[^0-9]/g, '') || '08123456789'; 
    }
    
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = JSON.parse(template.headers_json || '{}');
    headersFinal = { ...headersFinal, ...extraHeaders }; 

    // KIRIM REQUEST (Via Relay jika FlashPay)
    let res;
    if (slug.includes('flashpay')) {
        res = await fetch(RELAY_URL, {
            method: 'POST',
            headers: { "Content-Type": "application/json", "X-Relay-Secret": RELAY_SECRET },
            body: JSON.stringify({
                target_url: template.api_endpoint,
                target_method: template.method || 'POST',
                target_headers: headersFinal,
                target_payload: JSON.parse(bodyFinal)
            })
        });
    } else {
        res = await fetch(template.api_endpoint, {
            method: template.method || 'POST',
            headers: headersFinal,
            body: bodyFinal
        });
    }

    const resData = await res.json();

    // Mapping Response
    const mapping = JSON.parse(template.response_mapping || '{}');
    const result = {};
    const getVal = (path, source) => path.split('.').reduce((o, i) => o?.[i], source);
    for (const [key, path] of Object.entries(mapping)) {
        result[key] = getVal(path, resData) || null;
    }
    result._raw = resData; 
    return result;
}

// ===============================================
// 2. GLOBAL ERROR & ASSETS HANDLER
// ===============================================
app.onError((err, c) => {
    console.error(`[ERROR] ${err.message}`, err.stack);
    return c.json({ success: false, message: 'Internal Server Error: ' + err.message }, 500);
});

async function serveAsset(c, path) {
    try {
        const url = new URL(path, c.req.url);
        const response = await c.env.ASSETS.fetch(url);
        if (path.endsWith('.html')) {
            const newResponse = new Response(response.body, response);
            newResponse.headers.set('Cache-Control', 'no-store, max-age=0');
            return newResponse;
        }
        return response;
    } catch (e) { return c.text('Asset Not Found', 404); }
}

// ===============================================
// 3. MIDDLEWARE AUTHENTICATION
// ===============================================
const requireAuth = async (c, next) => {
    const url = new URL(c.req.url);
    const path = url.pathname;
    
    const whitelisted = (
        path === '/' || path === '/login' || path === '/admin/login' ||
        path === '/api/login' || path === '/api/setup-first-user' ||
        path.startsWith('/api/public/') || path.startsWith('/api/webhook/') || 
        path.endsWith('.js') || path.endsWith('.css') ||
        path.endsWith('.png') || path.endsWith('.jpg') || path.endsWith('.ico')
    );

    if (whitelisted && !path.startsWith('/_views')) {
        await next();
        return;
    }

    let token = getCookie(c, 'auth_token');
    const authHeader = c.req.header('Authorization');
    if (!token && authHeader && authHeader.startsWith('Bearer ')) token = authHeader.split(' ')[1];

    if (!token) {
        if (path.startsWith('/api/')) return c.json({ error: 'Unauthorized' }, 401);
        return c.redirect('/login');
    }

    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const payload = await verify(token, secret, 'HS256');
        c.set('user', payload);
        await next();
    } catch (e) {
        deleteCookie(c, 'auth_token');
        if (path.startsWith('/api/')) return c.json({ error: 'Invalid Token' }, 401);
        return c.redirect('/login');
    }
};

app.use('*', requireAuth); 

// ===============================================
// 4. AUTHENTICATION ROUTES
// ===============================================
app.post('/api/login', async (c) => {
    try {
        const { email, password } = await c.req.json();
        const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (!user) return c.json({ success: false, message: 'Email tidak ditemukan' }, 401);
        if (await sha256(password) !== user.password) return c.json({ success: false, message: 'Password salah' }, 401);

        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const token = await sign({ id: user.id, email: user.email, role: user.role, exp: Math.floor(Date.now() / 1000) + 86400 }, secret, 'HS256');
        setCookie(c, 'auth_token', token, { path: '/', secure: true, httpOnly: true, maxAge: 86400, sameSite: 'Lax' });
        return c.json({ success: true, token });
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

app.post('/api/setup-first-user', async (c) => {
    try {
        const { email, password, name } = await c.req.json();
        const hashedPassword = await sha256(password);
        await c.env.DB.prepare("INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, 'admin')").bind(email, hashedPassword, name || 'Admin').run();
        return c.json({ success: true });
    } catch (e) { return c.json({ success: false, error: e.message }); }
});

app.get('/api/logout', (c) => { deleteCookie(c, 'auth_token'); return c.redirect('/login'); });

// ===============================================
// 5. ADMIN ROUTES (VIEWS & API)
// ===============================================
app.get('/login', (c) => serveAsset(c, '/login.html'));
app.get('/admin', (c) => c.redirect('/admin/dashboard'));
app.get('/admin/*', (c) => serveAsset(c, '/_views' + c.req.path.replace('/admin','').replace(/^\/$/,'/dashboard') + '.html'));

// --- API: PAGES ---
app.get('/api/admin/pages', async (c) => {
    const res = await c.env.DB.prepare("SELECT id, slug, title, product_type, created_at FROM pages ORDER BY created_at DESC").all();
    return c.json(res.results);
});

app.post('/api/admin/pages', async (c) => {
    const { slug, title, html, css, product_config, product_type } = await c.req.json();
    await c.env.DB.prepare(`INSERT INTO pages (slug, title, html_content, css_content, product_config_json, product_type) VALUES (?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET title=excluded.title, html_content=excluded.html_content, css_content=excluded.css_content, product_config_json=excluded.product_config_json, product_type=excluded.product_type`).bind(slug, title, html, css, JSON.stringify(product_config), product_type || 'physical').run();
    return c.json({ success: true });
});

app.get('/api/admin/pages/:slug', async (c) => {
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(c.req.param('slug')).first();
    if(page) page.product_config_json = JSON.parse(page.product_config_json || '{}');
    return c.json(page || {});
});

// --- API: REPORTS ---
app.get('/api/admin/reports', async (c) => {
    try {
        const txs = await c.env.DB.prepare(`SELECT t.*, p.product_type, p.title as page_title FROM transactions t LEFT JOIN pages p ON t.page_id = p.id ORDER BY t.created_at DESC LIMIT 100`).all();
        const formatted = txs.results.map(t => {
            let customer = { name: 'Guest', email: '-' };
            try { const p = JSON.parse(t.customer_info); if(p) customer = p; } catch(e) {}
            return { id: t.id, order_id: t.order_id, page_title: t.page_title || 'Unknown', product_type: t.product_type || 'physical', customer_name: customer.name, customer_email: customer.email, total_amount: t.amount, status: t.status, created_at: t.created_at };
        });
        const stats = await c.env.DB.prepare(`SELECT COUNT(*) as total_orders, SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END) as revenue, SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count, SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) as paid_count FROM transactions`).first();
        return c.json({ orders: formatted, stats: stats || { total_orders: 0, revenue: 0, pending_count: 0, paid_count: 0 } });
    } catch(e) { return c.json({ error: e.message }, 500); }
});

// --- API: ANALYTICS ---
app.get('/api/admin/analytics/data', async (c) => {
    const total = await c.env.DB.prepare("SELECT COUNT(*) as count FROM analytics").first();
    const today = await c.env.DB.prepare("SELECT COUNT(*) as count FROM analytics WHERE date(created_at) = date('now')").first();
    const topPages = await c.env.DB.prepare(`SELECT p.title, p.slug, COUNT(a.id) as views FROM pages p LEFT JOIN analytics a ON p.id = a.page_id GROUP BY p.id ORDER BY views DESC LIMIT 10`).all();
    const referrers = await c.env.DB.prepare(`SELECT referrer, COUNT(*) as count FROM analytics WHERE referrer IS NOT NULL AND referrer != '' GROUP BY referrer ORDER BY count DESC LIMIT 10`).all();
    const recent = await c.env.DB.prepare(`SELECT p.title, a.referrer, a.created_at FROM analytics a JOIN pages p ON a.page_id = p.id ORDER BY a.created_at DESC LIMIT 20`).all();
    return c.json({ stats: { total_views: total?.count||0, today_views: today?.count||0 }, top_pages: topPages.results||[], referrers: referrers.results||[], recent: recent.results||[] });
});

// --- API: SETTINGS & CREDENTIALS ---
app.post('/api/admin/set-homepage', async (c) => {
    await c.env.DB.prepare("INSERT INTO settings (key, value) VALUES ('homepage_slug', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind((await c.req.json()).slug).run();
    return c.json({ success: true });
});

app.get('/api/admin/homepage-slug', async (c) => {
    const s = await c.env.DB.prepare("SELECT value FROM settings WHERE key='homepage_slug'").first();
    return c.json({ slug: s ? s.value : null });
});

app.post('/api/admin/credentials', async (c) => {
    const { provider, data } = await c.req.json();
    const { encrypted, iv } = await encryptJSON(data, c.env.APP_MASTER_KEY || JWT_SECRET);
    await c.env.DB.prepare(`INSERT INTO credentials (provider_slug, encrypted_data, iv) VALUES (?, ?, ?) ON CONFLICT(provider_slug) DO UPDATE SET encrypted_data=excluded.encrypted_data, iv=excluded.iv`).bind(provider, encrypted, iv).run();
    return c.json({ success: true });
});

app.post('/api/admin/upload-image', uploadImage);

app.post('/api/admin/change-password', async (c) => {
    const user = c.get('user');
    const { current_password, new_password } = await c.req.json();
    const dbUser = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
    if(!dbUser || await sha256(current_password) !== dbUser.password) return c.json({ success: false, message: 'Password salah' }, 401);
    await c.env.DB.prepare("UPDATE users SET password = ? WHERE id = ?").bind(await sha256(new_password), user.id).run();
    return c.json({ success: true });
});

// --- API: TEMPLATES ---
app.get('/api/admin/templates', async (c) => {
    const type = c.req.query('type') === 'shipping' ? 'shipping_templates' : 'payment_templates';
    try {
        const res = await c.env.DB.prepare(`SELECT * FROM ${type}`).all();
        return c.json(res.results);
    } catch(e) { return c.json([], 200); } 
});

app.post('/api/admin/templates', async (c) => {
    const { type, data } = await c.req.json();
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    await c.env.DB.prepare(`INSERT INTO ${table} (slug, name, api_endpoint, method, headers_json, body_json, response_mapping, webhook_config) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET name=excluded.name, api_endpoint=excluded.api_endpoint, method=excluded.method, headers_json=excluded.headers_json, body_json=excluded.body_json, response_mapping=excluded.response_mapping, webhook_config=excluded.webhook_config`)
        .bind(data.slug, data.name, data.api_endpoint, data.method, data.headers_json, data.body_json, data.response_mapping, data.webhook_config || '{}').run();
    return c.json({ success: true });
});

app.delete('/api/admin/templates', async (c) => {
    const type = c.req.query('type') === 'shipping' ? 'shipping_templates' : 'payment_templates';
    await c.env.DB.prepare(`DELETE FROM ${type} WHERE slug = ?`).bind(c.req.query('slug')).run();
    return c.json({ success: true });
});

// ===============================================
// 6. PUBLIC CUSTOMER API
// ===============================================
app.post('/api/public/submit-form', async (c) => {
    const body = await c.req.parseBody();
    await c.env.DB.prepare("INSERT INTO leads (name, email, message, created_at) VALUES (?, ?, ?, datetime('now'))").bind(body['name']||'Anon', body['email']||'-', body['message']||JSON.stringify(body)).run();
    return c.redirect((c.req.header('Referer') || '/') + '?status=success');
});

app.post('/api/public/checkout', async (c) => {
    try {
        const { page_id, customer, items, total, shipping, slug_payment } = await c.req.json();
        const orderId = `ORD-${Date.now()}-${Math.floor(Math.random()*1000)}`;
        const fullCustomer = { ...customer, items, shipping };

        await c.env.DB.prepare(`INSERT INTO transactions (page_id, order_id, provider, amount, status, customer_info, created_at) VALUES (?, ?, ?, ?, 'pending', ?, datetime('now'))`)
            .bind(page_id, orderId, slug_payment || 'whatsapp', total, JSON.stringify(fullCustomer)).run();

        const result = await executeGenericAPI(c, 'payment', slug_payment || 'whatsapp', { order_id: orderId, amount: total, customer: fullCustomer });
        return c.json({ success: true, order_id: orderId, payment: result });
    } catch (e) { return c.json({ success: false, message: e.message }, 500); }
});

app.post('/api/public/shipping', async (c) => {
    try {
        const body = await c.req.json();
        return c.json(await executeGenericAPI(c, 'shipping', body.slug_shipping, body));
    } catch (e) { return c.json({ success: false, message: e.message }, 500); }
});

// ===============================================
// 7. UNIVERSAL WEBHOOK HANDLER
// ===============================================
app.post('/api/webhook/:provider', async (c) => {
    const slug = c.req.param('provider');
    const rawBody = await c.req.text(); 
    const headers = c.req.header();
    let bodyJson = {}; try { bodyJson = JSON.parse(rawBody); } catch(e) {}

    console.log(`[WEBHOOK] Received from ${slug}`, bodyJson);

    const template = await c.env.DB.prepare("SELECT * FROM payment_templates WHERE slug = ?").bind(slug).first();
    if (!template) return c.json({ message: 'Provider not found' }, 404);

    const whConfig = JSON.parse(template.webhook_config || '{}');
    let orderId = whConfig.payload_order_id_path?.split('.').reduce((o, i) => o?.[i], bodyJson) || bodyJson.order_id || bodyJson.external_id;

    if (!orderId) return c.json({ message: 'Order ID not found' }, 400);

    // Keamanan Webhook (Simple Header Match)
    const providerBase = slug.split('-')[0];
    const credRow = await c.env.DB.prepare("SELECT * FROM credentials WHERE provider_slug = ?").bind(providerBase).first();
    if (credRow && whConfig.mode === 'header_match') {
        const creds = await decryptJSON(credRow.encrypted_data, credRow.iv, c.env.APP_MASTER_KEY || JWT_SECRET);
        const incoming = headers[whConfig.header_key.toLowerCase()];
        if (incoming !== (whConfig.prefix || '') + creds[whConfig.credential_ref]) return c.json({ message: 'Unauthorized' }, 401);
    }

    // Update Status
    const status = whConfig.payload_status_path?.split('.').reduce((o, i) => o?.[i], bodyJson);
    if (status) {
        let dbStatus = 'pending';
        const s = String(status).toUpperCase();
        if (['SUCCESS','PAID','SETTLEMENT','CAPTURE'].includes(s)) dbStatus = 'paid';
        else if (['EXPIRE','FAILURE','CANCEL','DENY'].includes(s)) dbStatus = 'cancel';
        await c.env.DB.prepare("UPDATE transactions SET status = ? WHERE order_id = ?").bind(dbStatus, orderId).run();
    }
    return c.json({ success: true });
});

// ===============================================
// 8. PUBLIC PAGE RENDERING
// ===============================================
app.get('/', async (c) => {
    try {
        const s = await c.env.DB.prepare("SELECT value FROM settings WHERE key='homepage_slug'").first();
        if (s?.value) {
            const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug = ?").bind(s.value).first();
            if (page) return renderPage(c, page);
        }
    } catch (e) {}
    return serveAsset(c, '/index.html');
});

app.get('/:slug', async (c) => {
    try {
        const slug = c.req.param('slug');
        if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
        if(!page) return c.text('404 Not Found', 404);
        c.env.DB.prepare("INSERT INTO analytics (page_id, event_type, referrer) VALUES (?, 'view', ?)").bind(page.id, c.req.header('Referer') || 'direct').run().catch(()=>{});
        return renderPage(c, page);
    } catch(e) { return c.env.ASSETS.fetch(c.req.raw); }
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const settings = config.settings || {}; 
    let headScripts = '';
    if (settings.fb_pixel_id) headScripts += `<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('init', '${settings.fb_pixel_id}');fbq('track', 'PageView');</script>`;
    if (settings.tiktok_pixel_id) headScripts += `<script>!function (w, d, t) { w.TiktokAnalyticsObject=t;var ttq=w[t]=w[t]||[];ttq.methods=["page","track","identify","instances","debug","on","off","once","ready","alias","group","enableCookie","disableCookie"],ttq.setAndDefer=function(t,e){t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}};for(var i=0;i<ttq.methods.length;i++)ttq.setAndDefer(ttq,ttq.methods[i]);ttq.instance=function(t){for(var e=ttq.methods[i],n=0;n<ttq.methods.length;n++)ttq.setAndDefer(e,ttq.methods[n]);return e},ttq.load=function(e,n){var i="https://analytics.tiktok.com/i18n/pixel/events.js";ttq._i=ttq._i||{},ttq._i[e]=[],ttq._i[e]._u=i,ttq._t=ttq._t||{},ttq._t[e]=+new Date,ttq._o=ttq._o||{},ttq._o[e]=n||{};var o=document.createElement("script");o.type="text/javascript",o.async=!0,o.src=i+"?sdkid="+e+"&lib="+t;var a=document.getElementsByTagName("script")[0];a.parentNode.insertBefore(o,a)};ttq.load('${settings.tiktok_pixel_id}');ttq.page();}(window, document, 'ttq');</script>`;
    
    const appScript = `<script>window.PAGE_ID=${page.id};window.PRODUCT_TYPE="${page.product_type||'physical'}";window.PRODUCT_VARIANTS=${JSON.stringify(config.variants||[])};window.ORDER_BUMP=${JSON.stringify(config.order_bump||{active:false})};window.SHIPPING_CONFIG=${JSON.stringify(config.shipping||{weight:1000})};</script>`;
    
    return c.html(`<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${settings.seo_title||page.title}</title><meta name="description" content="${settings.seo_description||''}">${settings.favicon?`<link rel="icon" href="${settings.favicon}">`:''}<script src="https://cdn.tailwindcss.com"></script><script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script><style>html,body{margin:0!important;padding:0!important;width:100%;height:100%;overflow-x:hidden}body::before{content:"";display:table}${page.css_content}[x-cloak]{display:none!important}</style>${headScripts}</head><body class="antialiased">${page.html_content}${appScript}${settings.custom_footer||''}</body></html>`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
