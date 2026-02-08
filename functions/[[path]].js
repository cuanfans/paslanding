import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import { encryptJSON, decryptJSON } from '../src/utils'
import { uploadImage } from '../src/modules/cloudinary'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'

// --- KONFIGURASI RELAY ---
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
    // Tabel Utama System
    await db.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, name TEXT, role TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS pages (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE, title TEXT, html_content TEXT, css_content TEXT, product_config_json TEXT, product_type TEXT, provider TEXT, views_count INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS credentials (provider_slug TEXT PRIMARY KEY, encrypted_data TEXT, iv TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`).run();
    
    // Tabel Transaksi & Analytics
    await db.prepare(`CREATE TABLE IF NOT EXISTS payment_templates (slug TEXT PRIMARY KEY, name TEXT, api_endpoint TEXT, method TEXT, headers_json TEXT, body_json TEXT, response_mapping TEXT, webhook_config TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS shipping_templates (slug TEXT PRIMARY KEY, name TEXT, api_endpoint TEXT, method TEXT, headers_json TEXT, body_json TEXT, response_mapping TEXT)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT UNIQUE, page_id INTEGER, amount INTEGER, status TEXT, customer_info TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS analytics (id INTEGER PRIMARY KEY AUTOINCREMENT, page_id INTEGER, event_type TEXT, referrer TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    
    // --- NEW: TABEL PESAN (CONTACT FORM) ---
    await db.prepare(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        page_id INTEGER,
        subject TEXT, 
        name TEXT, 
        email TEXT, 
        phone TEXT, 
        message TEXT, 
        status TEXT DEFAULT 'unread', 
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`).run();
}

// ===============================================
// 1. ENGINE PEMBAYARAN (FlashPay & Generic)
// ===============================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    
    // 1. Ambil Template
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    // 2. Ambil Credentials
    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials untuk '${providerSlug}' belum disetting.`);

    // 3. Dekripsi Data
    let creds;
    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const decrypted = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
        creds = typeof decrypted === 'string' ? JSON.parse(decrypted) : decrypted;
    } catch (e) { throw new Error("Gagal dekripsi kredensial."); }

    let extraHeaders = {};
    
    // --- AUTH RELAY (FLASHPAY) ---
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
        if (!authRes.ok || !authData?.data?.token) throw new Error("Auth Relay Gagal");
        
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
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
        // Cleaning Phone
        if (payload.customer?.phone) {
            payload.customer.phone_clean = payload.customer.phone.replace(/[^0-9]/g, '');
        }
        
        // Force Construct FlashPay Payload (Supaya Qty & Item detail sinkron)
        const fpPayload = {
            external_id: "INV-" + Date.now(),
            payment_type: [slug.toUpperCase().replace(/-/g, '_')],
            currency: "IDR",
            transaction_amount: Number(payload.amount),
            customer_id: String(payload.customer.phone).replace(/[^0-9]/g, ''),
            va_type: "CLOSE_AMOUNT",
            va_reusability: "SINGLE_USE",
            customer_details: {
                name: payload.customer.name,
                email: "customer@mail.com",
                phone: payload.customer.phone
            },
            item_details: [{
                item_id: "ITEM-01",
                information: payload.item_name || "Produk",
                amount: Number(payload.amount), // Total amount (Price * Qty)
                beneficiary_bank: "MNC",
                beneficiary_account: "5279910282",
                beneficiary_name: "PASDIGI"
            }]
        };
        bodyRaw = JSON.stringify(fpPayload);
    }
    
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = JSON.parse(template.headers_json || '{}');
    headersFinal = { ...headersFinal, ...extraHeaders }; 

    // KIRIM REQUEST
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
// 2. GLOBAL HANDLER & HELPER
// ===============================================
app.onError((err, c) => {
    console.error(`[ERROR] ${err.message}`);
    return c.json({ success: false, message: err.message }, 500);
});

async function serveAsset(c, path) {
    try {
        const url = new URL(path, c.req.url);
        const response = await c.env.ASSETS.fetch(url);
        if (path.endsWith('.html')) {
            const newRes = new Response(response.body, response);
            newRes.headers.set('Cache-Control', 'no-store, max-age=0');
            return newRes;
        }
        return response;
    } catch (e) { return c.text('Not Found', 404); }
}

// ===============================================
// 3. MIDDLEWARE
// ===============================================
const requireAuth = async (c, next) => {
    const url = new URL(c.req.url);
    const path = url.pathname;
    
    // Whitelist path yang boleh diakses publik
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

    if (!token) return c.redirect('/login');

    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const payload = await verify(token, secret, 'HS256');
        c.set('user', payload);
        await next();
    } catch (e) {
        deleteCookie(c, 'auth_token');
        return c.redirect('/login');
    }
};

app.use('*', requireAuth); 

// ===============================================
// 3.1 ANALYTICS ENGINE MIDDLEWARE (BUFFER)
// ===============================================
app.use('*', async (c, next) => {
    await next(); 
    const url = new URL(c.req.url);
    const path = url.pathname;
    const isPage = !path.includes('.') && !path.startsWith('/api/admin') && !path.startsWith('/admin');

    if (isPage) {
        try {
            c.env.ANALYTICS.writeDataPoint({
                blobs: [
                    path,
                    c.req.header('referer') || 'direct'
                ],
                doubles: [1]
            });
        } catch (e) {
            console.error("Analytics Engine Error:", e.message);
        }
    }
});

// ===============================================
// 4. AUTH ROUTES (Login Fix)
// ===============================================
app.post('/api/login', async (c) => {
    try {
        const { email, password } = await c.req.json();
        await initDB(c.env.DB); // Pastikan DB Ready
        const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        
        if (!user) return c.json({ success: false, message: 'Email tidak ditemukan' }, 401);
        
        const inputHash = await sha256(password);
        let isValid = false;
        let needMigration = false;

        if (user.password === inputHash) isValid = true;
        else if (user.password === password) { isValid = true; needMigration = true; }

        if (!isValid) return c.json({ success: false, message: 'Password salah' }, 401);

        if (needMigration) {
            await c.env.DB.prepare("UPDATE users SET password = ? WHERE id = ?").bind(inputHash, user.id).run();
        }

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
// 5. ADMIN ROUTES (Dashboard, Modules, Pages)
// ===============================================
app.get('/login', (c) => serveAsset(c, '/login.html'));
app.get('/admin', (c) => c.redirect('/admin/dashboard'));
app.get('/admin/*', (c) => serveAsset(c, '/_views' + c.req.path.replace('/admin','').replace(/^\/$/,'/dashboard') + '.html'));

// --- MODULE: HOMEPAGE SETTING ---
app.get('/api/admin/homepage-slug', async (c) => {
    try {
        const setting = await c.env.DB.prepare("SELECT value FROM settings WHERE key='homepage_slug'").first();
        return c.json({ slug: setting?.value || null });
    } catch (e) {
        return c.json({ error: e.message }, 500);
    }
});

app.post('/api/admin/set-homepage', async (c) => {
    try {
        const { slug } = await c.req.json();
        if (!slug) return c.json({ error: "Slug tidak valid" }, 400);
        const page = await c.env.DB.prepare("SELECT id FROM pages WHERE slug = ?").bind(slug).first();
        if (!page) return c.json({ error: "Halaman tidak ditemukan di database" }, 404);
        await c.env.DB.prepare(`INSERT INTO settings (key, value) VALUES ('homepage_slug', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`).bind(slug).run();
        return c.json({ success: true, message: "Homepage berhasil diatur", slug });
    } catch (e) {
        return c.json({ error: e.message }, 500);
    }
});

// --- MODULE: PAGES ---
app.get('/api/admin/pages', async (c) => {
    const res = await c.env.DB.prepare("SELECT id, slug, title, product_type, created_at, views_count FROM pages ORDER BY created_at DESC").all();
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

// --- MODULE: MESSAGES (KONTAK ADMIN) ---
app.get('/api/admin/messages', async (c) => {
    try {
        const res = await c.env.DB.prepare("SELECT * FROM messages ORDER BY created_at DESC LIMIT 100").all();
        return c.json(res.results);
    } catch (e) { return c.json({ error: e.message }, 500); }
});

app.patch('/api/admin/messages/:id', async (c) => {
    try {
        const { status } = await c.req.json();
        await c.env.DB.prepare("UPDATE messages SET status = ? WHERE id = ?").bind(status, c.req.param('id')).run();
        return c.json({ success: true });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

app.delete('/api/admin/messages/:id', async (c) => {
    try {
        await c.env.DB.prepare("DELETE FROM messages WHERE id = ?").bind(c.req.param('id')).run();
        return c.json({ success: true });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

// --- MODULE: ANALYTICS ---
app.get('/api/admin/analytics/data', async (c) => {
    try {
        const total = await c.env.DB.prepare("SELECT SUM(views_count) as count FROM pages").first();
        const topPages = await c.env.DB.prepare(`SELECT title, slug, views_count as views FROM pages ORDER BY views DESC LIMIT 10`).all();
        return c.json({ 
            stats: { total_views: total?.count||0 }, 
            top_pages: topPages.results||[], 
            recent: [] 
        });
    } catch(e) { return c.json({ error: e.message }); }
});

// --- MODULE: SETTINGS & TEMPLATES ---
app.post('/api/admin/credentials', async (c) => {
    const { provider, data } = await c.req.json();
    const { encrypted, iv } = await encryptJSON(data, c.env.APP_MASTER_KEY || JWT_SECRET);
    await c.env.DB.prepare(`INSERT INTO credentials (provider_slug, encrypted_data, iv) VALUES (?, ?, ?) ON CONFLICT(provider_slug) DO UPDATE SET encrypted_data=excluded.encrypted_data, iv=excluded.iv`).bind(provider, encrypted, iv).run();
    return c.json({ success: true });
});

app.get('/api/admin/templates', async (c) => {
    const type = c.req.query('type') === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const res = await c.env.DB.prepare(`SELECT * FROM ${type}`).all();
    return c.json(res.results);
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
// 6. PUBLIC API (Checkout & Contact)
// ===============================================

app.post('/api/public/contact', async (c) => {
    try {
        await initDB(c.env.DB);
        let body;
        const contentType = c.req.header('Content-Type');
        if (contentType && contentType.includes('application/json')) { body = await c.req.json(); } else { body = await c.req.parseBody(); }
        const { page_id, subject, name, email, phone, message } = body;
        if (!name || !message) return c.json({ error: "Nama dan Pesan wajib diisi!" }, 400);
        await c.env.DB.prepare(`INSERT INTO messages (page_id, subject, name, email, phone, message) VALUES (?, ?, ?, ?, ?, ?)`).bind(page_id || 0, subject || 'General', name, email || '', phone || '', message).run();
        if (!contentType || !contentType.includes('application/json')) { return c.redirect(c.req.header('Referer') + '?status=sent'); }
        return c.json({ success: true, message: "Pesan terkirim!" });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const { slug_payment, customer, quantity } = body;
        if (!slug_payment || !customer?.phone) return c.json({ error: "Data tidak lengkap!" }, 400);
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page.product_config_json || '{}');
        let unitPrice = 0;
        let itemName = page.title;
        if (config.variants && config.variants[body.variant_index]) {
            unitPrice = Number(config.variants[body.variant_index].price);
            itemName += ` (${config.variants[body.variant_index].name})`;
        } else {
            unitPrice = Number(config.price || 0);
        }
        const qty = parseInt(quantity || 1);
        let finalAmount = unitPrice * qty;
        let bumpName = '';
        if (body.take_bump && config.order_bump?.active) {
            finalAmount += Number(config.order_bump.price); 
            bumpName = config.order_bump.title;
        }
        if (body.coupon_code && config.coupons) {
            const cp = config.coupons.find(x => x.code.toUpperCase() === body.coupon_code.toUpperCase());
            if (cp) {
                const disc = cp.type === 'percent' ? (finalAmount * cp.value / 100) : cp.value;
                finalAmount = Math.max(0, finalAmount - disc);
            }
        }
        const apiPayload = { ...body, amount: finalAmount, item_name: itemName + (qty > 1 ? ` (x${qty})` : ''), bump_name: bumpName };
        const result = await executeGenericAPI(c, 'payment', slug_payment, apiPayload);
        return c.json({ payment_url: result.payment_url || result._raw?.data?.payment_url });
    } catch (e) { return c.json({ error: "Proses Gagal: " + e.message }, 500); }
});

// ===============================================
// 8. HOMEPAGE HANDLER (ROOT URL)
// ===============================================
app.get('/', async (c) => {
    try {
        const setting = await c.env.DB.prepare("SELECT value FROM settings WHERE key='homepage_slug'").first();
        if (!setting || !setting.value) {
            return c.html(`<div style="font-family: sans-serif; text-align: center; padding: 50px;"><h1>Welcome</h1><p>Homepage belum diatur.</p><a href="/login" style="color: blue;">Login Admin</a></div>`);
        }
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(setting.value).first();
        if (!page) return c.text(`Error: Halaman '${setting.value}' tidak ditemukan.`, 404);
        return renderPage(c, page);
    } catch (e) { return c.text(`Server Error: ${e.message}`, 500); }
});

// ===============================================
// 7. PAGE RENDERING (FINAL FIX & CLEAN)
// ===============================================
app.get('/:slug', async (c) => {
    try {
        const slug = c.req.param('slug');
        if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
        if(!page) return c.text('404 Not Found', 404);
        return renderPage(c, page);
    } catch(e) { return c.env.ASSETS.fetch(c.req.raw); }
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const activePayments = config.active_payments || [];
    const bridgeCSS = `body { min-height: 100vh; background-color: #ffffff; overflow-x: hidden; font-family: 'Inter', sans-serif; } .product-gallery { display: flex; flex-direction: column; gap: 12px; width:100%; } .product-gallery .main-img { border-radius: 12px; overflow: hidden; width: 100%; aspect-ratio: 4/3; background: #f3f4f6; } .product-gallery .main-img img { width: 100%; height: 100%; object-fit: cover; } .product-gallery .thumbs { display: flex; flex-direction: row; gap: 10px; overflow-x: auto; } .product-gallery .thumb { min-width: 70px; width: 70px; height: 70px; border-radius: 8px; cursor: pointer; opacity: 0.7; object-fit: cover; } .product-gallery .thumb.active { border: 2px solid #2563eb; opacity: 1; } .editable-carousel { position: relative; width: 100%; overflow: hidden; } .editable-carousel .slides { display: flex; transition: transform 0.5s; } .editable-carousel .slide { min-width: 100%; } .pricing-card { border: 1px solid #e2e8f0; border-radius: 16px; padding: 32px; transition: 0.3s; }`;
    const tailwindConfig = `tailwind.config = { theme: { extend: { fontFamily: { sans: ['Inter', 'sans-serif'] } } } }`;
    const liveScripts = `<script>if(new URLSearchParams(window.location.search).get('status') === 'sent') alert('Pesan diterima!'); document.addEventListener('DOMContentLoaded', () => { document.querySelectorAll('.product-gallery').forEach(el => { const main = el.querySelector('.main-img img'); const thumbs = el.querySelectorAll('.thumb'); if(main && thumbs.length) thumbs.forEach(t => t.onclick = function() { main.src = this.src; thumbs.forEach(x => x.classList.remove('active')); this.classList.add('active'); })}); if (document.body.innerHTML.includes('[ CHECKOUT ]')) { const activePayments = ${JSON.stringify(activePayments)}; const paymentHTML = activePayments.map(slug => '<label class="flex items-center p-3 border rounded-lg mb-2"><input type="radio" name="pay_method" value="' + slug + '" class="mr-3"><span>' + slug.toUpperCase() + '</span></label>').join(''); const checkoutHTML = '<div class="max-w-md mx-auto p-6 bg-white shadow-xl rounded-2xl"><h2>Form Pemesanan</h2>' + paymentHTML + '<button id="btn-submit-order" class="w-full py-4 bg-blue-600 text-white rounded-xl">BAYAR</button></div>'; document.body.innerHTML = document.body.innerHTML.replace('[ CHECKOUT ]', checkoutHTML); document.getElementById('btn-submit-order')?.addEventListener('click', async () => { const payMethod = document.querySelector('input[name="pay_method"]:checked')?.value; if(!payMethod) return alert('Pilih pembayaran!'); const res = await fetch('/api/public/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ page_id: ${page.id}, slug_payment: payMethod, quantity: 1, customer: { name: 'User', phone: '0812' } }) }); const d = await res.json(); if(d.payment_url) window.location.href = d.payment_url; }); } }); <\/script>`;

    return c.html(`<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${page.title}</title><script src="https://cdn.tailwindcss.com"><\/script><script>${tailwindConfig}<\/script><style>${bridgeCSS}${page.css_content}</style></head><body>${page.html_content}<script>window.PAGE_ID=${page.id};<\/script>${liveScripts}</body></html>`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));

// ===============================================
// 9. CRON SYNC & EXPORT
// ===============================================
async function syncAnalyticsToDB(env) {
    const query = `SELECT blob1 AS slug, count() AS total_hits FROM paslanding_event WHERE timestamp > NOW() - INTERVAL '6' HOUR GROUP BY slug`;
    try {
        const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}` },
            body: query
        });
        const result = await response.json();
        if (result.data) {
            for (const row of result.data) {
                const cleanSlug = row.slug.replace(/^\/|\/$/g, '');
                if (cleanSlug) {
                    await env.DB.prepare(`UPDATE pages SET views_count = COALESCE(views_count, 0) + ? WHERE slug = ?`).bind(row.total_hits, cleanSlug).run();
                }
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
