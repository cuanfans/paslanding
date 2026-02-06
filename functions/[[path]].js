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
    await db.prepare(`CREATE TABLE IF NOT EXISTS pages (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE, title TEXT, html_content TEXT, css_content TEXT, product_config_json TEXT, product_type TEXT, provider TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
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

// --- MODULE: PAGES ---
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
        const total = await c.env.DB.prepare("SELECT COUNT(*) as count FROM analytics").first();
        const today = await c.env.DB.prepare("SELECT COUNT(*) as count FROM analytics WHERE date(created_at) = date('now')").first();
        const topPages = await c.env.DB.prepare(`SELECT p.title, p.slug, COUNT(a.id) as views FROM pages p LEFT JOIN analytics a ON p.id = a.page_id GROUP BY p.id ORDER BY views DESC LIMIT 10`).all();
        const recent = await c.env.DB.prepare(`SELECT p.title, a.referrer, a.created_at FROM analytics a JOIN pages p ON a.page_id = p.id ORDER BY a.created_at DESC LIMIT 20`).all();
        
        return c.json({ 
            stats: { total_views: total?.count||0, today_views: today?.count||0 }, 
            top_pages: topPages.results||[], 
            recent: recent.results||[] 
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

// --- PUBLIC CONTACT FORM ---
app.post('/api/public/contact', async (c) => {
    try {
        await initDB(c.env.DB);
        let body;
        const contentType = c.req.header('Content-Type');
        
        if (contentType && contentType.includes('application/json')) {
            body = await c.req.json();
        } else {
            body = await c.req.parseBody();
        }

        const { page_id, subject, name, email, phone, message } = body;

        if (!name || !message) return c.json({ error: "Nama dan Pesan wajib diisi!" }, 400);

        await c.env.DB.prepare(`INSERT INTO messages (page_id, subject, name, email, phone, message) VALUES (?, ?, ?, ?, ?, ?)`)
            .bind(page_id || 0, subject || 'General', name, email || '', phone || '', message)
            .run();

        // Redirect jika form HTML biasa, JSON response jika AJAX
        if (!contentType || !contentType.includes('application/json')) {
            return c.redirect(c.req.header('Referer') + '?status=sent');
        }

        return c.json({ success: true, message: "Pesan terkirim!" });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

// --- PUBLIC CHECKOUT ---
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const { slug_payment, customer, quantity } = body;
        
        if (!slug_payment || !customer?.phone) return c.json({ error: "Data tidak lengkap!" }, 400);

        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page.product_config_json || '{}');

        // --- HITUNG HARGA DI BACKEND ---
        let unitPrice = 0;
        let itemName = page.title;

        // Cek Varian
        if (config.variants && config.variants[body.variant_index]) {
            unitPrice = Number(config.variants[body.variant_index].price);
            itemName += ` (${config.variants[body.variant_index].name})`;
        } else {
            unitPrice = Number(config.price || 0);
        }

        // Cek Qty (Default 1)
        const qty = parseInt(quantity || 1);
        let finalAmount = unitPrice * qty;

        // Cek Bump
        let bumpName = '';
        if (body.take_bump && config.order_bump?.active) {
            const bumpPrice = Number(config.order_bump.price);
            finalAmount += bumpPrice; 
            bumpName = config.order_bump.title;
        }

        // Cek Kupon
        if (body.coupon_code && config.coupons) {
            const cp = config.coupons.find(x => x.code.toUpperCase() === body.coupon_code.toUpperCase());
            if (cp) {
                const disc = cp.type === 'percent' ? (finalAmount * cp.value / 100) : cp.value;
                finalAmount = Math.max(0, finalAmount - disc);
            }
        }
        
        // Update Payload
        const apiPayload = {
            ...body,
            amount: finalAmount, 
            item_name: itemName + (qty > 1 ? ` (x${qty})` : ''),
            bump_name: bumpName
        };

        const result = await executeGenericAPI(c, 'payment', slug_payment, apiPayload);
        return c.json({ payment_url: result.payment_url || result._raw?.data?.payment_url });

    } catch (e) { return c.json({ error: "Proses Gagal: " + e.message }, 500); }
});

// ===============================================
// 7. PAGE RENDERING
// ===============================================
app.get('/:slug', async (c) => {
    try {
        const slug = c.req.param('slug');
        if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
        if(!page) return c.text('404 Not Found', 404);

        // TRACK ANALYTICS
        c.env.DB.prepare("INSERT INTO analytics (page_id, event_type, referrer) VALUES (?, 'view', ?)").bind(page.id, c.req.header('Referer') || 'direct').run().catch(()=>{});

        return renderPage(c, page);
    } catch(e) { return c.env.ASSETS.fetch(c.req.raw); }
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const activePayments = config.active_payments || [];
    
    // Inject Notification Script untuk Pesan
    const msgScript = `
    <script>
        if(new URLSearchParams(window.location.search).get('status') === 'sent') {
            alert('Pesan Anda telah kami terima! Kami akan segera menghubungi Anda.');
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    </script>
    `;

    // Checkout Script (Logic Kalkulator & Qty)
    const checkoutScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const container = document.body;
            if (!container.innerHTML.includes('[ CHECKOUT ]')) return;

            const config = ${JSON.stringify(config)};
            
            // --- RENDER VARIAN ---
            let productHTML = '';
            if (config.variants && config.variants.length > 0) {
                productHTML = config.variants.map((v, i) => \`
                    <label class="flex justify-between items-center p-4 border rounded-2xl mb-2 cursor-pointer border-gray-100 hover:border-blue-500 transition shadow-sm bg-white">
                        <div class="flex items-center">
                            <input type="radio" name="v_idx" value="\${i}" \${i===0?'checked':''} class="mr-3 w-5 h-5 text-blue-600" onchange="updateCalc()">
                            <div>
                                <div class="font-bold text-gray-800 text-sm">\${v.name}</div>
                            </div>
                        </div>
                        <div class="font-black text-blue-600">Rp \${new Intl.NumberFormat('id-ID').format(v.price)}</div>
                    </label>\`).join('');
            } else {
                 productHTML = \`
                    <div class="flex justify-between items-center p-4 bg-blue-50 rounded-xl border border-blue-100 mb-4">
                        <span class="font-bold text-blue-900">\${page.title}</span>
                        <span class="font-black text-blue-700">Rp \${new Intl.NumberFormat('id-ID').format(config.price)}</span>
                    </div>\`;
            }

            // --- RENDER PAYMENT ---
            const activeSlugs = ${JSON.stringify(activePayments)};
            let paymentListHTML = activeSlugs.map(slug => 
                '<label class="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-blue-50 transition border-gray-200 mb-2">' +
                '<input type="radio" name="pay_method" value="' + slug + '" class="mr-3 w-4 h-4 text-blue-600">' +
                '<span class="text-sm font-bold text-gray-700 uppercase">' + slug.split('-').join(' ') + '</span>' +
                '</label>'
            ).join('');

            // --- BUMP HTML ---
            let bumpHTML = '';
            if (config.order_bump?.active) {
                bumpHTML = \`
                <div class="bg-yellow-50 border-2 border-dashed border-yellow-400 p-4 rounded-xl mb-6 relative mt-4">
                    <div class="absolute top-0 right-0 bg-red-600 text-white text-[9px] px-2 py-1 rounded-bl-lg font-bold">PENWARAN TERBATAS</div>
                    <label class="flex items-start cursor-pointer">
                        <input type="checkbox" id="take_bump" class="mt-1 mr-3 w-5 h-5 text-blue-600 rounded" onchange="updateCalc()">
                        <div>
                            <div class="font-black text-gray-800 text-sm">\${config.order_bump.title}</div>
                            <p class="text-xs text-gray-600 mt-1">\${config.order_bump.desc}</p>
                            <div class="text-red-600 font-bold text-sm mt-1">+ Rp \${new Intl.NumberFormat('id-ID').format(config.order_bump.price)}</div>
                        </div>
                    </label>
                </div>\`;
            }

            const formHTML = \`
                <div id="checkout-form-real" class="max-w-md mx-auto my-8 p-6 bg-white rounded-2xl shadow-xl border border-gray-100 font-sans">
                    <h2 class="text-xl font-black text-gray-800 mb-6 text-center uppercase tracking-tight">Formulir Pemesanan</h2>
                    
                    <div class="mb-2">\${productHTML}</div>

                    <div class="flex items-center justify-between mb-6 p-3 border rounded-xl bg-gray-50">
                        <span class="text-xs font-bold text-gray-500 uppercase">Jumlah Pesanan</span>
                        <div class="flex items-center bg-white rounded-lg border shadow-sm">
                            <button onclick="changeQty(-1)" class="px-3 py-1 text-gray-600 hover:bg-gray-100 rounded-l-lg font-bold text-lg">-</button>
                            <input type="number" id="qty_input" value="1" readonly class="w-12 text-center font-bold text-gray-800 outline-none border-x py-1">
                            <button onclick="changeQty(1)" class="px-3 py-1 text-blue-600 hover:bg-blue-50 rounded-r-lg font-bold text-lg">+</button>
                        </div>
                    </div>

                    \${bumpHTML}

                    <div class="bg-gray-50 p-4 rounded-xl mb-6 border border-gray-200 space-y-2">
                        <div class="flex justify-between text-xs text-gray-500">
                            <span id="summary_item_name">Produk (x1)</span>
                            <span id="summary_item_price" class="font-bold">Rp 0</span>
                        </div>
                        <div id="summary_bump_row" class="flex justify-between text-xs text-gray-500 hidden">
                            <span id="summary_bump_name">Extra</span>
                            <span id="summary_bump_price" class="font-bold">Rp 0</span>
                        </div>
                        <div class="border-t border-gray-300 my-2 pt-2 flex justify-between items-center">
                            <span class="font-bold text-gray-700">Total Pembayaran</span>
                            <span id="summary_total" class="font-black text-xl text-blue-700">Rp 0</span>
                        </div>
                    </div>

                    <div class="space-y-4 mb-8">
                        <div>
                            <label class="text-[10px] font-bold text-gray-400 uppercase">Data Pengiriman</label>
                            <input type="text" id="c_name" placeholder="Nama Lengkap" class="w-full mt-1 p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500">
                            <input type="tel" id="c_phone" placeholder="No. WhatsApp (Aktif)" class="w-full mt-2 p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500">
                        </div>
                    </div>

                    <div class="mb-6">
                        <label class="text-[10px] font-bold text-gray-400 uppercase block mb-2">Metode Pembayaran</label>
                        <div class="grid gap-2">
                            \${paymentListHTML || '<p class="text-red-500 text-[10px]">Pilih metode pembayaran di editor!</p>'}
                        </div>
                    </div>

                    <button id="btn-submit-order" class="w-full py-4 bg-blue-600 text-white font-black rounded-xl shadow-lg shadow-blue-200 hover:bg-blue-700 transition transform active:scale-95 uppercase tracking-widest">
                        BAYAR SEKARANG
                    </button>
                </div>\`;

            container.innerHTML = container.innerHTML.replace('[ CHECKOUT ]', formHTML);

            // --- FUNGSI KALKULATOR ---
            window.changeQty = (delta) => {
                let input = document.getElementById('qty_input');
                let newVal = parseInt(input.value) + delta;
                if(newVal < 1) newVal = 1;
                input.value = newVal;
                updateCalc();
            };

            window.updateCalc = () => {
                // 1. Get Base Price
                let basePrice = ${config.price || 0};
                let productName = "${page.title}";
                
                // Cek Varian
                const vIdx = document.querySelector('input[name="v_idx"]:checked')?.value;
                if(config.variants && config.variants[vIdx]) {
                    basePrice = config.variants[vIdx].price;
                    productName = config.variants[vIdx].name;
                }

                // 2. Get Qty
                const qty = parseInt(document.getElementById('qty_input').value);

                // 3. Subtotal Item
                const subItem = basePrice * qty;

                // 4. Check Bump
                let bumpPrice = 0;
                const bumpRow = document.getElementById('summary_bump_row');
                const takeBump = document.getElementById('take_bump')?.checked;
                
                if (takeBump && config.order_bump?.active) {
                    bumpPrice = config.order_bump.price;
                    document.getElementById('summary_bump_name').innerText = config.order_bump.title;
                    document.getElementById('summary_bump_price').innerText = 'Rp ' + new Intl.NumberFormat('id-ID').format(bumpPrice);
                    bumpRow.classList.remove('hidden');
                } else {
                    bumpRow.classList.add('hidden');
                }

                // 5. Grand Total
                const total = subItem + bumpPrice;

                // 6. Update UI
                document.getElementById('summary_item_name').innerText = productName + ' (x' + qty + ')';
                document.getElementById('summary_item_price').innerText = 'Rp ' + new Intl.NumberFormat('id-ID').format(subItem);
                document.getElementById('summary_total').innerText = 'Rp ' + new Intl.NumberFormat('id-ID').format(total);
            };

            // Init Calculator
            updateCalc();

            // --- SUBMIT ---
            document.getElementById('btn-submit-order')?.addEventListener('click', async () => {
                const selectedMethod = document.querySelector('input[name="pay_method"]:checked')?.value;
                const name = document.getElementById('c_name').value;
                const phone = document.getElementById('c_phone').value;
                const qty = document.getElementById('qty_input').value;
                const vIdx = document.querySelector('input[name="v_idx"]:checked')?.value;
                const takeBump = document.getElementById('take_bump')?.checked;

                if(!name || !phone) return alert('Lengkapi data pengiriman!');
                if(!selectedMethod) return alert('Pilih metode pembayaran!');

                const btn = document.getElementById('btn-submit-order');
                btn.disabled = true;
                btn.innerText = 'MEMPROSES...';

                try {
                    const res = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            page_id: ${page.id},
                            slug_payment: selectedMethod,
                            variant_index: vIdx,
                            quantity: qty,
                            take_bump: takeBump,
                            customer: { name, phone }
                        })
                    });
                    const data = await res.json();
                    if(data.payment_url) window.location.href = data.payment_url;
                    else if(data.error) alert(data.error);
                } catch(e) {
                    alert('Gagal membuat pesanan. Coba lagi.');
                    btn.disabled = false;
                    btn.innerText = 'BAYAR SEKARANG';
                }
            });
        });
    </script>`;

    const appScript = `<script>window.PAGE_ID=${page.id};</script>`;
    
    return c.html("<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script><style>" + page.css_content + "</style></head><body>" + page.html_content + appScript + msgScript + checkoutScript + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
