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
    
    // 1. Ambil Template
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    // 2. Ambil Credentials
    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(
        `SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`
    ).bind(providerSlug).first();

    if (!credRow) throw new Error(`Credentials untuk '${providerSlug}' belum disetting.`);

    // 3. Dekripsi Data
    let creds;
    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const decrypted = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
        creds = typeof decrypted === 'string' ? JSON.parse(decrypted) : decrypted;
    } catch (e) {
        throw new Error("Gagal dekripsi kredensial: " + e.message);
    }

    let extraHeaders = {};
    
    // --- LOGIKA KHUSUS FLASHPAY (AUTO AUTH VIA RELAY) ---
    if (slug.includes('flashpay')) {
        const authPayload = {
            target_url: "https://sandbox-secure.flashmobile.id/auth/v2/access-token",
            target_method: "POST",
            target_headers: { "Accept": "application/json", "Content-Type": "application/json" },
            target_payload: { 
                client_key: creds.client_key, 
                server_key: creds.server_key 
            }
        };

        const authRes = await fetch(RELAY_URL, {
            method: 'POST',
            headers: { 
                "Content-Type": "application/json", 
                "x-relay-auth": RELAY_SECRET
            },
            body: JSON.stringify(authPayload)
        });
        
        const authData = await authRes.json();
        
        if (!authRes.ok || !authData?.data?.token) {
            throw new Error(`Relay Auth Fail: ` + JSON.stringify(authData));
        }
        
        const token = authData.data.token;
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
        if (payload.customer?.phone) {
            payload.customer.phone_clean = payload.customer.phone.replace(/[^0-9]/g, '');
        }
    }
    
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = JSON.parse(template.headers_json || '{}');
    headersFinal = { ...headersFinal, ...extraHeaders }; 

    // KIRIM REQUEST KE API TUJUAN
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
        
        // Verifikasi SHA256
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
// 5. ADMIN ROUTES & API
// ===============================================
app.get('/login', (c) => serveAsset(c, '/login.html'));
app.get('/admin', (c) => c.redirect('/admin/dashboard'));
app.get('/admin/*', (c) => serveAsset(c, '/_views' + c.req.path.replace('/admin','').replace(/^\/$/,'/dashboard') + '.html'));

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
// 6. PUBLIC CUSTOMER API
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const { slug_payment, customer } = body;

        if (!slug_payment || !customer?.phone) {
            return c.json({ error: "Data pesanan atau nomor HP tidak lengkap!" }, 400);
        }

        const result = await executeGenericAPI(c, 'payment', slug_payment, body);
        
        return c.json({ 
            payment_url: result.payment_url || result.redirect_url || result._raw?.data?.payment_url 
        });

    } catch (e) { 
        return c.json({ error: "Gagal memproses pesanan: " + e.message }, 500); 
    }
});

// ===============================================
// 8. PUBLIC PAGE RENDERING
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
    const settings = config.settings || {}; 
    const activePayments = config.active_payments || [];
    
    // Checkout Script dengan string yang aman dari backslash error
    const checkoutScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const container = document.body;
            if (!container.innerHTML.includes('[ CHECKOUT ]')) return;

            const activeSlugs = ${JSON.stringify(activePayments)};
            
            let paymentListHTML = activeSlugs.map(slug => 
                '<label class="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-blue-50 transition border-gray-200">' +
                '<input type="radio" name="pay_method" value="' + slug + '" class="mr-3 w-4 h-4 text-blue-600">' +
                '<span class="text-sm font-bold text-gray-700 uppercase">' + slug.split('-').join(' ') + '</span>' +
                '</label>'
            ).join('');

            const formHTML = 
                '<div id="checkout-form-real" class="max-w-md mx-auto my-8 p-6 bg-white rounded-2xl shadow-xl border border-gray-100">' +
                '<h2 class="text-xl font-bold text-gray-800 mb-6">Konfirmasi Pesanan</h2>' +
                '<div class="space-y-4 mb-8">' +
                '<div>' +
                '<label class="text-[10px] font-bold text-gray-400 uppercase">Informasi Pengiriman</label>' +
                '<input type="text" id="c_name" placeholder="Nama Lengkap" class="w-full mt-1 p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500">' +
                '<input type="tel" id="c_phone" placeholder="No. WhatsApp (Aktif)" class="w-full mt-2 p-3 bg-gray-50 border border-gray-200 rounded-lg outline-none focus:border-blue-500">' +
                '</div>' +
                '</div>' +
                '<div class="mb-6">' +
                '<label class="text-[10px] font-bold text-gray-400 uppercase block mb-2">Metode Pembayaran</label>' +
                '<div class="grid gap-2">' + (paymentListHTML || '<p class="text-red-500 text-[10px]">Pilih metode pembayaran di editor!</p>') + '</div>' +
                '</div>' +
                '<button id="btn-submit-order" class="w-full py-4 bg-blue-600 text-white font-black rounded-xl shadow-lg shadow-blue-200 hover:bg-blue-700 transition transform active:scale-95">BAYAR SEKARANG</button>' +
                '</div>';

            container.innerHTML = container.innerHTML.replace('[ CHECKOUT ]', formHTML);

            document.getElementById('btn-submit-order')?.addEventListener('click', async () => {
                const selectedMethod = document.querySelector('input[name="pay_method"]:checked')?.value;
                const name = document.getElementById('c_name').value;
                const phone = document.getElementById('c_phone').value;

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
    
    // Perbaikan: Menggunakan string biasa, bukan template literal untuk return final agar tidak ada backtick yang salah
    return c.html("<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script><style>" + page.css_content + "</style></head><body>" + page.html_content + appScript + checkoutScript + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
