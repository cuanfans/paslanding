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
    const credRow = await c.env.DB.prepare(
        `SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`
    ).bind(providerSlug).first();

    if (!credRow) throw new Error(`Credentials untuk '${providerSlug}' belum disetting.`);
    
    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
    const decryptedText = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
    const creds = typeof decryptedText === 'string' ? JSON.parse(decryptedText) : decryptedText;

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
            headers: { 
                "Content-Type": "application/json", 
                "x-relay-auth": RELAY_SECRET // Sesuai hasil test PHP lo
            },
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
        // Tambahkan phone_clean & customer_id otomatis untuk FlashPay VA
        payload.customer.phone_clean = payload.customer?.phone?.replace(/[^0-9]/g, '') || '08123456789';
        payload.customer.customer_id = payload.customer.phone_clean; 
    }
    
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = JSON.parse(template.headers_json || '{}');
    headersFinal = { ...headersFinal, ...extraHeaders }; 

    // KIRIM REQUEST (Via Relay jika FlashPay)
    let res;
    if (slug.includes('flashpay')) {
        res = await fetch(RELAY_URL, {
            method: 'POST',
            headers: { "Content-Type": "application/json", "x-relay-auth": RELAY_SECRET },
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
        path === '/' || path === '/login' || path === '/api/login' ||
        path === '/api/setup-first-user' || path.startsWith('/api/public/') || 
        path.startsWith('/api/webhook/') || path.includes('.')
    );

    if (whitelisted && !path.startsWith('/_views')) {
        await next();
        return;
    }

    let token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.split(' ')[1];
    if (!token) return path.startsWith('/api/') ? c.json({ error: 'Unauthorized' }, 401) : c.redirect('/login');

    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const payload = await verify(token, secret, 'HS256');
        c.set('user', payload);
        await next();
    } catch (e) {
        deleteCookie(c, 'auth_token');
        return path.startsWith('/api/') ? c.json({ error: 'Invalid Token' }, 401) : c.redirect('/login');
    }
};

app.use('*', requireAuth); 

// ===============================================
// 4. AUTH & ADMIN API (Gue Skip Detail biar cukup space)
// ===============================================
app.post('/api/login', async (c) => {
    const { email, password } = await c.req.json();
    const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user || await sha256(password) !== user.password) return c.json({ success: false, message: 'Auth Gagal' }, 401);
    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
    const token = await sign({ id: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 86400 }, secret, 'HS256');
    setCookie(c, 'auth_token', token, { path: '/', secure: true, httpOnly: true });
    return c.json({ success: true, token });
});

// --- API: CREDENTIALS (Wajib Pakai encryptJSON) ---
app.post('/api/admin/credentials', async (c) => {
    const { provider, data } = await c.req.json();
    const { encrypted, iv } = await encryptJSON(data, c.env.APP_MASTER_KEY || JWT_SECRET);
    await c.env.DB.prepare(`INSERT INTO credentials (provider_slug, encrypted_data, iv) VALUES (?, ?, ?) ON CONFLICT(provider_slug) DO UPDATE SET encrypted_data=excluded.encrypted_data, iv=excluded.iv`).bind(provider, encrypted, iv).run();
    return c.json({ success: true });
});

// ===============================================
// 6. PUBLIC CUSTOMER API (CHECKOUT DINAMIS)
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        
        // --- AMBIL DATA HARGA DARI DB BIAR PAYLOAD GAK KOSONG ---
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page?.product_config_json || '{}');
        
        // Injeksi data tambahan ke body sebelum ke engine
        body.amount = config.price || 150000; // Harga dari database
        body.order_id = "INV-" + Date.now();
        body.customer_name = body.customer?.name || "Customer";
        body.customer_phone = body.customer?.phone || "0812";

        const result = await executeGenericAPI(c, 'payment', body.slug_payment, body);
        
        // Cari URL di mapping utama atau di data mentah (_raw)
        const finalUrl = result.payment_url || result._raw?.data?.payment_url || result._raw?.payment_url;

        if (!finalUrl) {
            return c.json({ error: "Backend OK tapi Link Bayar Kosong", debug: result._raw }, 400);
        }

        // KIRIM DENGAN UNDERSCORE
        return c.json({ payment_url: finalUrl });

    } catch (e) {
        return c.json({ error: e.message }, 500);
    }
});

// ===============================================
// 8. PUBLIC PAGE RENDERING
// ===============================================
app.get('/:slug', async (c) => {
    const slug = c.req.param('slug');
    if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
    if(!page) return c.text('404', 404);
    return renderPage(c, page);
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const activePayments = config.active_payments || [];
    
    const checkoutScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            if (!document.body.innerHTML.includes('[ CHECKOUT ]')) return;
            const activeSlugs = ${JSON.stringify(activePayments)};
            let listHTML = activeSlugs.map(s => \`
                <label class="flex items-center p-3 border rounded-lg mb-2 cursor-pointer hover:bg-gray-50">
                    <input type="radio" name="pay_method" value="\${s}" class="mr-3">
                    <span class="font-bold text-sm uppercase">\${s.replace(/-/g,' ')}</span>
                </label>\`).join('');

            const formHTML = \`
                <div class="max-w-md mx-auto p-6 bg-white rounded-xl shadow-lg border">
                    <input type="text" id="c_name" placeholder="Nama" class="w-full mb-2 p-2 border rounded">
                    <input type="tel" id="c_phone" placeholder="WhatsApp" class="w-full mb-4 p-2 border rounded">
                    <div class="mb-4">\${listHTML}</div>
                    <button id="btn-pay" class="w-full p-3 bg-blue-600 text-white font-bold rounded">BAYAR SEKARANG</button>
                </div>\`;

            document.body.innerHTML = document.body.innerHTML.replace('[ CHECKOUT ]', formHTML);

            // Di dalam renderPage -> checkoutScript
document.getElementById('btn-pay').onclick = async () => {
    const method = document.querySelector('input[name="pay_method"]:checked')?.value;
    if(!method) return alert('Pilih pembayaran!');

    const btn = document.getElementById('btn-pay');
    btn.disabled = true; 
    btn.innerText = 'MEMPROSES...';
    
    try {
        const res = await fetch('/api/public/checkout', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                page_id: window.PAGE_ID,
                slug_payment: method,
                customer: { 
                    name: document.getElementById('c_name').value, 
                    phone: document.getElementById('c_phone').value 
                }
            })
        });

        const data = await res.json();
        console.log("Response dari Backend:", data); // LIHAT DI INSPECT ELEMENT -> CONSOLE

        if (data.payment_url) {
            // REDIRECT SEKARANG!
            window.location.href = data.payment_url;
        } else {
            alert('Gagal: ' + (data.error || 'Cek Console'));
            btn.disabled = false;
            btn.innerText = 'BAYAR SEKARANG';
        }
    } catch (err) {
        alert('Crash: ' + err.message);
        btn.disabled = false;
        btn.innerText = 'BAYAR SEKARANG';
    }
};
        });
    </script>`;

    return c.html(\`<!DOCTYPE html><html><head><title>\${page.title}</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body>\${page.html_content}<script>window.PAGE_ID=\${page.id}</script>\${checkoutScript}</body></html>\`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
