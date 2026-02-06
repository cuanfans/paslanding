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
    
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(
        `SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`
    ).bind(providerSlug).first();

    if (!credRow) throw new Error(`Credentials untuk '${providerSlug}' belum disetting.`);
    
    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
    const decryptedText = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
    const creds = typeof decryptedText === 'string' ? JSON.parse(decryptedText) : decryptedText;

    let extraHeaders = {};
    
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
                "x-relay-auth": RELAY_SECRET 
            },
            body: JSON.stringify(authPayload)
        });
        
        const authData = await authRes.json();
        const token = authData?.data?.token;
        if (!token) throw new Error("Gagal ambil Token FlashPay via Relay: " + JSON.stringify(authData));
        
        extraHeaders['Authorization'] = `Bearer ${token}`;
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
    if (slug.includes('flashpay')) {
        payload.customer.phone_clean = payload.customer?.phone?.replace(/[^0-9]/g, '') || '08123456789';
        payload.customer.customer_id = payload.customer.phone_clean; 
    }
    
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = JSON.parse(template.headers_json || '{}');
    headersFinal = { ...headersFinal, ...extraHeaders }; 

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
// 2. GLOBAL HANDLERS
// ===============================================
app.onError((err, c) => {
    console.error(`[ERROR] ${err.message}`);
    return c.json({ success: false, message: err.message }, 500);
});

async function serveAsset(c, path) {
    try {
        const url = new URL(path, c.req.url);
        const response = await c.env.ASSETS.fetch(url);
        return response;
    } catch (e) { return c.text('Not Found', 404); }
}

const requireAuth = async (c, next) => {
    const path = new URL(c.req.url).pathname;
    const whitelisted = (path === '/' || path === '/login' || path.startsWith('/api/public/') || path.includes('.'));
    if (whitelisted) return await next();
    
    const token = getCookie(c, 'auth_token');
    if (!token) return c.redirect('/login');
    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        await verify(token, secret, 'HS256');
        await next();
    } catch (e) { return c.redirect('/login'); }
};

app.use('*', requireAuth);

// ===============================================
// 4. ADMIN API
// ===============================================
app.post('/api/login', async (c) => {
    const { email, password } = await c.req.json();
    const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user || await sha256(password) !== user.password) return c.json({ success: false }, 401);
    const token = await sign({ id: user.id, exp: Math.floor(Date.now() / 1000) + 86400 }, c.env.APP_MASTER_KEY || JWT_SECRET, 'HS256');
    setCookie(c, 'auth_token', token, { path: '/', secure: true, httpOnly: true });
    return c.json({ success: true, token });
});

app.post('/api/admin/credentials', async (c) => {
    const { provider, data } = await c.req.json();
    const { encrypted, iv } = await encryptJSON(data, c.env.APP_MASTER_KEY || JWT_SECRET);
    await c.env.DB.prepare(`INSERT INTO credentials (provider_slug, encrypted_data, iv) VALUES (?, ?, ?) ON CONFLICT(provider_slug) DO UPDATE SET encrypted_data=excluded.encrypted_data, iv=excluded.iv`).bind(provider, encrypted, iv).run();
    return c.json({ success: true });
});

// ===============================================
// 6. PUBLIC CHECKOUT (REDIRECT FIXED)
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        
        // 1. Tarik Data Page buat dapetin Harga & Config
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        if (!page) return c.json({ error: "Halaman tidak ditemukan" }, 404);
        
        const config = JSON.parse(page.product_config_json || '{}');
        
        // 2. Perkaya Payload (Wajib buat FlashPay)
        body.amount = config.price || 150000;
        body.order_id = "INV-" + Date.now();
        body.customer_name = body.customer?.name || "Customer";
        body.customer_phone = body.customer?.phone || "0812";
        body.customer_email = "customer@mail.com";

        // 3. Eksekusi API
        const result = await executeGenericAPI(c, 'payment', body.slug_payment, body);
        
        // 4. Ambil URL (Cek mapping atau raw)
        const payment_url = result.payment_url || result._raw?.data?.payment_url || result._raw?.payment_url;

        if (!payment_url) {
            return c.json({ error: "Link pembayaran tidak ditemukan", debug: result._raw }, 400);
        }

        return c.json({ payment_url });
    } catch (e) {
        return c.json({ error: e.message }, 500);
    }
});

// ===============================================
// 8. PAGE RENDERING (FRONTEND SCRIPT FIXED)
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
            const container = document.body;
            if (!container.innerHTML.includes('[ CHECKOUT ]')) return;

            const activeSlugs = ${JSON.stringify(activePayments)};
            let listHTML = activeSlugs.map(s => \`
                <label class="flex items-center p-3 border rounded-lg mb-2 cursor-pointer hover:bg-gray-50 border-gray-200">
                    <input type="radio" name="pay_method" value="\${s}" class="mr-3 w-4 h-4">
                    <span class="font-bold text-xs uppercase text-gray-700">\${s.replace(/-/g,' ')}</span>
                </label>\`).join('');

            const formHTML = \`
                <div class="max-w-md mx-auto my-10 p-8 bg-white rounded-2xl shadow-2xl border border-gray-100">
                    <h2 class="text-xl font-black mb-6 text-gray-800">CHECKOUT</h2>
                    <input type="text" id="c_name" placeholder="Nama Lengkap" class="w-full mb-3 p-3 bg-gray-50 border rounded-lg outline-none focus:border-blue-500">
                    <input type="tel" id="c_phone" placeholder="Nomor WhatsApp" class="w-full mb-6 p-3 bg-gray-50 border rounded-lg outline-none focus:border-blue-500">
                    <div class="mb-6">\${listHTML}</div>
                    <button id="btn-pay" class="w-full p-4 bg-blue-600 text-white font-black rounded-xl shadow-lg hover:bg-blue-700 transition active:scale-95">BAYAR SEKARANG</button>
                </div>\`;

            container.innerHTML = container.innerHTML.replace('[ CHECKOUT ]', formHTML);

            document.getElementById('btn-pay').onclick = async () => {
                const method = document.querySelector('input[name="pay_method"]:checked')?.value;
                const name = document.getElementById('c_name').value;
                const phone = document.getElementById('c_phone').value;

                if(!name || !phone || !method) return alert('Lengkapi data dan pilih pembayaran!');
                
                const btn = document.getElementById('btn-pay');
                btn.disabled = true; btn.innerText = 'MEMPROSES...';
                
                try {
                    const res = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            page_id: ${page.id},
                            slug_payment: method,
                            customer: { name, phone }
                        })
                    });
                    const data = await res.json();
                    if(data.payment_url) {
                        window.location.href = data.payment_url;
                    } else {
                        alert('Error: ' + (data.error || 'Gagal'));
                        btn.disabled = false; btn.innerText = 'BAYAR SEKARANG';
                    }
                } catch(e) {
                    alert('Crash: ' + e.message);
                    btn.disabled = false; btn.innerText = 'BAYAR SEKARANG';
                }
            };
        });
    </script>`;

    return c.html(\`<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>\${page.title}</title><script src="https://cdn.tailwindcss.com"></script><style>\${page.css_content}</style></head>
    <body class="antialiased">\${page.html_content}<script>window.PAGE_ID=\${page.id}</script>\${checkoutScript}</body></html>\`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
