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
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials untuk '${providerSlug}' belum disetting.`);

    let creds;
    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const decrypted = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
        creds = typeof decrypted === 'string' ? JSON.parse(decrypted) : decrypted;
    } catch (e) {
        throw new Error("Gagal dekripsi kredensial: " + e.message);
    }

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
            headers: { "Content-Type": "application/json", "x-relay-auth": RELAY_SECRET },
            body: JSON.stringify(authPayload)
        });
        
        const authData = await authRes.json();
        if (!authRes.ok || !authData?.data?.token) throw new Error("FlashPay Auth Fail via Relay");
        
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
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
    if (slug.includes('flashpay') && payload.customer?.phone) {
        payload.customer.phone_clean = payload.customer.phone.replace(/[^0-9]/g, '');
    }
    
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = { ...JSON.parse(template.headers_json || '{}'), ...extraHeaders }; 

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
        if (path.endsWith('.html')) {
            const newRes = new Response(response.body, response);
            newRes.headers.set('Cache-Control', 'no-store, max-age=0');
            return newRes;
        }
        return response;
    } catch (e) { return c.text('Not Found', 404); }
}

// ===============================================
// 3. MIDDLEWARE & AUTH
// ===============================================
const requireAuth = async (c, next) => {
    const path = new URL(c.req.url).pathname;
    const isPublic = (
        path === '/' || path === '/login' || path === '/api/login' ||
        path.startsWith('/api/public/') || path.includes('.')
    );

    if (isPublic) return await next();

    const token = getCookie(c, 'auth_token');
    if (!token) return c.redirect('/login');

    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        await verify(token, secret, 'HS256');
        await next();
    } catch (e) {
        deleteCookie(c, 'auth_token');
        return c.redirect('/login');
    }
};

app.use('*', requireAuth);

// ===============================================
// 4. ROUTES
// ===============================================
app.get('/login', (c) => serveAsset(c, '/login.html'));

app.post('/api/login', async (c) => {
    try {
        const { email, password } = await c.req.json();
        const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (!user || await sha256(password) !== user.password) {
            return c.json({ success: false, message: 'Email atau Password salah' }, 401);
        }
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const token = await sign({ id: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 86400 }, secret, 'HS256');
        setCookie(c, 'auth_token', token, { path: '/', secure: true, httpOnly: true, maxAge: 86400, sameSite: 'Lax' });
        return c.json({ success: true, token });
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

app.get('/api/logout', (c) => { deleteCookie(c, 'auth_token'); return c.redirect('/login'); });

// --- ADMIN API ---
app.get('/api/admin/pages', async (c) => {
    const res = await c.env.DB.prepare("SELECT * FROM pages ORDER BY created_at DESC").all();
    return c.json(res.results);
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

// --- PUBLIC API ---
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const result = await executeGenericAPI(c, 'payment', body.slug_payment, body);
        return c.json({ payment_url: result.payment_url || result._raw?.data?.payment_url });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

// ===============================================
// 8. PAGE RENDERING
// ===============================================
app.get('/:slug', async (c) => {
    const slug = c.req.param('slug');
    if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
    if(!page) return c.text('404 Not Found', 404);
    return renderPage(c, page);
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const activePayments = config.active_payments || [];
    const checkoutScript = `<script>
        document.addEventListener('DOMContentLoaded', () => {
            if (!document.body.innerHTML.includes('[ CHECKOUT ]')) return;
            const slugs = ${JSON.stringify(activePayments)};
            let list = slugs.map(s => \`<label class="flex items-center p-3 border rounded-lg mb-2"><input type="radio" name="pay_method" value="\${s}" class="mr-3"><span class="uppercase">\${s.replace(/-/g,' ')}</span></label>\`).join('');
            document.body.innerHTML = document.body.innerHTML.replace('[ CHECKOUT ]', \`<div class="max-w-md mx-auto p-6 bg-white rounded-xl shadow-lg border">
                <input type="text" id="cn" placeholder="Nama" class="w-full mb-2 p-3 border rounded">
                <input type="tel" id="cp" placeholder="WhatsApp" class="w-full mb-4 p-3 border rounded">
                <div class="mb-4">\${list}</div>
                <button id="bp" class="w-full p-4 bg-blue-600 text-white font-bold rounded-xl">BAYAR SEKARANG</button>
            </div>\`);
            document.getElementById('bp').onclick = async () => {
                const m = document.querySelector('input[name="pay_method"]:checked')?.value;
                if(!m) return alert('Pilih metode!');
                const res = await fetch('/api/public/checkout', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ page_id: ${page.id}, slug_payment: m, customer: { name: document.getElementById('cn').value, phone: document.getElementById('cp').value } })
                });
                const data = await res.json();
                if(data.payment_url) window.location.href = data.payment_url;
                else alert(data.error || 'Gagal');
            };
        });
    </script>`;
    
    return c.html(\`<!DOCTYPE html><html><head><title>\${page.title}</title><script src="https://cdn.tailwindcss.com"></script><style>\${page.css_content}</style></head>
    <body>\${page.html_content}<script>window.PAGE_ID=\${page.id}</script>\${checkoutScript}</body></html>\`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
