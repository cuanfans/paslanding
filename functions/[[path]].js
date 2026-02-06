import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import { sha256, encryptJSON, decryptJSON } from '../src/utils'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'
const RELAY_URL = "https://pasdigi-relay.hf.space/proxy";
const RELAY_SECRET = "BantarCaringin1";

// =============================================================
// 1. ENGINE PEMBAYARAN (VA & QRIS)
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
    
    // Dekripsi menggunakan APP_MASTER_KEY
    const decrypted = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
    const creds = typeof decrypted === 'string' ? JSON.parse(decrypted) : decrypted;

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
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
    }

    const transactionAmount = Number(payload.amount);
    const finalPayload = {
        external_id: "INV-" + Date.now(),
        payment_type: [slug.toUpperCase().replace(/-/g, '_')],
        currency: "IDR",
        transaction_amount: transactionAmount,
        customer_id: String(payload.customer_phone).replace(/[^0-9]/g, ''),
        va_type: "CLOSE_AMOUNT",
        va_reusability: "SINGLE_USE",
        customer_details: {
            name: payload.customer_name,
            email: "customer@mail.com",
            phone: payload.customer_phone,
            address: "Jl.In",
            postal_code: "13930"
        },
        item_details: [{
            item_id: "ITEM-01",
            information: "Order " + slug,
            amount: transactionAmount,
            beneficiary_bank: "MNC",
            beneficiary_account: "5279910282",
            beneficiary_name: "PASDIGI"
        }]
    };

    const res = await fetch(RELAY_URL, {
        method: 'POST',
        headers: { "Content-Type": "application/json", "x-relay-auth": RELAY_SECRET },
        body: JSON.stringify({
            target_url: "https://sandbox-secure.flashmobile.id/payment/api/v1/create",
            target_method: "POST",
            target_headers: { "Accept": "application/json", "Content-Type": "application/json", ...extraHeaders },
            target_payload: finalPayload
        })
    });

    return { _raw: await res.json(), amount: transactionAmount };
}

// ===============================================
// 2. HELPER: SERVE ASSETS (FIXED LOGIN 404)
// ===============================================
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
// 3. MIDDLEWARE & AUTH (WHIETLIST LOGIN)
// ===============================================
const requireAuth = async (c, next) => {
    const path = new URL(c.req.url).pathname;
    
    // Akses publik yang diizinkan
    const isPublic = (
        path === '/' || 
        path === '/login' || 
        path === '/api/login' || 
        path.startsWith('/api/public/') || 
        path.includes('.')
    );

    if (whitelisted) return await next();

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

// ROUTE LOGIN (MELAYANI FILE login.html)
app.get('/login', (c) => serveAsset(c, '/login.html'));

// API LOGIN (MENGGUNAKAN SHA-256)
app.post('/api/login', async (c) => {
    try {
        const { email, password } = await c.req.json();
        const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        
        // Verifikasi password dengan SHA-256
        const hashedInput = await sha256(password);
        if (!user || hashedInput !== user.password) {
            return c.json({ success: false, message: 'Kredensial salah' }, 401);
        }

        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const token = await sign({ id: user.id, exp: Math.floor(Date.now() / 1000) + 86400 }, secret, 'HS256');
        
        setCookie(c, 'auth_token', token, { 
            path: '/', secure: true, httpOnly: true, maxAge: 86400, sameSite: 'Lax' 
        });

        return c.json({ success: true, token });
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

// ===============================================
// 6. PUBLIC CHECKOUT (Dinamis sesuai Editor)
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page.product_config_json || '{}');
        
        // Ambil harga asli dari pilihan varian di editor
        let finalPrice = (config.variants && config.variants[body.variant_index]) 
            ? Number(config.variants[body.variant_index].price) 
            : Number(config.price || 0);

        if (finalPrice <= 0) return c.json({ error: "Harga tidak valid di editor!" }, 400);

        const result = await executeGenericAPI(c, 'payment', body.slug_payment, {
            amount: finalPrice,
            customer_name: body.customer?.name || "Customer",
            customer_phone: body.customer?.phone || "0812312312"
        });

        const d = result._raw.data;
        const va = d?.payment_code || d?.va_number;
        const qr = d?.qr_string || d?.qr_url;

        if (va || qr) {
            return c.json({ success: true, type: va ? 'va' : 'qris', data: va || qr, amount: finalPrice });
        }
        return c.json({ success: false, error: "Gagal memproses", debug: result._raw }, 400);
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

// ===============================================
// 8. PAGE RENDERING
// ===============================================
app.get('/:slug', async (c) => {
    const slug = c.req.param('slug');
    if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
    return page ? renderPage(c, page) : c.text('404 Not Found', 404);
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const checkoutScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const cont = document.body;
            if (!cont.innerHTML.includes('[ CHECKOUT ]')) return;
            const config = ${JSON.stringify(config)};
            
            // Render Varian (Price List)
            let vHTML = (config.variants || []).map((v, i) => \`
                <label class="flex justify-between items-center p-4 border rounded-2xl mb-2 cursor-pointer border-gray-100 hover:border-blue-500 transition">
                    <span><input type="radio" name="v_idx" value="\${i}" \${i===0?'checked':''} class="mr-2">\${v.name}</span>
                    <span class="font-bold text-blue-600 italic">Rp \${new Intl.NumberFormat('id-ID').format(v.price)}</span>
                </label>\`).join('');
            
            // Render Payment Methods
            let pHTML = (config.active_payments || []).map(s => \`
                <label class="flex items-center p-3 border rounded-xl mb-2 cursor-pointer border-gray-100 uppercase text-[10px] font-bold">
                    <input type="radio" name="p_slug" value="\${s}" class="mr-2">\${s.replace(/-/g,' ')}
                </label>\`).join('');

            cont.innerHTML = cont.innerHTML.replace('[ CHECKOUT ]', \`
                <div id="checkout-box" class="max-w-md mx-auto my-10 p-8 bg-white rounded-[2rem] shadow-2xl border">
                    <div id="inner-checkout">
                        <h2 class="text-xl font-black mb-6 text-center uppercase">Pembayaran</h2>
                        <div class="mb-6">\${vHTML}</div>
                        <input type="text" id="cn" placeholder="Nama Lengkap" class="w-full mb-3 p-4 bg-gray-50 border rounded-xl outline-none">
                        <input type="tel" id="cp" placeholder="WhatsApp" class="w-full mb-6 p-4 bg-gray-50 border rounded-xl outline-none">
                        <div class="mb-6">\${pHTML}</div>
                        <button id="btn-p" class="w-full p-4 bg-blue-600 text-white font-black rounded-xl uppercase shadow-lg shadow-blue-100">Bayar Sekarang</button>
                    </div>
                </div>\`);

            document.getElementById('btn-p').onclick = async () => {
                const b = document.getElementById('btn-p');
                const m = document.querySelector('input[name="p_slug"]:checked')?.value;
                if(!m) return alert('Pilih metode pembayaran!');
                b.disabled = true; b.innerText = 'PROSES...';
                try {
                    const r = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ 
                            page_id: ${page.id}, 
                            slug_payment: m, 
                            variant_index: document.querySelector('input[name="v_idx"]:checked')?.value,
                            customer: { name: document.getElementById('cn').value, phone: document.getElementById('cp').value } 
                        })
                    });
                    const d = await r.json();
                    if(d.success) {
                        let ui = d.type === 'va' 
                            ? \`<div class="bg-blue-50 p-6 rounded-2xl border border-dashed text-xl font-black text-blue-700 tracking-widest mb-4">\${d.data}</div>\` 
                            : \`<div class="mb-4 flex justify-center"><img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=\${encodeURIComponent(d.data)}" class="border-4 p-2 rounded-xl"></div>\`;
                        document.getElementById('inner-checkout').innerHTML = \`
                            <div class="text-center">
                                <h3 class="font-bold mb-4 uppercase text-xs text-gray-400">Instruksi Pembayaran</h3>
                                \${ui}
                                <div class="text-lg font-black">Rp \${new Intl.NumberFormat('id-ID').format(d.amount)}</div>
                            </div>\`;
                    } else alert(d.error);
                } catch(e) { alert('Sistem Error'); } finally { b.disabled = false; b.innerText = 'BAYAR SEKARANG'; }
            };
        });
    </script>`;
    return c.html("<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script><style>" + page.css_content + "</style></head><body>" + page.html_content + "<script>window.PAGE_ID=" + page.id + "</script>" + checkoutScript + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
