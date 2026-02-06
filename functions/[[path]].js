import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import { sha256, encryptJSON, decryptJSON } from '../src/utils'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'

// --- KONFIGURASI RELAY ---
const RELAY_URL = "https://pasdigi-relay.hf.space/proxy";
const RELAY_SECRET = "BantarCaringin1";

// =============================================================
// 1. INTERNAL ENGINE (LENGKAP DENGAN LOGGING TOTAL)
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    console.log(`[LOG] Memulai Engine: ${slug}`);
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials untuk ${providerSlug} belum diset.`);
    
    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
    const decryptedText = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
    const creds = typeof decryptedText === 'string' ? JSON.parse(decryptedText) : decryptedText;

    let extraHeaders = {};
    if (slug.includes('flashpay')) {
        console.log(`[LOG] Minta Token FlashPay via Relay...`);
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
        if (!authData?.data?.token) {
            console.error(`[LOG] Gagal Auth:`, authData);
            throw new Error("Gagal Auth FlashPay: " + JSON.stringify(authData));
        }
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
        console.log(`[LOG] Token Berhasil Didapat.`);
    }

    // KONSTRUKSI PAYLOAD SESUAI SPEK DOKUMENTASI VA
    const finalPayload = {
        external_id: "INV-" + Date.now(),
        payment_type: ["VA_BRI"],
        currency: "IDR",
        transaction_amount: Number(payload.amount),
        session_time: "15",
        remark: "Order " + (payload.customer_name || "Guest"),
        customer_id: String(payload.customer_phone).replace(/[^0-9]/g, ''),
        va_type: "CLOSE_AMOUNT",
        va_reusability: "SINGLE_USE",
        customer_details: {
            name: payload.customer_name,
            email: "customer@mail.com",
            phone: payload.customer_phone,
            address: "Jl. In",
            postal_code: "13930"
        }
    };

    console.log(`[LOG] PAYLOAD YANG DIKIRIM KE FLASHMOBILE:`, JSON.stringify(finalPayload, null, 2));

    const res = await fetch(RELAY_URL, {
        method: 'POST',
        headers: { "Content-Type": "application/json", "x-relay-auth": RELAY_SECRET },
        body: JSON.stringify({
            target_url: "https://sandbox-secure.flashmobile.id/payment/api/v1/create",
            target_method: "POST",
            target_headers: { 
                "Accept": "application/json", 
                "Content-Type": "application/json",
                ...extraHeaders
            },
            target_payload: finalPayload
        })
    });

    const resData = await res.json();
    console.log(`[LOG] RESPON MENTAH DARI FLASHMOBILE:`, JSON.stringify(resData, null, 2));

    return { _raw: resData, amount: finalPayload.transaction_amount };
}

// ===============================================
// 2. MIDDLEWARE & AUTH
// ===============================================
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
// 6. PUBLIC CHECKOUT
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        if (!page) return c.json({ error: "Page not found" }, 404);
        
        const config = JSON.parse(page.product_config_json || '{}');
        const payload = {
            slug_payment: body.slug_payment,
            amount: config.price || 170000,
            customer_name: body.customer?.name || "Guest",
            customer_phone: body.customer?.phone || "08123456789"
        };

        const result = await executeGenericAPI(c, 'payment', payload.slug_payment, payload);
        const data = result._raw;

        if (data.code == 200 || data.data?.payment_code || data.data?.va_number) {
            return c.json({
                success: true,
                va: {
                    number: data.data?.payment_code || data.data?.va_number,
                    bank: "BRI VA",
                    amount: result.amount
                }
            });
        }
        return c.json({ success: false, error: data.message || "Gagal", debug: data }, 400);
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

// ===============================================
// 8. PAGE RENDERING
// ===============================================
app.get('/:slug', async (c) => {
    const slug = c.req.param('slug');
    if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
    return page ? renderPage(c, page) : c.text('404', 404);
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const activePayments = config.active_payments || [];
    const checkoutScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const bodyHtml = document.body.innerHTML;
            if (!bodyHtml.includes('[ CHECKOUT ]')) return;
            const slugs = ${JSON.stringify(activePayments)};
            let listHTML = slugs.map(s => \`
                <label class="flex items-center p-3 border rounded-lg mb-2 cursor-pointer border-gray-200">
                    <input type="radio" name="pay_method" value="\${s}" class="mr-3">
                    <span class="font-bold text-xs uppercase">\${s.replace(/-/g,' ')}</span>
                </label>\`).join('');
            
            const formHTML = \`
                <div id="checkout-box" class="max-w-md mx-auto my-10 p-8 bg-white rounded-2xl shadow-xl border">
                    <div id="checkout-form-inner">
                        <h2 class="text-xl font-black mb-6 text-center">CHECKOUT</h2>
                        <input type="text" id="c_name" placeholder="Nama" class="w-full mb-3 p-3 bg-gray-50 border rounded-lg outline-none">
                        <input type="tel" id="c_phone" placeholder="No WA" class="w-full mb-6 p-3 bg-gray-50 border rounded-lg outline-none">
                        <div class="mb-6">\${listHTML}</div>
                        <button id="btn-pay" class="w-full p-4 bg-blue-600 text-white font-black rounded-xl uppercase">Bayar Sekarang</button>
                    </div>
                </div>\`;
            document.body.innerHTML = bodyHtml.replace('[ CHECKOUT ]', formHTML);

            document.getElementById('btn-pay').onclick = async () => {
                const method = document.querySelector('input[name="pay_method"]:checked')?.value;
                if(!method) return alert('Pilih pembayaran!');
                const btn = document.getElementById('btn-pay');
                btn.disabled = true; btn.innerText = 'MEMPROSES...';
                try {
                    const res = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ page_id: ${page.id}, slug_payment: method, customer: { name: document.getElementById('c_name').value, phone: document.getElementById('c_phone').value } })
                    });
                    const data = await res.json();
                    if(data.va) {
                        document.getElementById('checkout-form-inner').innerHTML = \`
                            <div class="text-center">
                                <h3 class="font-bold text-gray-800 mb-4 uppercase">Nomor Virtual Account BRI</h3>
                                <div class="bg-gray-50 p-6 rounded-xl border border-dashed mb-4 border-blue-200">
                                    <div class="text-3xl font-black text-blue-700 tracking-widest">\${data.va.number}</div>
                                </div>
                                <div class="text-lg font-bold uppercase">Total Tagihan: Rp \${new Intl.NumberFormat('id-ID').format(data.va.amount)}</div>
                            </div>\`;
                    } else { alert('Gagal: ' + data.error); console.log(data.debug); btn.disabled = false; btn.innerText = 'BAYAR SEKARANG'; }
                } catch(e) { alert('Error: ' + e.message); btn.disabled = false; }
            };
        });
    </script>`;
    return c.html(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${page.title}</title><script src="https://cdn.tailwindcss.com"></script><style>${page.css_content}</style></head><body>${page.html_content}<script>window.PAGE_ID=${page.id}</script>${checkoutScript}</body></html>`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
