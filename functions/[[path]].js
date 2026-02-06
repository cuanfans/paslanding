import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import { sha256, encryptJSON, decryptJSON } from '../src/utils'
import { uploadImage } from '../src/modules/cloudinary'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'

// --- KONFIGURASI RELAY ---
const RELAY_URL = "https://pasdigi-relay.hf.space/proxy";
const RELAY_SECRET = "BantarCaringin1";

// =============================================================
// 1. INTERNAL ENGINE (SINKRON DENGAN SPEK SUKSES)
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials belum diset.`);
    
    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
    const decryptedText = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
    const creds = typeof decryptedText === 'string' ? JSON.parse(decryptedText) : decryptedText;

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
        const token = authData?.data?.token;
        if (!token) throw new Error("Gagal Auth Token FlashPay");
        extraHeaders['Authorization'] = `Bearer ${token}`;
    }

    const replaceVars = (str) => {
        return str.replace(/{{(.*?)}}/g, (match, key) => {
            const keys = key.trim().split('.');
            let val = payload;
            for (let k of keys) val = val?.[k];
            return val !== undefined ? val : match;
        });
    };

    // KONSTRUKSI PAYLOAD SESUAI SPEK SUKSES
    const transactionAmount = Number(payload.amount);
    const finalPayload = {
        external_id: "INV-" + Date.now(),
        payment_type: ["VA_BRI"],
        currency: "IDR",
        transaction_amount: transactionAmount,
        session_time: "15",
        remark: "Order " + payload.customer_name,
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
        item_details: [
            {
                item_id: "ITEM-01",
                information: "Pembelian Produk",
                amount: transactionAmount,
                beneficiary_bank: "BRI",
                beneficiary_account: "5279910282",
                beneficiary_name: "PASDIGI"
            }
        ]
    };

    const res = await fetch(RELAY_URL, {
        method: 'POST',
        headers: { "Content-Type": "application/json", "x-relay-auth": RELAY_SECRET },
        body: JSON.stringify({
            target_url: template.api_endpoint || "https://sandbox-secure.flashmobile.id/payment/api/v1/create",
            target_method: "POST",
            target_headers: { "Accept": "application/json", "Content-Type": "application/json", ...extraHeaders },
            target_payload: finalPayload
        })
    });

    const resData = await res.json();
    const result = { _raw: resData, amount: transactionAmount };
    
    // Mapping sederhana
    const mapping = JSON.parse(template.response_mapping || '{}');
    const getVal = (path, source) => path.split('.').reduce((o, i) => o?.[i], source);
    for (const [key, path] of Object.entries(mapping)) {
        result[key] = getVal(path, resData) || null;
    }
    return result;
}

// ===============================================
// 3. MIDDLEWARE & AUTH
// ===============================================
const requireAuth = async (c, next) => {
    const path = new URL(c.req.url).pathname;
    const whitelisted = (path === '/' || path === '/login' || path.startsWith('/api/public/') || path.includes('.'));
    if (whitelisted) return await next();
    
    const token = getCookie(c, 'auth_token');
    if (!token) return c.redirect('/login');
    try {
        await verify(token, c.env.APP_MASTER_KEY || JWT_SECRET, 'HS256');
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

// ===============================================
// 6. PUBLIC CHECKOUT (SMART RESPONSE)
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page?.product_config_json || '{}');
        
        const result = await executeGenericAPI(c, 'payment', body.slug_payment, {
            amount: config.price || 170000,
            customer_name: body.customer?.name || "Customer",
            customer_phone: body.customer?.phone || "0812312312"
        });

        const data = result._raw;
        const va_number = data.data?.payment_code || data.data?.va_number;
        const payment_url = result.payment_url || data.data?.payment_url || data.data?.redirect_url;

        if (va_number) {
            return c.json({ success: true, va: { number: va_number, bank: "BRI VA", amount: result.amount } });
        } else if (payment_url) {
            return c.json({ success: true, payment_url });
        }
        
        return c.json({ success: false, error: data.message || "Gagal memproses", debug: data }, 400);
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

// ===============================================
// 8. PAGE RENDERING (SMART UI)
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
            const container = document.body;
            if (!container.innerHTML.includes('[ CHECKOUT ]')) return;
            const slugs = ${JSON.stringify(activePayments)};
            let listHTML = slugs.map(s => \`
                <label class="flex items-center p-4 border rounded-xl mb-3 cursor-pointer hover:bg-blue-50 transition border-gray-200">
                    <input type="radio" name="pay_method" value="\${s}" class="mr-3 w-4 h-4 text-blue-600">
                    <span class="font-bold text-sm uppercase text-gray-700 tracking-tight">\${s.replace(/-/g,' ')}</span>
                </label>\`).join('');
            
            const formHTML = \`
                <div id="checkout-box" class="max-w-md mx-auto my-10 p-8 bg-white rounded-3xl shadow-2xl border border-gray-100">
                    <div id="inner-checkout">
                        <h2 class="text-2xl font-black mb-6 text-gray-800 tracking-tighter">ISI DATA PESANAN</h2>
                        <input type="text" id="cn" placeholder="Nama Lengkap" class="w-full mb-3 p-4 bg-gray-50 border border-gray-200 rounded-xl outline-none focus:border-blue-500 transition">
                        <input type="tel" id="cp" placeholder="Nomor WhatsApp" class="w-full mb-6 p-4 bg-gray-50 border border-gray-200 rounded-xl outline-none focus:border-blue-500 transition">
                        <div class="mb-8">\${listHTML || '<p class="text-red-500 text-xs">Pilih metode pembayaran di editor!</p>'}</div>
                        <button id="btn-p" class="w-full p-5 bg-blue-600 text-white font-black rounded-2xl shadow-xl shadow-blue-100 hover:bg-blue-700 transition active:scale-95 uppercase tracking-widest">Konfirmasi Bayar</button>
                    </div>
                </div>\`;
            
            container.innerHTML = container.innerHTML.replace('[ CHECKOUT ]', formHTML);

            document.getElementById('btn-p').onclick = async () => {
                const m = document.querySelector('input[name="pay_method"]:checked')?.value;
                const name = document.getElementById('cn').value;
                const phone = document.getElementById('cp').value;
                if(!m || !name || !phone) return alert('Lengkapi data!');
                
                const b = document.getElementById('btn-p');
                b.disabled = true; b.innerText = 'SEDANG MEMPROSES...';
                
                try {
                    const r = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ page_id: ${page.id}, slug_payment: m, customer: { name, phone } })
                    });
                    const d = await r.json();
                    
                    if(d.payment_url) {
                        window.location.href = d.payment_url;
                    } else if(d.va) {
                        document.getElementById('inner-checkout').innerHTML = \`
                            <div class="text-center py-4">
                                <div class="w-20 h-20 bg-green-100 text-green-600 rounded-full flex items-center justify-center mx-auto mb-6">
                                    <svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>
                                </div>
                                <h3 class="text-xl font-black text-gray-800 mb-2 uppercase tracking-tight">VA BERHASIL DIBUAT</h3>
                                <p class="text-xs text-gray-400 mb-8 uppercase tracking-widest">Selesaikan pembayaran Anda</p>
                                <div class="bg-gray-50 p-8 rounded-3xl border border-dashed border-gray-300 mb-6">
                                    <div class="text-[10px] text-gray-400 font-bold mb-2 uppercase tracking-widest">\${d.va.bank}</div>
                                    <div class="text-3xl font-black text-blue-600 tracking-widest mb-4">\${d.va.number}</div>
                                    <button onclick="navigator.clipboard.writeText('\${d.va.number}');alert('Nomor VA Disalin!')" class="text-[10px] font-black text-blue-500 hover:underline uppercase tracking-widest">Salin Nomor VA</button>
                                </div>
                                <div class="bg-blue-600 p-5 rounded-2xl shadow-lg shadow-blue-100">
                                    <div class="flex justify-between items-center text-white">
                                        <span class="text-xs font-bold uppercase opacity-80">Total Tagihan</span>
                                        <span class="text-xl font-black italic">Rp \${new Intl.NumberFormat('id-ID').format(d.va.amount)}</span>
                                    </div>
                                </div>
                                <p class="text-[10px] text-gray-400 mt-8 italic">*Simpan halaman ini sebagai bukti pemesanan.</p>
                            </div>\`;
                    } else { alert('Gagal: ' + (d.error || 'Terjadi kesalahan')); b.disabled = false; b.innerText = 'KONFIRMASI BAYAR'; }
                } catch(e) { alert('Server Error!'); b.disabled = false; }
            };
        });
    </script>`;
    
    return c.html("<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script><style>" + page.css_content + "</style></head><body>" + page.html_content + "<script>window.PAGE_ID=" + page.id + "</script>" + checkoutScript + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
