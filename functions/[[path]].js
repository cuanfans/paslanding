import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import { sha256, encryptJSON, decryptJSON } from '../src/utils'
import { uploadImage } from '../src/modules/cloudinary'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'

const RELAY_URL = "https://pasdigi-relay.hf.space/proxy";
const RELAY_SECRET = "BantarCaringin1";

// =============================================================
// 1. INTERNAL ENGINE (FINAL SPEK SYNC)
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

    // --- SINKRONISASI PAYLOAD (FIXED TYPO & STRUCTURE) ---
    if (slug.includes('flashpay')) {
        payload.external_id = "INV-" + Date.now();
        payload.payment_type = ["VA_BRI"]; // TYPO FIXED: VA_BRI (Murni)
        payload.currency = "IDR";
        payload.session_time = "15";
        payload.transaction_amount = Number(payload.transaction_amount); // Wajib Number murni
        
        // Root Parameters
        payload.customer_id = String(payload.customer_phone).replace(/[^0-9]/g, ''); 
        payload.va_type = "CLOSE_AMOUNT";
        payload.va_reusability = "SINGLE_USE";
        
        // Customer Details Object
        payload.customer_details = {
            name: payload.customer_name,
            email: payload.customer_email,
            phone: payload.customer_phone,
            address: "Jl. In",
            postal_code: "13930"
        };
    }
    
    const bodyFinal = replaceVars(template.body_json || '{}');
    const headersFinal = { ...JSON.parse(template.headers_json || '{}'), ...extraHeaders }; 

    const res = await fetch(RELAY_URL, {
        method: 'POST',
        headers: { "Content-Type": "application/json", "x-relay-auth": RELAY_SECRET },
        body: JSON.stringify({
            target_url: template.api_endpoint,
            target_method: template.method || 'POST',
            target_headers: headersFinal,
            target_payload: JSON.parse(bodyFinal)
        })
    });

    const resData = await res.json();
    const result = {};
    const mapping = JSON.parse(template.response_mapping || '{}');
    const getVal = (path, source) => path.split('.').reduce((o, i) => o?.[i], source);
    for (const [key, path] of Object.entries(mapping)) {
        result[key] = getVal(path, resData) || null;
    }
    result._raw = resData; 
    return result;
}

// ===============================================
// 6. PUBLIC CHECKOUT
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page?.product_config_json || '{}');
        
        const requestData = {
            slug_payment: body.slug_payment,
            page_id: body.page_id,
            transaction_amount: parseInt(config.price || 175000),
            customer_name: body.customer?.name || "Alea",
            customer_email: "customer@mail.com",
            customer_phone: (body.customer?.phone || "0812312312").replace(/[^0-9]/g, '')
        };

        const result = await executeGenericAPI(c, 'payment', requestData.slug_payment, requestData);
        const va_number = result.va_number || result._raw?.data?.payment_code || result._raw?.data?.va_number;

        if (!va_number) return c.json({ error: "FlashPay nolak: " + (result._raw?.message || "Bad Request"), debug: result._raw }, 400);

        return c.json({ va: { number: va_number, bank: "BRI VA", amount: requestData.transaction_amount } });
    } catch (e) { return c.json({ error: e.message }, 500); }
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
            const cont = document.body;
            if (!cont.innerHTML.includes('[ CHECKOUT ]')) return;
            const slugs = ${JSON.stringify(activePayments)};
            let list = slugs.map(s => \`
                <label class="flex items-center p-3 border rounded-lg mb-2 cursor-pointer border-gray-200">
                    <input type="radio" name="pay_method" value="\${s}" class="mr-3">
                    <span class="font-bold text-xs uppercase text-gray-700">\${s.replace(/-/g,' ')}</span>
                </label>\`).join('');
            const form = \`
                <div id="checkout-box" class="max-w-md mx-auto my-10 p-8 bg-white rounded-2xl shadow-xl border">
                    <div id="checkout-form-inner">
                        <h2 class="text-xl font-black mb-6 text-center uppercase tracking-tighter">Checkout</h2>
                        <input type="text" id="c_name" placeholder="Nama Lengkap" class="w-full mb-3 p-3 bg-gray-50 border rounded-lg outline-none">
                        <input type="tel" id="c_phone" placeholder="WhatsApp (08...)" class="w-full mb-6 p-3 bg-gray-50 border rounded-lg outline-none">
                        <div class="mb-6">\${list}</div>
                        <button id="btn-pay" class="w-full p-4 bg-blue-600 text-white font-black rounded-xl uppercase active:scale-95 transition">Konfirmasi Bayar</button>
                    </div>
                </div>\`;
            cont.innerHTML = cont.innerHTML.replace('[ CHECKOUT ]', form);

            document.getElementById('btn-pay').onclick = async () => {
                const method = document.querySelector('input[name="pay_method"]:checked')?.value;
                const name = document.getElementById('c_name').value;
                const phone = document.getElementById('c_phone').value;
                if(!method || !name || !phone) return alert('Lengkapi data!');
                
                const btn = document.getElementById('btn-pay');
                btn.disabled = true; btn.innerText = 'MEMPROSES...';
                try {
                    const res = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ page_id: ${page.id}, slug_payment: method, customer: { name, phone } })
                    });
                    const data = await res.json();
                    if(data.va) {
                        document.getElementById('checkout-form-inner').innerHTML = \`
                            <div class="text-center">
                                <h3 class="text-sm font-bold text-gray-500 mb-2">VA BERHASIL DIBUAT</h3>
                                <div class="bg-gray-50 p-6 rounded-xl border border-dashed mb-4 border-blue-200">
                                    <div class="text-[10px] text-gray-400 mb-1">BRI VIRTUAL ACCOUNT</div>
                                    <div class="text-2xl font-black text-blue-600 tracking-widest">\${data.va.number}</div>
                                </div>
                                <div class="text-lg font-bold">Rp \${new Intl.NumberFormat('id-ID').format(data.va.amount)}</div>
                                <p class="text-[10px] text-gray-400 mt-4 italic">Silahkan transfer sebelum 15 menit.</p>
                            </div>\`;
                    } else { alert(data.error || 'Gagal'); btn.disabled = false; btn.innerText = 'BAYAR SEKARANG'; }
                } catch(e) { alert(e.message); btn.disabled = false; }
            };
        });
    </script>`;
    return c.html(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${page.title}</title><script src="https://cdn.tailwindcss.com"></script><style>${page.css_content}</style></head><body>${page.html_content}<script>window.PAGE_ID=${page.id}</script>${checkoutScript}</body></html>`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
