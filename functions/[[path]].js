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
// 1. INTERNAL ENGINE (FIXED ITEM_DETAILS & VA SPEC)
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials missing.`);
    
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
        if (!authData?.data?.token) throw new Error("Gagal Auth FlashPay");
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
    }

    // --- CONSTRUCT PAYLOAD SESUAI SPEK JSON LO ---
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
        // WAJIB: Item details harus sinkron harganya dengan transaction_amount
        item_details: [
            {
                item_id: "ITEM-01",
                information: "Product Purchase",
                amount: transactionAmount,
                beneficiary_bank: "BRI",
                beneficiary_account: "5279910282", // Dummy account sandbox
                beneficiary_name: "PASDIGI STORE"
            }
        ]
    };

    console.log(`[LOG] PAYLOAD SEND:`, JSON.stringify(finalPayload));

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
    console.log(`[LOG] RAW RESPONSE:`, JSON.stringify(resData));

    return { _raw: resData, amount: transactionAmount };
}

// ===============================================
// 6. PUBLIC CHECKOUT
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

        if (va_number) {
            return c.json({ success: true, va: { number: va_number, bank: "BRI VA", amount: result.amount } });
        }
        return c.json({ success: false, error: data.message || "Gagal", debug: data }, 400);
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

// ===============================================
// 8. RENDERING (NO SYNTAX ERROR)
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
    const script = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const html = document.body.innerHTML;
            if (!html.includes('[ CHECKOUT ]')) return;
            const slugs = ${JSON.stringify(activePayments)};
            let list = slugs.map(s => \`
                <label class="flex items-center p-3 border rounded-lg mb-2 cursor-pointer border-gray-200">
                    <input type="radio" name="pay_method" value="\${s}" class="mr-3">
                    <span class="font-bold text-xs uppercase">\${s.replace(/-/g,' ')}</span>
                </label>\`).join('');
            
            const form = \`
                <div class="max-w-md mx-auto my-10 p-8 bg-white rounded-2xl shadow-xl border">
                    <div id="inner-checkout">
                        <h2 class="text-xl font-black mb-6 text-center">CHECKOUT</h2>
                        <input type="text" id="cn" placeholder="Nama" class="w-full mb-3 p-3 bg-gray-50 border rounded-lg">
                        <input type="tel" id="cp" placeholder="No WhatsApp" class="w-full mb-6 p-3 bg-gray-50 border rounded-lg">
                        <div class="mb-6">\${list}</div>
                        <button id="btn-p" class="w-full p-4 bg-blue-600 text-white font-bold rounded-xl">BAYAR SEKARANG</button>
                    </div>
                </div>\`;
            document.body.innerHTML = html.replace('[ CHECKOUT ]', form);

            document.getElementById('btn-p').onclick = async () => {
                const m = document.querySelector('input[name="pay_method"]:checked')?.value;
                if(!m) return alert('Pilih metode!');
                const b = document.getElementById('btn-p');
                b.disabled = true; b.innerText = 'MEMPROSES...';
                try {
                    const r = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ page_id: ${page.id}, slug_payment: m, customer: { name: document.getElementById('cn').value, phone: document.getElementById('cp').value } })
                    });
                    const d = await r.json();
                    if(d.va) {
                        document.getElementById('inner-checkout').innerHTML = \`
                            <div class="text-center">
                                <h3 class="font-bold text-gray-800 mb-4">VA BRI BERHASIL</h3>
                                <div class="bg-blue-50 p-6 rounded-xl border border-blue-200 mb-4">
                                    <div class="text-3xl font-black text-blue-700 tracking-widest">\${d.va.number}</div>
                                </div>
                                <div class="text-lg font-bold">Total: Rp \${new Intl.NumberFormat('id-ID').format(d.va.amount)}</div>
                            </div>\`;
                    } else { alert('Gagal: ' + d.error); b.disabled = false; b.innerText = 'BAYAR'; }
                } catch(e) { alert(e.message); b.disabled = false; }
            };
        });
    </script>`;
    return c.html("<!DOCTYPE html><html><head><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script></head><body>" + page.html_content + "<script>window.PAGE_ID=" + page.id + "</script>" + script + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
