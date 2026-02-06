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
// 1. INTERNAL ENGINE (DENGAN LOGGING LENGKAP)
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    console.log(`[LOG] Starting engine for: ${slug}`);
    
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' not found.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Credentials missing for ${providerSlug}`);
    
    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
    const decryptedText = await decryptJSON(credRow.encrypted_data, credRow.iv, secret);
    const creds = typeof decryptedText === 'string' ? JSON.parse(decryptedText) : decryptedText;

    let extraHeaders = {};
    if (slug.includes('flashpay')) {
        console.log(`[LOG] Requesting FlashPay Token...`);
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
            console.error(`[LOG] Auth Failed:`, authData);
            throw new Error("Gagal Auth FlashPay");
        }
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
    }

    // --- CONSTRUCT PAYLOAD SESUAI CONTOH SPEK ---
    const finalPayload = {
        external_id: "INV-" + Date.now(),
        payment_type: ["VA_BRI"], // Sesuai pilihan di dashboard
        currency: "IDR",
        transaction_amount: Number(payload.amount),
        session_time: "15",
        remark: "Payment for " + (payload.customer_name || "Order"),
        customer_id: String(payload.customer_phone).replace(/[^0-9]/g, ''),
        va_type: "CLOSE_AMOUNT",
        va_reusability: "SINGLE_USE",
        customer_details: {
            name: payload.customer_name,
            email: payload.customer_email || "customer@mail.com",
            phone: payload.customer_phone,
            address: "Jl. In",
            postal_code: "13930"
        }
    };

    console.log(`[LOG] DATA DIKIRIM KE RELAY:`, JSON.stringify(finalPayload, null, 2));

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
// 6. PUBLIC CHECKOUT (LOGGING KE FRONTEND)
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page?.product_config_json || '{}');
        
        const payload = {
            slug_payment: body.slug_payment,
            amount: config.price || 170000,
            customer_name: body.customer?.name || "Customer",
            customer_phone: body.customer?.phone || "0812312312"
        };

        const result = await executeGenericAPI(c, 'payment', payload.slug_payment, payload);
        const data = result._raw;

        if (data.code == 200 || data.data?.va_number || data.data?.payment_code) {
            return c.json({
                success: true,
                va: {
                    number: data.data?.payment_code || data.data?.va_number,
                    bank: "BRI VA",
                    amount: result.amount
                }
            });
        }

        return c.json({ 
            success: false, 
            error: data.message || "Gagal Generate VA", 
            debug_payload_sent: data // Mengirim balik respon FlashPay ke browser untuk didebug
        }, 400);

    } catch (e) {
        return c.json({ success: false, error: e.message }, 500);
    }
});

// ===============================================
// 8. PAGE RENDERING (DENGAN LOG CONSOLE BROWSER)
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
            if (!document.body.innerHTML.includes('[ CHECKOUT ]')) return;
            const slugs = ${JSON.stringify(activePayments)};
            let listHTML = slugs.map(s => \`
                <label class="flex items-center p-3 border rounded-lg mb-2 cursor-pointer border-gray-100">
                    <input type="radio" name="pay_method" value="\${s}" class="mr-3">
                    <span class="font-bold text-xs uppercase">\${s.replace(/-/g,' ')}</span>
                </label>\`).join('');
            
            const formHTML = \`
                <div id="checkout-box" class="max-w-md mx-auto my-10 p-8 bg-white rounded-2xl shadow-xl border">
                    <div id="checkout-form-inner">
                        <h2 class="text-xl font-black mb-6 text-center">CHECKOUT</h2>
                        <input type="text" id="c_name" placeholder="Nama" class="w-full mb-3 p-3 bg-gray-50 border rounded-lg">
                        <input type="tel" id="c_phone" placeholder="No WhatsApp" class="w-full mb-6 p-3 bg-gray-50 border rounded-lg">
                        <div class="mb-6">\${listHTML}</div>
                        <button id="btn-pay" class="w-full p-4 bg-blue-600 text-white font-bold rounded-xl">KONFIRMASI BAYAR</button>
                    </div>
                </div>\`;
            document.body.innerHTML = document.body.innerHTML.replace('[ CHECKOUT ]', formHTML);

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
                    console.log("[DEBUG LOG] Response Server:", data);
                    
                    if(data.va) {
                        document.getElementById('checkout-form-inner').innerHTML = \`
                            <div class="text-center">
                                <h3 class="font-bold text-gray-800 mb-4 uppercase">Nomor Virtual Account</h3>
                                <div class="bg-blue-50 p-6 rounded-xl border border-blue-200 mb-4">
                                    <div class="text-3xl font-black text-blue-700 tracking-widest">\${data.va.number}</div>
                                </div>
                                <div class="text-lg font-bold">Total: Rp \${new Intl.NumberFormat('id-ID').format(data.va.amount)}</div>
                            </div>\`;
                    } else { 
                        alert('Gagal: ' + data.error);
                        console.error("[DEBUG LOG] Detail Error:", data.debug_payload_sent);
                        btn.disabled = false; btn.innerText = 'KONFIRMASI BAYAR';
                    }
                } catch(e) { alert('Crash: ' + e.message); btn.disabled = false; }
            };
        });
    </script>`;
    return c.html(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${page.title}</title><script src="https://cdn.tailwindcss.com"></script></head><body>${page.html_content}<script>window.PAGE_ID=${page.id}</script>${checkoutScript}</body></html>`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
