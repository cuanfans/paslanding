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
// 1. ENGINE: EKSEKUSI API DENGAN LOGGING MENTAH
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
    if (!credRow) throw new Error(`Kredensial ${providerSlug} belum di-set.`);

    const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
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
        if (!authData?.data?.token) throw new Error("FlashPay Auth Fail: " + JSON.stringify(authData));
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
    }

    const finalPayload = {
        external_id: "INV-" + Date.now(),
        payment_type: [slug.toUpperCase().replace(/-/g, '_')],
        currency: "IDR",
        transaction_amount: parseInt(payload.amount),
        session_time: "15",
        remark: "Order " + payload.customer_name,
        customer_id: String(payload.customer_phone).replace(/[^0-9]/g, ''),
        va_type: "CLOSE_AMOUNT",
        va_reusability: "SINGLE_USE",
        customer_details: {
            name: payload.customer_name,
            email: payload.customer_email || "customer@mail.com",
            phone: payload.customer_phone,
            address: "Jl.In",
            postal_code: "13930"
        },
        item_details: [{
            item_id: "ITEM-01",
            information: "Order " + slug,
            amount: parseInt(payload.amount),
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

    const resBody = await res.json();
    return { _raw: resBody, amount: finalPayload.transaction_amount };
}

// ===============================================
// 6. CHECKOUT: HANDLE HARGA & KUPON
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        if (!page) return c.json({ success: false, error: "Halaman tidak ditemukan" }, 404);
        
        const config = JSON.parse(page.product_config_json || '{}');
        let finalPrice = 0;

        // Ambil Harga dari Varian (Price List) atau Harga Dasar
        if (config.variants && config.variants[body.variant_index]) {
            finalPrice = Number(config.variants[body.variant_index].price);
        } else {
            finalPrice = Number(config.price || 0);
        }

        // Cek Kupon
        if (body.coupon_code && config.coupons) {
            const cp = config.coupons.find(x => x.code.toUpperCase() === body.coupon_code.toUpperCase());
            if (cp) {
                const disc = cp.type === 'percent' ? (finalPrice * cp.value / 100) : cp.value;
                finalPrice = Math.max(0, finalPrice - disc);
            }
        }

        if (finalPrice <= 0) return c.json({ success: false, error: "Harga tidak valid. Cek editor!" }, 400);

        const result = await executeGenericAPI(c, 'payment', body.slug_payment, {
            amount: finalPrice,
            customer_name: body.customer?.name || "Guest",
            customer_phone: body.customer?.phone || "0812345678"
        });

        const d = result._raw;
        // Tangkap data VA/QRIS/URL
        const va = d.data?.payment_code || d.data?.va_number;
        const qr = d.data?.qr_string || d.data?.qr_url;
        const url = d.data?.payment_url || d.data?.redirect_url;

        if (va || qr || url) {
            return c.json({ success: true, type: va ? 'va' : (qr ? 'qris' : 'url'), data: va || qr || url, amount: finalPrice });
        }

        // JIKA GAGAL, LEMPAR SEMUA DEBUG KE FRONTEND
        return c.json({ success: false, error: d.message || "Provider Rejected Request", debug: d }, 400);

    } catch (e) {
        return c.json({ success: false, error: e.message }, 500);
    }
});

// ===============================================
// 8. RENDERING: UI DENGAN DEBUG LOG
// ===============================================
app.get('/:slug', async (c) => {
    const slug = c.req.param('slug');
    if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
    return page ? renderPage(c, page) : c.text('404', 404);
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const checkoutScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const cont = document.body;
            if (!cont.innerHTML.includes('[ CHECKOUT ]')) return;
            const config = ${JSON.stringify(config)};

            // UI PRICE LIST
            let varHTML = (config.variants || []).map((v, i) => \`
                <label class="flex justify-between items-center p-4 border rounded-2xl cursor-pointer mb-2 border-gray-100 hover:border-blue-500 transition">
                    <span class="text-sm font-bold"><input type="radio" name="v_idx" value="\${i}" \${i===0?'checked':''} class="mr-2"> \${v.name}</span>
                    <span class="font-black text-blue-600 italic">Rp \${new Intl.NumberFormat('id-ID').format(v.price)}</span>
                </label>\`).join('');

            // UI GATEWAY
            let payHTML = (config.active_payments || []).map(s => \`
                <label class="flex items-center p-3 border rounded-xl cursor-pointer mb-2 border-gray-100 hover:bg-gray-50 uppercase text-[10px] font-bold">
                    <input type="radio" name="p_slug" value="\${s}" class="mr-2"> \${s.replace(/-/g,' ')}
                </label>\`).join('');

            const formHTML = \`
                <div id="checkout-box" class="max-w-md mx-auto my-10 p-8 bg-white rounded-[2rem] shadow-2xl border border-gray-50">
                    <div id="inner-checkout">
                        <h2 class="text-xl font-black mb-6 text-center italic tracking-tighter uppercase">Konfirmasi Order</h2>
                        <div class="mb-6">\${varHTML}</div>
                        <input type="text" id="cn" placeholder="Nama Lengkap" class="w-full mb-2 p-4 bg-gray-50 border rounded-xl outline-none focus:ring-4 ring-blue-500/10">
                        <input type="tel" id="cp" placeholder="No WhatsApp" class="w-full mb-4 p-4 bg-gray-50 border rounded-xl outline-none focus:ring-4 ring-blue-500/10">
                        <div class="mb-6">\${payHTML}</div>
                        <button id="btn-p" class="w-full p-5 bg-blue-600 text-white font-black rounded-2xl shadow-xl uppercase italic tracking-widest">Bayar Sekarang</button>
                    </div>
                </div>\`;

            cont.innerHTML = cont.innerHTML.replace('[ CHECKOUT ]', formHTML);

            document.getElementById('btn-p').onclick = async () => {
                const b = document.getElementById('btn-p');
                const m = document.querySelector('input[name="p_slug"]:checked')?.value;
                if(!m) return alert('Pilih metode pembayaran!');
                
                b.disabled = true; b.innerText = 'MEMPROSES...';
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
                        if(d.type === 'url') { window.location.href = d.data; return; }
                        let ui = d.type === 'va' 
                            ? \`<div class="bg-blue-50 p-6 rounded-2xl border border-dashed border-blue-200 mb-6"><div class="text-xl font-black text-blue-700 tracking-widest">\${d.data}</div></div>\`
                            : \`<div class="flex justify-center mb-6 border-4 p-2 rounded-2xl border-gray-50"><img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=\${encodeURIComponent(d.data)}" class="w-40 h-40"></div>\`;
                        
                        document.getElementById('inner-checkout').innerHTML = \`
                            <div class="text-center">
                                <h3 class="font-bold text-gray-400 mb-4 uppercase text-[10px] tracking-widest">Selesaikan Pembayaran</h3>
                                \${ui}
                                <div class="text-xl font-black text-gray-800 italic">Total: Rp \${new Intl.NumberFormat('id-ID').format(d.amount)}</div>
                            </div>\`;
                    } else { 
                        alert('Error: ' + d.error);
                        console.error("DEBUG FLASHMOBILE:", d.debug); // Buka Console Browser buat liat ini!
                        b.disabled = false; b.innerText = 'BAYAR SEKARANG';
                    }
                } catch(e) { alert('System Error!'); b.disabled = false; }
            };
        });
    </script>`;
    
    return c.html("<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script><style>" + page.css_content + "</style></head><body>" + page.html_content + "<script>window.PAGE_ID=" + page.id + "</script>" + checkoutScript + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
