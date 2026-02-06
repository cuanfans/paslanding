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
// 1. INTERNAL ENGINE (MULTIPLE GATEWAY SUPPORT)
// =============================================================
async function executeGenericAPI(c, type, slug, payload) {
    const table = type === 'shipping' ? 'shipping_templates' : 'payment_templates';
    const template = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE slug = ?`).bind(slug).first();
    if (!template) throw new Error(`Template '${slug}' tidak ditemukan.`);

    const providerSlug = slug.split('-')[0]; 
    const credRow = await c.env.DB.prepare(`SELECT encrypted_data, iv FROM credentials WHERE provider_slug = ?`).bind(providerSlug).first();
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
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
    }

    const transactionAmount = Number(payload.amount);
    // Logika Payment Type Dinamis berdasarkan Slug
    const paymentType = [slug.toUpperCase().replace(/-/g, '_')];

    const finalPayload = {
        external_id: "INV-" + Date.now(),
        payment_type: paymentType,
        currency: "IDR",
        transaction_amount: transactionAmount,
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
            information: payload.item_name || "Produk",
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
            target_url: template.api_endpoint || "https://sandbox-secure.flashmobile.id/payment/api/v1/create",
            target_method: "POST",
            target_headers: { "Accept": "application/json", "Content-Type": "application/json", ...extraHeaders },
            target_payload: finalPayload
        })
    });

    return { _raw: await res.json(), amount: transactionAmount };
}

// ===============================================
// 6. PUBLIC CHECKOUT (GATEWAY MAPPER & DYNAMIC PRICE)
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        if (!page) return c.json({ error: "Page not found" }, 404);
        
        const config = JSON.parse(page.product_config_json || '{}');
        let finalPrice = 0;
        let itemName = page.title;

        // 1. Ambil Harga Nyata dari Varian/Price List
        if (config.variants && config.variants[body.variant_index]) {
            const v = config.variants[body.variant_index];
            finalPrice = Number(v.price);
            itemName += ` (${v.name})`;
        } else {
            finalPrice = Number(config.price || 0);
        }

        // 2. Logika Kupon
        if (body.coupon_code && config.coupons) {
            const coupon = config.coupons.find(cp => cp.code.toUpperCase() === body.coupon_code.toUpperCase());
            if (coupon) {
                const discount = coupon.type === 'percent' ? (finalPrice * coupon.value / 100) : coupon.value;
                finalPrice = Math.max(0, finalPrice - discount);
            }
        }

        // 3. Eksekusi Pembayaran
        const result = await executeGenericAPI(c, 'payment', body.slug_payment, {
            amount: finalPrice,
            item_name: itemName,
            customer_name: body.customer?.name,
            customer_phone: body.customer?.phone
        });

        const d = result._raw.data;
        const va = d?.payment_code || d?.va_number;
        const qr = d?.qr_string || d?.qr_url;
        const url = result.payment_url || d?.payment_url || d?.redirect_url;

        if (va) return c.json({ success: true, type: 'va', data: va, amount: finalPrice });
        if (qr) return c.json({ success: true, type: 'qris', data: qr, amount: finalPrice });
        if (url) return c.json({ success: true, type: 'url', data: url, amount: finalPrice });
        
        return c.json({ success: false, error: "Provider Error", debug: result._raw }, 400);
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

// ===============================================
// 8. RENDERING (DYNAMIC GATEWAY LABELS)
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
            
            // Gateway Labels Mapper
            const gatewayLabels = {
                'QRIS': 'QRIS / E-Wallet',
                'CARD': 'Card (Credit/Debit)',
                'CARD_FULLPAYMENT': 'Card Full Payment',
                'EWALLET': 'E-Wallet (OVO/Dana/Gopay)',
                'VA_MANDIRI': 'Bank Mandiri VA',
                'VA_BRI': 'Bank BRI VA',
                'VA_BNI': 'Bank BNI VA',
                'VA_BSI': 'Bank BSI VA',
                'VA_PERMATA': 'Bank Permata VA'
            };

            // UI Price List
            let variantsHTML = (config.variants || []).map((v, i) => \`
                <label class="flex justify-between items-center p-4 border-2 rounded-2xl cursor-pointer transition border-gray-100 hover:border-blue-500">
                    <div class="flex items-center">
                        <input type="radio" name="v_idx" value="\${i}" \${i===0?'checked':''} class="mr-3 w-4 h-4">
                        <span class="font-bold text-gray-700">\${v.name}</span>
                    </div>
                    <span class="font-black text-blue-600 italic">Rp \${new Intl.NumberFormat('id-ID').format(v.price)}</span>
                </label>\`).join('');

            // UI Gateway Dinamis (Sesuai Editor)
            let payHTML = (config.active_payments || []).map(s => {
                const label = gatewayLabels[s.toUpperCase()] || s.replace(/-/g,' ').toUpperCase();
                return \`
                <label class="flex items-center p-3 border rounded-xl cursor-pointer hover:bg-gray-50 border-gray-100 transition">
                    <input type="radio" name="p_slug" value="\${s}" class="mr-3">
                    <span class="font-bold text-[10px] text-gray-500 uppercase">\${label}</span>
                </label>\`}).join('');

            const formHTML = \`
                <div id="checkout-box" class="max-w-md mx-auto my-12 p-8 bg-white rounded-[2rem] shadow-2xl border border-gray-50">
                    <div id="inner-checkout">
                        <h2 class="text-2xl font-black mb-8 text-center tracking-tighter uppercase italic">Checkout</h2>
                        <div class="space-y-3 mb-8">\${variantsHTML}</div>
                        <div class="space-y-4 mb-8">
                            <input type="text" id="cn" placeholder="Nama Lengkap" class="w-full p-4 bg-gray-50 border rounded-xl outline-none focus:ring-4 ring-blue-500/10 transition">
                            <input type="tel" id="cp" placeholder="WhatsApp (08...)" class="w-full p-4 bg-gray-50 border rounded-xl outline-none focus:ring-4 ring-blue-500/10 transition">
                            <input type="text" id="coupon" placeholder="Punya kode kupon?" class="w-full p-4 bg-gray-50 border border-dashed rounded-xl outline-none">
                        </div>
                        <div class="grid grid-cols-1 gap-2 mb-8">\${payHTML}</div>
                        <button id="btn-p" class="w-full p-5 bg-blue-600 text-white font-black rounded-2xl shadow-xl shadow-blue-200 hover:bg-blue-700 active:scale-95 transition tracking-widest uppercase italic">Bayar Sekarang</button>
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
                            coupon_code: document.getElementById('coupon').value,
                            customer: { name: document.getElementById('cn').value, phone: document.getElementById('cp').value } 
                        })
                    });
                    const d = await r.json();
                    if(d.success) {
                        if(d.type === 'url') { window.location.href = d.data; return; }
                        let resUI = d.type === 'va' 
                            ? \`<div class="bg-blue-50 p-6 rounded-2xl border border-dashed border-blue-200 mb-6"><div class="text-xl font-black text-blue-700 tracking-widest">\${d.data}</div></div>\`
                            : \`<div class="flex justify-center mb-6 border-4 p-2 rounded-2xl border-gray-50"><img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=\${encodeURIComponent(d.data)}" class="w-40 h-40"></div>\`;
                        
                        document.getElementById('inner-checkout').innerHTML = \`
                            <div class="text-center">
                                <h3 class="font-bold text-gray-400 mb-4 uppercase text-[10px] tracking-widest">Instruksi Pembayaran</h3>
                                \${resUI}
                                <div class="text-xl font-black text-gray-800 tracking-tighter italic">Total: Rp \${new Intl.NumberFormat('id-ID').format(d.amount)}</div>
                                <p class="text-[9px] text-gray-400 mt-8 italic">Silahkan selesaikan pembayaran sebelum 15 menit.</p>
                            </div>\`;
                    } else { alert(d.error); b.disabled = false; b.innerText = 'BAYAR SEKARANG'; }
                } catch(e) { alert('Error!'); b.disabled = false; }
            };
        });
    </script>`;
    
    return c.html("<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script><style>" + page.css_content + "</style></head><body>" + page.html_content + "<script>window.PAGE_ID=" + page.id + "</script>" + checkoutScript + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
