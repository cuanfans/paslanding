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

// ===============================================
// 1. ENGINE PEMBAYARAN (SUPPORT BUMP & DONASI)
// ===============================================
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
    } catch (e) { throw new Error("Gagal dekripsi kredensial."); }

    let extraHeaders = {};
    if (slug.includes('flashpay')) {
        // --- AUTO AUTH FLASHPAY VIA RELAY ---
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
        if (!authRes.ok || !authData?.data?.token) throw new Error("FlashPay Auth Fail");
        extraHeaders['Authorization'] = `Bearer ${authData.data.token}`;
        extraHeaders['X-Client-Key'] = creds.client_key;
    }

    // --- KONSTRUKSI PAYLOAD ---
    const transactionAmount = Number(payload.amount);
    
    // Support Nama Item Majemuk (Produk Utama + Bump)
    const itemInfo = payload.bump_name ? `Order: ${payload.item_name} + ${payload.bump_name}` : `Order: ${payload.item_name}`;

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
        // FlashPay Specific Logic
        if (payload.customer?.phone) payload.customer.phone_clean = payload.customer.phone.replace(/[^0-9]/g, '');
        
        // Paksa override payload body untuk menjamin struktur FlashPay benar
        const fpPayload = {
            external_id: "INV-" + Date.now(),
            payment_type: [slug.toUpperCase().replace(/-/g, '_')],
            currency: "IDR",
            transaction_amount: transactionAmount,
            customer_id: String(payload.customer.phone).replace(/[^0-9]/g, ''),
            va_type: "CLOSE_AMOUNT",
            va_reusability: "SINGLE_USE",
            customer_details: {
                name: payload.customer.name,
                email: "customer@mail.com",
                phone: payload.customer.phone,
            },
            item_details: [{
                item_id: "ITEM-" + Date.now(),
                information: itemInfo.substring(0, 200), // Limit chars
                amount: transactionAmount,
                beneficiary_bank: "MNC",
                beneficiary_account: "5279910282",
                beneficiary_name: "PASDIGI"
            }]
        };
        bodyRaw = JSON.stringify(fpPayload);
    }
    
    const bodyFinal = replaceVars(bodyRaw);
    let headersFinal = { ...JSON.parse(template.headers_json || '{}'), ...extraHeaders }; 

    // KIRIM KE RELAY
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
// 2. HELPER & ERROR
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
// 3. MIDDLEWARE
// ===============================================
const requireAuth = async (c, next) => {
    const path = new URL(c.req.url).pathname;
    const isPublic = (path === '/' || path === '/login' || path === '/api/login' || path.startsWith('/api/public/') || path.includes('.'));
    if (isPublic) return await next();
    const token = getCookie(c, 'auth_token');
    if (!token) return c.redirect('/login');
    try {
        await verify(token, c.env.APP_MASTER_KEY || JWT_SECRET, 'HS256');
        await next();
    } catch (e) { deleteCookie(c, 'auth_token'); return c.redirect('/login'); }
};
app.use('*', requireAuth);

// ===============================================
// 4. AUTH & ADMIN
// ===============================================
app.get('/login', (c) => serveAsset(c, '/login.html'));
app.post('/api/login', async (c) => {
    const { email, password } = await c.req.json();
    const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user || await sha256(password) !== user.password) return c.json({ success: false, message: 'Gagal' }, 401);
    const token = await sign({ id: user.id }, c.env.APP_MASTER_KEY || JWT_SECRET, 'HS256');
    setCookie(c, 'auth_token', token, { path: '/', secure: true, httpOnly: true, maxAge: 86400, sameSite: 'Lax' });
    return c.json({ success: true, token });
});
app.get('/api/admin/pages', async (c) => { return c.json((await c.env.DB.prepare("SELECT * FROM pages").all()).results); });
app.post('/api/admin/pages', async (c) => {
    const { slug, title, html, css, product_config, product_type } = await c.req.json();
    await c.env.DB.prepare(`INSERT INTO pages (slug, title, html_content, css_content, product_config_json, product_type) VALUES (?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET title=excluded.title, html_content=excluded.html_content, css_content=excluded.css_content, product_config_json=excluded.product_config_json, product_type=excluded.product_type`).bind(slug, title, html, css, JSON.stringify(product_config), product_type || 'physical').run();
    return c.json({ success: true });
});
app.post('/api/admin/credentials', async (c) => {
    const { provider, data } = await c.req.json();
    const { encrypted, iv } = await encryptJSON(data, c.env.APP_MASTER_KEY || JWT_SECRET);
    await c.env.DB.prepare(`INSERT INTO credentials (provider_slug, encrypted_data, iv) VALUES (?, ?, ?) ON CONFLICT(provider_slug) DO UPDATE SET encrypted_data=excluded.encrypted_data, iv=excluded.iv`).bind(provider, encrypted, iv).run();
    return c.json({ success: true });
});

// ===============================================
// 6. PUBLIC CHECKOUT (ORDER BUMP & DONASI)
// ===============================================
app.post('/api/public/checkout', async (c) => {
    try {
        const body = await c.req.json();
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE id = ?").bind(body.page_id).first();
        const config = JSON.parse(page.product_config_json || '{}');
        
        let finalPrice = 0;
        let itemName = page.title;
        let bumpName = null;

        // 1. HARGA DASAR (Varian / Single / Donasi)
        if (page.product_type === 'donation') {
             // Fitur: Web Donasi (User input nominal)
             finalPrice = Number(body.custom_amount);
             if (finalPrice < 1000) return c.json({ error: "Minimal donasi Rp 1.000" }, 400);
             itemName = "Donasi: " + itemName;
        } else if (config.variants && config.variants.length > 0) {
            // Fitur: Varian Produk
            const idx = body.variant_index;
            if(config.variants[idx]) {
                finalPrice = Number(config.variants[idx].price);
                itemName += ` (${config.variants[idx].name})`;
            } else {
                finalPrice = Number(config.price || 0);
            }
        } else {
            finalPrice = Number(config.price || 0);
        }

        // 2. KUPON DISKON
        if (body.coupon_code && config.coupons) {
            const cp = config.coupons.find(x => x.code.toUpperCase() === body.coupon_code.toUpperCase());
            if (cp) {
                const disc = cp.type === 'percent' ? (finalPrice * cp.value / 100) : cp.value;
                finalPrice = Math.max(0, finalPrice - disc);
            }
        }

        // 3. ORDER BUMP (Killer Feature Sejoli)
        // User mencentang penawaran tambahan
        if (body.take_bump && config.order_bump?.active) {
            const bumpPrice = Number(config.order_bump.price);
            finalPrice += bumpPrice;
            bumpName = config.order_bump.title || "Extra Item";
        }

        if (finalPrice <= 0) return c.json({ error: "Total 0 tidak diizinkan." }, 400);

        // Eksekusi Payment
        const result = await executeGenericAPI(c, 'payment', body.slug_payment, {
            amount: finalPrice,
            item_name: itemName,
            bump_name: bumpName, // Kirim info bump ke engine
            customer: body.customer
        });

        const d = result._raw.data || {};
        const va = d.payment_code || d.va_number;
        const qr = d.qr_string || d.qr_url;
        const url = result.payment_url || d.payment_url || d.redirect_url;

        if (va || qr || url) {
            return c.json({ success: true, type: va ? 'va' : (qr ? 'qris' : 'url'), data: va || qr || url, amount: finalPrice });
        }
        
        return c.json({ error: "Gagal dari provider", debug: result._raw }, 400);

    } catch (e) { return c.json({ error: e.message }, 500); }
});

// ===============================================
// 8. PAGE RENDERING (UI KILLER)
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
    const isDonation = page.product_type === 'donation';
    
    // Pixel Scripts
    const pixelScript = `
        <script>
            // FB PIXEL
            ${config.settings?.fb_pixel_id ? `
            !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js');
            fbq('init', '${config.settings.fb_pixel_id}');
            fbq('track', 'PageView');
            ` : ''}
        </script>`;

    const checkoutScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const cont = document.body;
            if (!cont.innerHTML.includes('[ CHECKOUT ]')) return;
            
            const config = ${JSON.stringify(config)};
            const isDonation = ${isDonation};
            let totalPrice = ${config.price || 0};
            
            // --- 1. RENDER VARIAN / DONASI ---
            let productHTML = '';
            if (isDonation) {
                productHTML = \`
                    <div class="mb-4">
                        <label class="text-xs font-bold text-gray-500 uppercase">Nominal Donasi</label>
                        <input type="number" id="custom_amount" class="w-full p-3 border rounded-xl font-bold text-lg text-blue-600" placeholder="Rp 100.000">
                    </div>\`;
            } else {
                productHTML = (config.variants || []).map((v, i) => \`
                    <label class="flex justify-between items-center p-4 border rounded-2xl mb-2 cursor-pointer border-gray-100 hover:border-blue-500 transition shadow-sm">
                        <div class="flex items-center">
                            <input type="radio" name="v_idx" value="\${i}" \${i===0?'checked':''} class="mr-3 w-4 h-4 text-blue-600" onchange="updateTotal()">
                            <span class="text-sm font-bold text-gray-700">\${v.name}</span>
                        </div>
                        <span class="font-black text-blue-600">Rp \${new Intl.NumberFormat('id-ID').format(v.price)}</span>
                    </label>\`).join('');
                if(!productHTML) productHTML = \`<div class="text-center font-bold text-2xl text-blue-600 mb-4">Rp \${new Intl.NumberFormat('id-ID').format(config.price)}</div>\`;
            }

            // --- 2. RENDER ORDER BUMP ---
            let bumpHTML = '';
            if (config.order_bump?.active) {
                bumpHTML = \`
                    <div class="bg-yellow-50 border-2 border-dashed border-yellow-400 p-4 rounded-xl mb-6 relative overflow-hidden">
                        <div class="absolute top-0 right-0 bg-red-600 text-white text-[9px] px-2 py-1 font-bold uppercase">Penawaran Khusus</div>
                        <label class="flex items-start cursor-pointer">
                            <input type="checkbox" id="take_bump" class="mt-1 mr-3 w-5 h-5 text-blue-600 rounded" onchange="updateTotal()">
                            <div>
                                <div class="font-black text-gray-800 text-sm">\${config.order_bump.title || 'Tambah Penawaran Ini?'}</div>
                                <p class="text-xs text-gray-600 mt-1 leading-snug">\${config.order_bump.desc || 'Dapatkan bonus spesial dengan harga hemat.'}</p>
                                <div class="text-red-600 font-bold text-sm mt-1">Hanya Tambah Rp \${new Intl.NumberFormat('id-ID').format(config.order_bump.price)}</div>
                            </div>
                        </label>
                    </div>\`;
            }

            // --- 3. RENDER PEMBAYARAN ---
            const labels = { 'VA_BRI': 'Bank BRI', 'VA_MANDIRI': 'Bank Mandiri', 'VA_BNI': 'Bank BNI', 'QRIS': 'QRIS / E-Wallet', 'EWALLET': 'OVO / Dana / Gopay' };
            let payHTML = (config.active_payments || []).map(s => \`
                <label class="flex items-center p-3 border rounded-xl mb-2 cursor-pointer border-gray-100 hover:bg-gray-50 transition">
                    <input type="radio" name="p_slug" value="\${s}" class="mr-3">
                    <span class="font-bold text-xs uppercase text-gray-600">\${labels[s] || s.replace(/-/g,' ')}</span>
                </label>\`).join('');

            // --- INJECT FORM ---
            const formHTML = \`
                <div id="checkout-box" class="max-w-md mx-auto my-10 p-6 bg-white rounded-[2rem] shadow-2xl border border-gray-50 relative">
                    <h2 class="text-xl font-black mb-6 text-center uppercase tracking-tight text-gray-800">Formulir Pemesanan</h2>
                    
                    <div class="mb-6">\${productHTML}</div>
                    \${bumpHTML}

                    <div class="space-y-3 mb-6">
                        <input type="text" id="cn" placeholder="Nama Lengkap" class="w-full p-3 bg-gray-50 border rounded-xl text-sm focus:ring-2 ring-blue-500 outline-none transition">
                        <input type="tel" id="cp" placeholder="Nomor WhatsApp" class="w-full p-3 bg-gray-50 border rounded-xl text-sm focus:ring-2 ring-blue-500 outline-none transition">
                        <input type="text" id="coupon" placeholder="Punya Kode Kupon?" class="w-full p-3 border-dashed border-2 rounded-xl text-sm text-center uppercase tracking-widest outline-none focus:border-blue-500 transition">
                    </div>

                    <div class="mb-6">
                        <div class="text-[10px] font-bold text-gray-400 uppercase mb-2">Metode Pembayaran</div>
                        \${payHTML}
                    </div>

                    <button id="btn-p" class="w-full p-4 bg-gradient-to-r from-blue-600 to-blue-700 text-white font-black rounded-xl uppercase shadow-lg shadow-blue-200 transform transition active:scale-95 hover:shadow-xl">
                        Bayar <span id="btn-total">Sekarang</span>
                    </button>
                    
                    <div class="mt-4 text-[10px] text-center text-gray-400 flex justify-center items-center">
                        <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                        Transaksi Aman & Terenkripsi
                    </div>
                </div>\`;

            cont.innerHTML = cont.innerHTML.replace('[ CHECKOUT ]', formHTML);

            // --- LOGIKA UPDATE TOTAL & SUBMIT ---
            window.updateTotal = () => {
                // Logika kosmetik tombol (opsional, bisa dikembangkan)
                // Di sistem backend harga tetap dihitung ulang demi keamanan
            };

            document.getElementById('btn-p').onclick = async () => {
                const b = document.getElementById('btn-p');
                const m = document.querySelector('input[name="p_slug"]:checked')?.value;
                const v = document.querySelector('input[name="v_idx"]:checked')?.value;
                const custAmt = document.getElementById('custom_amount')?.value;
                const takeBump = document.getElementById('take_bump')?.checked;

                if(!m) return alert('Pilih pembayaran!');
                if(isDonation && !custAmt) return alert('Isi nominal donasi!');

                b.disabled = true; b.innerHTML = '<svg class="animate-spin h-5 w-5 mx-auto text-white" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';
                
                try {
                    const r = await fetch('/api/public/checkout', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ 
                            page_id: ${page.id}, 
                            slug_payment: m, 
                            variant_index: v,
                            coupon_code: document.getElementById('coupon').value,
                            take_bump: takeBump,
                            custom_amount: custAmt,
                            customer: { name: document.getElementById('cn').value, phone: document.getElementById('cp').value } 
                        })
                    });
                    const d = await r.json();
                    
                    if(d.success) {
                        // TRIGGER PIXEL PURCHASE
                        if(typeof fbq === 'function') {
                            fbq('track', 'Purchase', {value: d.amount, currency: 'IDR'});
                        }

                        if(d.type === 'url') { window.location.href = d.data; return; }
                        
                        let ui = d.type === 'va' 
                            ? \`<div class="bg-blue-50 p-6 rounded-2xl border border-dashed border-blue-200 mb-6 relative"><div class="absolute top-0 right-0 bg-blue-600 text-white text-[9px] px-2 py-1 rounded-bl-lg font-bold">VIRTUAL ACCOUNT</div><div class="text-2xl font-black text-blue-700 tracking-widest mt-2">\${d.data}</div></div>\`
                            : \`<div class="flex justify-center mb-6"><div class="p-3 border-4 border-gray-100 rounded-3xl"><img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=\${encodeURIComponent(d.data)}" class="w-48 h-48 rounded-lg"></div></div>\`;
                        
                        document.getElementById('checkout-box').innerHTML = \`
                            <div class="text-center animate-fade-in-up">
                                <div class="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4 text-green-600">
                                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>
                                </div>
                                <h3 class="font-bold text-gray-800 mb-1 text-lg">Pesanan Diterima!</h3>
                                <p class="text-xs text-gray-400 mb-6 uppercase tracking-widest">Selesaikan pembayaran Anda</p>
                                \${ui}
                                <div class="text-xl font-black text-gray-800 tracking-tighter">Rp \${new Intl.NumberFormat('id-ID').format(d.amount)}</div>
                                <button onclick="location.reload()" class="mt-8 text-blue-600 font-bold text-xs uppercase hover:underline">Buat Pesanan Baru</button>
                            </div>\`;
                    } else { alert(d.error); b.disabled = false; b.innerText = 'BAYAR SEKARANG'; }
                } catch(e) { alert('Gagal memproses.'); b.disabled = false; b.innerText = 'BAYAR SEKARANG'; }
            };
        });
    </script>`;
    
    // Perbaikan: Return string biasa untuk menghindari syntax error backtick
    return c.html("<!DOCTYPE html><html lang='id'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>" + page.title + "</title><script src='https://cdn.tailwindcss.com'></script><style>" + page.css_content + "</style>" + pixelScript + "</head><body>" + page.html_content + "<script>window.PAGE_ID=" + page.id + "</script>" + checkoutScript + "</body></html>");
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
