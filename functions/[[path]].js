import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import { sha256, encryptJSON, decryptJSON } from '../src/utils'
import { executeGenericAPI } from '../src/engine' 
import { uploadImage } from '../src/modules/cloudinary'

const app = new Hono()
const JWT_SECRET = 'BantarCaringin1BantarCaringin2BantarCaringin3'

// ===============================================
// 0. GLOBAL ERROR & ASSETS
// ===============================================
app.onError((err, c) => {
    console.error(`[ERROR] ${err.message}`, err.stack);
    return c.json({ success: false, message: 'Internal Server Error' }, 500);
});

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
// 1. MIDDLEWARE AUTH (PERBAIKAN LOGIKA & COOKIE)
// ===============================================
const requireAuth = async (c, next) => {
    const url = new URL(c.req.url);
    const path = url.pathname;
    
    // A. WHITELIST (Jalur Bebas Tanpa Login)
    if (
        path === '/' ||                          // Homepage Wajib Public
        path === '/login' ||                     // Halaman Login
        path === '/admin/login' || 
        path === '/api/login' ||                 // API Login
        path === '/api/setup-first-user' ||      // Setup Awal
        path.startsWith('/api/public/')          // API Publik (Checkout, dll)
    ) {
        await next(); 
        return;
    }

    // B. ASSET CHECK (File Statis)
    // Izinkan file berekstensi (js, css, png), KECUALI file HTML di folder sensitif
    if (path.includes('.')) {
        // Jika file ada di folder _views (Source Code Admin), BLOKIR (lanjut ke cek token)
        if (path.startsWith('/_views')) {
             // Pass through to Token Check
        } else {
             // File aset biasa aman -> Lolos
             await next(); 
             return;
        }
    }

    // C. TOKEN CHECK (Proteksi Admin)
    let token = getCookie(c, 'auth_token');
    const authHeader = c.req.header('Authorization');
    
    // Support Bearer Token juga (untuk fetch API)
    if (!token && authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }

    // Jika Tidak Ada Token -> Tolak
    if (!token) {
        if (path.startsWith('/api/')) return c.json({ error: 'Unauthorized' }, 401);
        return c.redirect('/login');
    }

    // Validasi Token
    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const payload = await verify(token, secret);
        c.set('user', payload);
        
        await next();
        
        // Header Anti-Cache untuk Admin Area
        c.res.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    } catch (e) {
        deleteCookie(c, 'auth_token');
        if (path.startsWith('/api/')) return c.json({ error: 'Invalid Token' }, 401);
        return c.redirect('/login');
    }
};

app.use('*', requireAuth); 

// ===============================================
// 2. AUTH ROUTES (FIX COOKIE SECURE)
// ===============================================
app.post('/api/login', async (c) => {
    try {
        const { email, password } = await c.req.json();
        const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (!user) return c.json({ success: false, message: 'Akun tidak ditemukan' }, 401);

        const inputHash = await sha256(password);
        if (inputHash !== user.password) {
            return c.json({ success: false, message: 'Password Salah' }, 401);
        }

        const secret = c.env.APP_MASTER_KEY || JWT_SECRET;
        const token = await sign({ 
            id: user.id, 
            email: user.email, 
            role: user.role, 
            exp: Math.floor(Date.now() / 1000) + 86400 
        }, secret);

        // FIX: Deteksi HTTPS agar cookie bisa disimpan di Localhost (HTTP)
        const url = new URL(c.req.url);
        const isSecure = url.protocol === 'https:'; // True di Cloudflare, False di Localhost

        setCookie(c, 'auth_token', token, { 
            path: '/', 
            secure: isSecure,  // Dinamis: false jika localhost
            httpOnly: true, 
            maxAge: 86400, 
            sameSite: 'Lax' 
        });

        return c.json({ success: true, token: token, user: { name: user.name, email: user.email } });
    } catch (e) { return c.json({ success: false, error: e.message }, 500); }
});

app.post('/api/setup-first-user', async (c) => {
    try {
        const { email, password, name } = await c.req.json();
        const hashedPassword = await sha256(password);
        await c.env.DB.prepare("INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, 'admin')")
            .bind(email, hashedPassword, name || 'Admin').run();
        return c.json({ success: true, message: 'User admin created' });
    } catch (e) { return c.json({ success: false, error: e.message }); }
});

app.get('/api/logout', (c) => { 
    deleteCookie(c, 'auth_token'); 
    return c.redirect('/login'); 
});

// ===============================================
// 3. ADMIN ROUTES MAPPING
// ===============================================
app.get('/login', (c) => serveAsset(c, '/login.html'));
app.get('/admin/login', (c) => c.redirect('/login'));

app.get('/admin', (c) => c.redirect('/admin/dashboard'));
app.get('/admin/dashboard', (c) => serveAsset(c, '/_views/dashboard.html'));
app.get('/admin/pages', (c) => serveAsset(c, '/_views/pages.html'));
app.get('/admin/editor', (c) => serveAsset(c, '/_views/editor.html'));
app.get('/admin/reports', (c) => serveAsset(c, '/_views/reports.html'));
app.get('/admin/analytics', (c) => serveAsset(c, '/_views/analytics.html'));
app.get('/admin/settings', (c) => serveAsset(c, '/_views/settings.html'));

// Proteksi Folder Views
app.get('/_views*', (c) => c.redirect('/login'));

// ===============================================
// 4. API DATA ROUTES
// ===============================================
app.get('/api/admin/pages', async (c) => {
    try {
        const res = await c.env.DB.prepare("SELECT id, slug, title, product_type, created_at FROM pages ORDER BY created_at DESC").all();
        return c.json(res.results);
    } catch(e) { return c.json({ error: e.message }, 500); }
});

app.get('/api/admin/analytics/data', async (c) => {
    try {
        const total = await c.env.DB.prepare("SELECT COUNT(*) as count FROM analytics").first();
        const today = await c.env.DB.prepare("SELECT COUNT(*) as count FROM analytics WHERE date(created_at) = date('now')").first();
        
        const topPages = await c.env.DB.prepare(`SELECT p.title, p.slug, COUNT(a.id) as views FROM pages p LEFT JOIN analytics a ON p.id = a.page_id GROUP BY p.id ORDER BY views DESC LIMIT 10`).all();
        const referrers = await c.env.DB.prepare(`SELECT referrer, COUNT(*) as count FROM analytics WHERE referrer IS NOT NULL AND referrer != '' GROUP BY referrer ORDER BY count DESC LIMIT 10`).all();
        const recent = await c.env.DB.prepare(`SELECT p.title, a.referrer, a.created_at FROM analytics a JOIN pages p ON a.page_id = p.id ORDER BY a.created_at DESC LIMIT 20`).all();

        return c.json({
            stats: { total_views: total?.count || 0, today_views: today?.count || 0 },
            top_pages: topPages.results || [],
            referrers: referrers.results || [],
            recent: recent.results || []
        });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

app.post('/api/admin/pages', async (c) => {
    const { slug, title, html, css, product_config, product_type } = await c.req.json();
    try {
        await c.env.DB.prepare(
            `INSERT INTO pages (slug, title, html_content, css_content, product_config_json, product_type) VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(slug) DO UPDATE SET 
             title=excluded.title, html_content=excluded.html_content, css_content=excluded.css_content, product_config_json=excluded.product_config_json, product_type=excluded.product_type`
        ).bind(slug, title, html, css, JSON.stringify(product_config), product_type || 'physical').run();
        return c.json({ success: true });
    } catch(e) { return c.json({ error: e.message }, 500); }
});

app.get('/api/admin/pages/:slug', async (c) => {
    const slug = c.req.param('slug');
    const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
    if(page) page.product_config_json = JSON.parse(page.product_config_json || '{}');
    return c.json(page || {});
});

app.post('/api/admin/set-homepage', async (c) => {
    try {
        const { slug } = await c.req.json();
        await c.env.DB.prepare("INSERT INTO settings (key, value) VALUES ('homepage_slug', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(slug).run();
        return c.json({ success: true });
    } catch (e) { return c.json({ error: e.message }, 500); }
});

app.get('/api/admin/homepage-slug', async (c) => {
    try {
        const s = await c.env.DB.prepare("SELECT value FROM settings WHERE key='homepage_slug'").first();
        return c.json({ slug: s ? s.value : null });
    } catch(e) { return c.json({ slug: null }); }
});

app.post('/api/admin/credentials', async (c) => {
    const { provider, data } = await c.req.json();
    const { encrypted, iv } = await encryptJSON(data, c.env.APP_MASTER_KEY || JWT_SECRET);
    await c.env.DB.prepare(
        `INSERT INTO credentials (provider_slug, encrypted_data, iv) VALUES (?, ?, ?)
         ON CONFLICT(provider_slug) DO UPDATE SET encrypted_data=excluded.encrypted_data, iv=excluded.iv`
    ).bind(provider, encrypted, iv).run();
    return c.json({ success: true });
});

app.post('/api/admin/upload-image', uploadImage);

app.post('/api/shipping/check', async (c) => {
    try {
        const body = await c.req.json();
        const result = await executeGenericAPI(c, 'shipping', body.slug_shipping, body);
        return c.json(result);
    } catch(e) { return c.json({ success: false, message: e.message }, 500); }
});

// ===============================================
// 5. API PUBLIC (NO AUTH)
// ===============================================
app.post('/api/public/submit-form', async (c) => {
    try {
        const body = await c.req.parseBody();
        const name = body['name'] || 'Anonymous';
        const email = body['email'] || '-';
        const message = body['message'] || JSON.stringify(body);
        await c.env.DB.prepare("INSERT INTO leads (name, email, message, created_at) VALUES (?, ?, ?, datetime('now'))").bind(name, email, message).run();
        return c.redirect((c.req.header('Referer') || '/') + '?status=success');
    } catch (e) { return c.text('Error: ' + e.message, 500); }
});

app.post('/api/public/checkout', async (c) => {
    try {
        const { page_id, customer, items, total, shipping, slug_payment } = await c.req.json();
        const orderId = `ORD-${Date.now()}-${Math.floor(Math.random()*1000)}`;
        await c.env.DB.prepare(`INSERT INTO orders (order_id, page_id, customer_name, customer_phone, customer_address, items_json, total_amount, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))`)
            .bind(orderId, page_id, customer.name, customer.phone, JSON.stringify(shipping || {}), JSON.stringify(items), total).run();
        const provider = slug_payment || 'whatsapp';
        const paymentResult = await executeGenericAPI(c, 'payment', provider, {
            order_id: orderId, amount: total, customer: customer, items: items, shipping: shipping
        });
        return c.json({ success: true, order_id: orderId, payment: paymentResult });
    } catch (e) { return c.json({ success: false, message: e.message }, 500); }
});

app.post('/api/public/shipping', async (c) => {
    try {
        const body = await c.req.json();
        const result = await executeGenericAPI(c, 'shipping', body.slug_shipping, body);
        return c.json(result);
    } catch (e) { return c.json({ success: false, message: e.message }, 500); }
});

// ===============================================
// 6. PUBLIC RENDER & FALLBACK
// ===============================================
app.get('/', async (c) => {
    try {
        const s = await c.env.DB.prepare("SELECT value FROM settings WHERE key='homepage_slug'").first();
        if (s && s.value) {
            const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug = ?").bind(s.value).first();
            if (page) return renderPage(c, page);
        }
    } catch (e) {}
    return serveAsset(c, '/index.html');
});

app.get('/:slug', async (c) => {
    const slug = c.req.param('slug');
    if (slug.includes('.')) return c.env.ASSETS.fetch(c.req.raw);
    try {
        const page = await c.env.DB.prepare("SELECT * FROM pages WHERE slug=?").bind(slug).first();
        if(!page) return c.text('404 Not Found', 404);
        c.env.DB.prepare("INSERT INTO analytics (page_id, event_type, referrer) VALUES (?, 'view', ?)").bind(page.id, c.req.header('Referer') || 'direct').run().catch(()=>{});
        return renderPage(c, page);
    } catch(e) { return c.env.ASSETS.fetch(c.req.raw); }
});

async function renderPage(c, page) {
    const config = JSON.parse(page.product_config_json || '{}');
    const settings = config.settings || {}; 
    const url = c.req.url;
    let headScripts = '';
    if (settings.fb_pixel_id) headScripts += `<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('init', '${settings.fb_pixel_id}');fbq('track', 'PageView');</script>`;
    if (settings.tiktok_pixel_id) headScripts += `<script>!function (w, d, t) { w.TiktokAnalyticsObject=t;var ttq=w[t]=w[t]||[];ttq.methods=["page","track","identify","instances","debug","on","off","once","ready","alias","group","enableCookie","disableCookie"],ttq.setAndDefer=function(t,e){t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}};for(var i=0;i<ttq.methods.length;i++)ttq.setAndDefer(ttq,ttq.methods[i]);ttq.instance=function(t){for(var e=ttq.methods[i],n=0;n<ttq.methods.length;n++)ttq.setAndDefer(e,ttq.methods[n]);return e},ttq.load=function(e,n){var i="https://analytics.tiktok.com/i18n/pixel/events.js";ttq._i=ttq._i||{},ttq._i[e]=[],ttq._i[e]._u=i,ttq._t=ttq._t||{},ttq._t[e]=+new Date,ttq._o=ttq._o||{},ttq._o[e]=n||{};var o=document.createElement("script");o.type="text/javascript",o.async=!0,o.src=i+"?sdkid="+e+"&lib="+t;var a=document.getElementsByTagName("script")[0];a.parentNode.insertBefore(o,a)};ttq.load('${settings.tiktok_pixel_id}');ttq.page();}(window, document, 'ttq');</script>`;
    if (settings.custom_head) headScripts += settings.custom_head;

    const appScript = `<script>window.PAGE_ID=${page.id};window.PRODUCT_TYPE="${page.product_type||'physical'}";window.PRODUCT_VARIANTS=${JSON.stringify(config.variants||[])};window.ORDER_BUMP=${JSON.stringify(config.order_bump||{active:false})};window.SHIPPING_CONFIG=${JSON.stringify(config.shipping||{weight:1000})};</script>`;

    return c.html(`<!DOCTYPE html><html lang="id" style="margin:0;padding:0;"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${settings.seo_title||page.title}</title><meta name="description" content="${settings.seo_description||''}">${settings.favicon?`<link rel="icon" href="${settings.favicon}">`:''}<meta property="og:type" content="website"/><meta property="og:url" content="${url}"/><meta property="og:title" content="${settings.og_title||settings.seo_title||page.title}"/><meta property="og:description" content="${settings.og_description||settings.seo_description||''}"/>${settings.og_image?`<meta property="og:image" content="${settings.og_image}"/>`:''}<script src="https://cdn.tailwindcss.com"></script><script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script><style>html,body{margin:0!important;padding:0!important;width:100%;height:100%;overflow-x:hidden}body::before{content:"";display:table}${page.css_content}[x-cloak]{display:none!important}</style>${headScripts}</head><body class="antialiased" style="margin:0;padding:0;">${page.html_content}${appScript}${settings.custom_footer||''}</body></html>`);
}

app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));
export const onRequest = handle(app);
