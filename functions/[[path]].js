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
// UTILITY FUNCTIONS - PASSWORD HASHING WITH SALT
// ===============================================

/**
 * Generate random salt untuk password hashing
 * @param {number} length - Panjang salt (default 16)
 * @returns {string} Random salt string
 */
function randomSalt(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    let salt = ''
    for (let i = 0; i < length; i++) {
        salt += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    return salt
}

/**
 * Hash password dengan salt
 * Format: salt:hash
 * @param {string} password - Password plain text
 * @returns {Promise<string>} Hash dengan format salt:hash
 */
async function hashPassword(password) {
    const salt = randomSalt(16)
    const hash = await sha256(salt + password)
    return `${salt}:${hash}`
}

/**
 * Verify password dengan salt
 * @param {string} password - Password plain text dari input user
 * @param {string} stored - Hash yang tersimpan di database (format: salt:hash)
 * @returns {Promise<boolean>} True jika password cocok
 */
async function verifyPassword(password, stored) {
    // Format stored harus: salt:hash
    if (!stored || !stored.includes(':')) {
        return false
    }
    const [salt, hash] = stored.split(':')
    if (!salt || !hash) {
        return false
    }
    const input = await sha256(salt + password)
    return input === hash
}

// ===============================================
// 0. GLOBAL ERROR & ASSETS
// ===============================================

/**
 * Global error handler
 */
app.onError((err, c) => {
    console.error(`[ERROR] ${err.message}`, err.stack)
    return c.json({ 
        success: false, 
        message: 'Internal Server Error',
        error: err.message 
    }, 500)
})

/**
 * Serve static asset dari ASSETS binding
 * @param {Context} c - Hono context
 * @param {string} path - Path file yang ingin diakses
 * @returns {Response} File response atau 404
 */
async function serveAsset(c, path) {
    try {
        const url = new URL(path, c.req.url)
        const response = await c.env.ASSETS.fetch(url)
        
        // Jangan cache HTML file
        if (path.endsWith('.html')) {
            const newResponse = new Response(response.body, response)
            newResponse.headers.set('Cache-Control', 'no-store, max-age=0')
            newResponse.headers.set('Pragma', 'no-cache')
            newResponse.headers.set('Expires', '0')
            return newResponse
        }
        
        return response
    } catch (e) {
        console.error(`[ASSET ERROR] Path: ${path}`, e)
        return c.text('Asset Not Found', 404)
    }
}

// ===============================================
// 1. MIDDLEWARE AUTH (PERBAIKAN TOTAL)
// ===============================================

/**
 * Authentication middleware
 * - Level 1: Whitelist public paths (login, setup, public APIs)
 * - Level 2: Static assets whitelist (assets, public, static folders)
 * - Level 3: Protected routes (cek JWT token)
 */
const requireAuth = async (c, next) => {
    const url = new URL(c.req.url)
    const path = url.pathname

    console.log(`[AUTH] Checking path: ${path}`)

    // ============================================
    // LEVEL 1: WHITELIST - PUBLIC PATHS
    // ============================================
    // Paths yang TIDAK perlu token untuk diakses
    const publicPaths = [
        '/login',                   // Login page
        '/admin/login',             // Redirect ke login
        '/api/login',               // Login API endpoint
        '/api/setup-first-user',    // Setup admin pertama kali
        '/api/public/'              // Public APIs (checkout, form, dll)
    ]

    const isPublicPath = publicPaths.some(p => path === p || path.startsWith(p))

    if (isPublicPath) {
        console.log(`[AUTH] Public path allowed: ${path}`)
        await next()
        return
    }

    // ============================================
    // LEVEL 2: STATIC ASSETS WHITELIST
    // ============================================
    // Hanya izinkan file .js, .css, .png, .jpg, dll dari folder publik tertentu
    if (path.includes('.')) {
        const publicAssetFolders = [
            '/assets/',
            '/public/',
            '/static/',
            '/css/',
            '/js/',
            '/images/',
            '/fonts/'
        ]

        const isPublicAsset = publicAssetFolders.some(p => path.startsWith(p)) ||
            ['/favicon.ico', '/robots.txt', '/sitemap.xml', '/manifest.json'].some(f => path === f)

        if (isPublicAsset) {
            console.log(`[AUTH] Public asset allowed: ${path}`)
            await next()
            return
        }

        // File di /_views dan /admin JANGAN diloloskan tanpa token
        // (akan dicheck di LEVEL 3)
        console.log(`[AUTH] Protected asset requires token: ${path}`)
    }

    // ============================================
    // LEVEL 3: PROTECTED ROUTES - CEK TOKEN
    // ============================================
    // Semua path yang bukan public atau public asset harus ada token

    let token = getCookie(c, 'auth_token')
    console.log(`[AUTH] Token dari cookie: ${token ? 'ada' : 'tidak ada'}`)

    // Coba ambil dari Authorization header jika tidak ada di cookie
    const authHeader = c.req.header('Authorization')
    if (!token && authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1]
        console.log(`[AUTH] Token dari Authorization header: ada`)
    }

    // Jika tidak ada token sama sekali
    if (!token) {
        console.log(`[AUTH] No token found for path: ${path}`)
        
        if (path.startsWith('/api/')) {
            return c.json({ 
                success: false, 
                error: 'Unauthorized',
                message: 'Token tidak ditemukan. Silakan login terlebih dahulu.' 
            }, 401)
        }
        
        // Redirect ke login
        return c.redirect('/login')
    }

    // Verifikasi token JWT
    try {
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET
        const payload = await verify(token, secret)

        console.log(`[AUTH] Token valid for user: ${payload.email}`)

        // Simpan user data di context untuk diakses handler
        c.set('user', payload)

        await next()

        // Set anti-cache headers untuk page admin
        c.res.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        c.res.headers.set('Pragma', 'no-cache')
        c.res.headers.set('Expires', '0')

    } catch (e) {
        console.error(`[AUTH] Token verification failed: ${e.message}`)

        // Hapus cookie yang tidak valid
        deleteCookie(c, 'auth_token')

        if (path.startsWith('/api/')) {
            return c.json({ 
                success: false, 
                error: 'Invalid Token',
                message: 'Token tidak valid atau sudah kadaluarsa' 
            }, 401)
        }

        // Redirect ke login
        return c.redirect('/login')
    }
}

// Apply middleware ke semua route
app.use('*', requireAuth)

// ===============================================
// 2. AUTH ROUTES
// ===============================================

/**
 * LOGIN ENDPOINT
 * POST /api/login
 * Body: { email: string, password: string }
 * Response: { success: boolean, token?: string, user?: object }
 */
app.post('/api/login', async (c) => {
    try {
        console.log('[LOGIN] Login attempt received')

        // Parse request body
        const body = await c.req.json()
        const { email, password } = body

        // Validasi input
        if (!email || !password) {
            console.log('[LOGIN] Missing email or password')
            return c.json({
                success: false,
                message: 'Email dan password harus diisi'
            }, 400)
        }

        console.log(`[LOGIN] Login attempt for email: ${email}`)

        // Cari user di database
        const user = await c.env.DB.prepare(
            "SELECT id, email, password, name, role FROM users WHERE email = ?"
        ).bind(email).first()

        if (!user) {
            console.log(`[LOGIN] User not found: ${email}`)
            return c.json({
                success: false,
                message: 'Email atau password salah'
            }, 401)
        }

        console.log(`[LOGIN] User found: ${email}`)

        // Verify password dengan salt
        const passwordMatch = await verifyPassword(password, user.password)

        if (!passwordMatch) {
            console.log(`[LOGIN] Password mismatch for user: ${email}`)
            return c.json({
                success: false,
                message: 'Email atau password salah'
            }, 401)
        }

        console.log(`[LOGIN] Password verified for user: ${email}`)

        // Generate JWT token
        const secret = c.env.APP_MASTER_KEY || JWT_SECRET
        const token = await sign(
            {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                exp: Math.floor(Date.now() / 1000) + 86400  // 24 jam
            },
            secret
        )

        console.log(`[LOGIN] JWT token generated for user: ${email}`)

        // Set auth cookie
        setCookie(c, 'auth_token', token, {
            path: '/',
            secure: true,        // HTTPS only
            httpOnly: true,      // Tidak bisa diakses JavaScript
            maxAge: 86400,       // 24 jam
            sameSite: 'Strict'   // Strict CSRF protection
        })

        console.log(`[LOGIN] Cookie set for user: ${email}`)

        return c.json({
            success: true,
            message: 'Login berhasil',
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        })

    } catch (e) {
        console.error('[LOGIN] Error:', e.message, e.stack)
        return c.json({
            success: false,
            error: 'Internal Server Error',
            message: e.message
        }, 500)
    }
})

/**
 * SETUP FIRST USER ENDPOINT
 * POST /api/setup-first-user
 * Body: { email: string, password: string, name?: string }
 * Response: { success: boolean, message: string }
 * NOTE: Hanya bisa dijalankan jika belum ada user di database
 */
app.post('/api/setup-first-user', async (c) => {
    try {
        console.log('[SETUP] Setup first user attempt')

        // Cek apakah sudah ada user sebelumnya
        const existingUserCount = await c.env.DB.prepare(
            "SELECT COUNT(*) as count FROM users"
        ).first()

        if (existingUserCount && existingUserCount.count > 0) {
            console.log('[SETUP] Users already exist, setup blocked')
            return c.json({
                success: false,
                message: 'User sudah ada. Setup hanya bisa dilakukan sekali.'
            }, 403)
        }

        // Parse request body
        const body = await c.req.json()
        const { email, password, name } = body

        // Validasi input
        if (!email || !password) {
            console.log('[SETUP] Missing email or password')
            return c.json({
                success: false,
                message: 'Email dan password harus diisi'
            }, 400)
        }

        if (password.length < 6) {
            console.log('[SETUP] Password too short')
            return c.json({
                success: false,
                message: 'Password minimal 6 karakter'
            }, 400)
        }

        console.log(`[SETUP] Creating first user: ${email}`)

        // Hash password dengan salt
        const hashedPassword = await hashPassword(password)

        // Insert user ke database
        const result = await c.env.DB.prepare(
            "INSERT INTO users (email, password, name, role, created_at) VALUES (?, ?, ?, 'admin', datetime('now'))"
        ).bind(email, hashedPassword, name || 'Admin').run()

        console.log(`[SETUP] User created successfully: ${email}`)

        return c.json({
            success: true,
            message: 'User admin berhasil dibuat',
            user: {
                email: email,
                name: name || 'Admin',
                role: 'admin'
            }
        })

    } catch (e) {
        console.error('[SETUP] Error:', e.message, e.stack)
        return c.json({
            success: false,
            error: 'Internal Server Error',
            message: e.message
        }, 500)
    }
})

/**
 * LOGOUT ENDPOINT
 * GET /api/logout
 */
app.get('/api/logout', (c) => {
    console.log('[LOGOUT] User logout')
    deleteCookie(c, 'auth_token')
    return c.json({
        success: true,
        message: 'Logout berhasil'
    })
})

/**
 * GET CURRENT USER ENDPOINT
 * GET /api/user/me
 */
app.get('/api/user/me', (c) => {
    try {
        const user = c.get('user')

        if (!user) {
            return c.json({
                success: false,
                message: 'User tidak ditemukan'
            }, 401)
        }

        return c.json({
            success: true,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role
            }
        })

    } catch (e) {
        console.error('[GET USER] Error:', e.message)
        return c.json({
            success: false,
            message: e.message
        }, 500)
    }
})

// ===============================================
// 3. ADMIN ROUTES MAPPING
// ===============================================

/**
 * Login page
 * GET /login
 */
app.get('/login', (c) => {
    console.log('[ROUTE] Serving login page')
    return serveAsset(c, '/login.html')
})

/**
 * Redirect admin login to login
 * GET /admin/login
 */
app.get('/admin/login', (c) => {
    console.log('[ROUTE] Redirecting /admin/login to /login')
    return c.redirect('/login')
})

/**
 * Admin dashboard pages
 */
app.get('/admin', (c) => {
    console.log('[ROUTE] Redirecting /admin to /admin/dashboard')
    return c.redirect('/admin/dashboard')
})

app.get('/admin/dashboard', (c) => {
    console.log('[ROUTE] Serving /admin/dashboard')
    return serveAsset(c, '/_views/dashboard.html')
})

app.get('/admin/pages', (c) => {
    console.log('[ROUTE] Serving /admin/pages')
    return serveAsset(c, '/_views/pages.html')
})

app.get('/admin/editor', (c) => {
    console.log('[ROUTE] Serving /admin/editor')
    return serveAsset(c, '/_views/editor.html')
})

app.get('/admin/reports', (c) => {
    console.log('[ROUTE] Serving /admin/reports')
    return serveAsset(c, '/_views/reports.html')
})

app.get('/admin/analytics', (c) => {
    console.log('[ROUTE] Serving /admin/analytics')
    return serveAsset(c, '/_views/analytics.html')
})

app.get('/admin/settings', (c) => {
    console.log('[ROUTE] Serving /admin/settings')
    return serveAsset(c, '/_views/settings.html')
})

/**
 * Block direct access to _views folder
 * GET /_views*
 */
app.get('/_views*', (c) => {
    console.log('[ROUTE] Blocked direct access to _views')
    return c.redirect('/login')
})

// ===============================================
// 4. API DATA ROUTES (ADMIN)
// ===============================================

/**
 * GET PAGES LIST
 * GET /api/admin/pages
 */
app.get('/api/admin/pages', async (c) => {
    try {
        console.log('[API] Fetching pages list')

        const user = c.get('user')
        if (!user || user.role !== 'admin') {
            console.log('[API] Unauthorized pages list access')
            return c.json({
                success: false,
                error: 'Forbidden'
            }, 403)
        }

        const res = await c.env.DB.prepare(
            "SELECT id, slug, title, product_type, created_at FROM pages ORDER BY created_at DESC"
        ).all()

        return c.json({
            success: true,
            data: res.results || []
        })

    } catch (e) {
        console.error('[API] Pages list error:', e.message)
        return c.json({
            success: false,
            error: e.message
        }, 500)
    }
})

/**
 * GET ANALYTICS DATA
 * GET /api/admin/analytics/data
 */
app.get('/api/admin/analytics/data', async (c) => {
    try {
        console.log('[API] Fetching analytics data')

        const user = c.get('user')
        if (!user || user.role !== 'admin') {
            console.log('[API] Unauthorized analytics access')
            return c.json({
                success: false,
                error: 'Forbidden'
            }, 403)
        }

        const total = await c.env.DB.prepare(
            "SELECT COUNT(*) as count FROM analytics"
        ).first()

        const today = await c.env.DB.prepare(
            "SELECT COUNT(*) as count FROM analytics WHERE date(created_at) = date('now')"
        ).first()

        const topPages = await c.env.DB.prepare(`
            SELECT p.id, p.title, p.slug, COUNT(a.id) as views 
            FROM pages p 
            LEFT JOIN analytics a ON p.id = a.page_id 
            GROUP BY p.id 
            ORDER BY views DESC 
            LIMIT 10
        `).all()

        const referrers = await c.env.DB.prepare(`
            SELECT referrer, COUNT(*) as count 
            FROM analytics 
            WHERE referrer IS NOT NULL AND referrer != ''
            GROUP BY referrer 
            ORDER BY count DESC 
            LIMIT 10
        `).all()

        const recent = await c.env.DB.prepare(`
            SELECT p.title, a.referrer, a.created_at 
            FROM analytics a 
            JOIN pages p ON a.page_id = p.id 
            ORDER BY a.created_at DESC 
            LIMIT 20
        `).all()

        return c.json({
            success: true,
            stats: {
                total_views: total?.count || 0,
                today_views: today?.count || 0
            },
            top_pages: topPages.results || [],
            referrers: referrers.results || [],
            recent: recent.results || []
        })

    } catch (e) {
        console.error('[API] Analytics error:', e.message)
        return c.json({
            success: false,
            error: e.message
        }, 500)
    }
})

/**
 * CREATE/UPDATE PAGE
 * POST /api/admin/pages
 */
app.post('/api/admin/pages', async (c) => {
    try {
        console.log('[API] Creating/updating page')

        const user = c.get('user')
        if (!user || user.role !== 'admin') {
            console.log('[API] Unauthorized page creation')
            return c.json({
                success: false,
                error: 'Forbidden'
            }, 403)
        }

        const { slug, title, html, css, product_config, product_type } = await c.req.json()

        if (!slug || !title) {
            return c.json({
                success: false,
                message: 'Slug dan title harus diisi'
            }, 400)
        }

        await c.env.DB.prepare(`
            INSERT INTO pages (
                slug,
                title,
                html_content,
                css_content,
                product_config_json,
                product_type,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(slug) DO UPDATE SET
                title=excluded.title,
                html_content=excluded.html_content,
                css_content=excluded.css_content,
                product_config_json=excluded.product_config_json,
                product_type=excluded.product_type,
                updated_at=datetime('now')
        `).bind(
            slug,
            title,
            html || '',
            css || '',
            JSON.stringify(product_config || {}),
            product_type || 'physical'
        ).run()

        console.log(`[API] Page created/updated: ${slug}`)

        return c.json({
            success: true,
            message: 'Page berhasil disimpan'
        })

    } catch (e) {
        console.error('[API] Page creation error:', e.message)
        return c.json({
            success: false,
            error: e.message
        }, 500)
    }
})

/**
 * GET PAGE BY SLUG
 * GET /api/admin/pages/:slug
 */
app.get('/api/admin/pages/:slug', async (c) => {
    try {
        console.log('[API] Fetching page by slug')

        const user = c.get('user')
        if (!user || user.role !== 'admin') {
            console.log('[API] Unauthorized page access')
            return c.json({
                success: false,
                error: 'Forbidden'
            }, 403)
        }

        const slug = c.req.param('slug')

        const page = await c.env.DB.prepare(
            "SELECT * FROM pages WHERE slug = ?"
        ).bind(slug).first()

        if (!page) {
            return c.json({
                success: false,
                message: 'Page tidak ditemukan'
            }, 404)
        }

        if (page.product_config_json) {
            try {
                page.product_config_json = JSON.parse(page.product_config_json)
            } catch (e) {
                page.product_config_json = {}
            }
        }

        return c.json({
            success: true,
            data: page
        })

    } catch (e) {
        console.error('[API] Page fetch error:', e.message)
        return c.json({
            success: false,
            error: e.message
        }, 500)
    }
})

/**
 * SET HOMEPAGE
 * POST /api/admin/set-homepage
 */
app.post('/api/admin/set-homepage', async (c) => {
    try {
        console.log('[API] Setting homepage')

        const user = c.get('user')
        if (!user || user.role !== 'admin') {
            console.log('[API] Unauthorized homepage setting')
            return c.json({
                success: false,
                error: 'Forbidden'
            }, 403)
        }

        const { slug } = await c.req.json()

        if (!slug) {
            return c.json({
                success: false,
                message: 'Slug harus diisi'
            }, 400)
        }

        const page = await c.env.DB.prepare(
            "SELECT id FROM pages WHERE slug = ?"
        ).bind(slug).first()

        if (!page) {
            return c.json({
                success: false,
                message: 'Page tidak ditemukan'
            }, 404)
        }

        await c.env.DB.prepare(
            "INSERT INTO settings (key, value, updated_at) VALUES ('homepage_slug', ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')"
        ).bind(slug).run()

        console.log(`[API] Homepage set to: ${slug}`)

        return c.json({
            success: true,
            message: 'Homepage berhasil diatur'
        })

    } catch (e) {
        console.error('[API] Homepage setting error:', e.message)
        return c.json({
            success: false,
            error: e.message
        }, 500)
    }
})

/**
 * GET HOMEPAGE SLUG
 * GET /api/admin/homepage-slug
 */
app.get('/api/admin/homepage-slug', async (c) => {
    try {
        const s = await c.env.DB.prepare(
            "SELECT value FROM settings WHERE key = 'homepage_slug'"
        ).first()

        return c.json({
            success: true,
            slug: s ? s.value : null
        })

    } catch (e) {
        console.error('[API] Homepage slug error:', e.message)
        return c.json({
            success: true,
            slug: null
        })
    }
})

/**
 * SET CREDENTIALS
 * POST /api/admin/credentials
 */
app.post('/api/admin/credentials', async (c) => {
    try {
        console.log('[API] Setting credentials')

        const user = c.get('user')
        if (!user || user.role !== 'admin') {
            console.log('[API] Unauthorized credentials setting')
            return c.json({
                success: false,
                error: 'Forbidden'
            }, 403)
        }

        const { provider, data } = await c.req.json()

        if (!provider || !data) {
            return c.json({
                success: false,
                message: 'Provider dan data harus diisi'
            }, 400)
        }

        const { encrypted, iv } = await encryptJSON(data, c.env.APP_MASTER_KEY || JWT_SECRET)

        await c.env.DB.prepare(`
            INSERT INTO credentials (
                provider_slug,
                encrypted_data,
                iv,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(provider_slug) DO UPDATE SET
                encrypted_data=excluded.encrypted_data,
                iv=excluded.iv,
                updated_at=datetime('now')
        `).bind(provider, encrypted, iv).run()

        console.log(`[API] Credentials saved for: ${provider}`)

        return c.json({
            success: true,
            message: 'Credentials berhasil disimpan'
        })

    } catch (e) {
        console.error('[API] Credentials error:', e.message)
        return c.json({
            success: false,
            error: e.message
        }, 500)
    }
})

/**
 * UPLOAD IMAGE
 * POST /api/admin/upload-image
 */
app.post('/api/admin/upload-image', uploadImage)

/**
 * CHECK SHIPPING
 * POST /api/shipping/check
 */
app.post('/api/shipping/check', async (c) => {
    try {
        console.log('[API] Checking shipping')

        const body = await c.req.json()
        const result = await executeGenericAPI(c, 'shipping', body.slug_shipping, body)

        return c.json({
            success: true,
            data: result
        })

    } catch (e) {
        console.error('[API] Shipping check error:', e.message)
        return c.json({
            success: false,
            message: e.message
        }, 500)
    }
})

// ===============================================
// 5. API PUBLIC (NO AUTH REQUIRED)
// ===============================================

/**
 * SUBMIT FORM
 * POST /api/public/submit-form
 */
app.post('/api/public/submit-form', async (c) => {
    try {
        console.log('[PUBLIC API] Form submission received')

        const body = await c.req.parseBody()
        const name = (body['name'] as string) || 'Anonymous'
        const email = (body['email'] as string) || '-'
        const message = (body['message'] as string) || JSON.stringify(body)

        await c.env.DB.prepare(`
            INSERT INTO leads (name, email, message, created_at)
            VALUES (?, ?, ?, datetime('now'))
        `).bind(name, email, message).run()

        console.log(`[PUBLIC API] Form submitted by: ${name}`)

        const referer = c.req.header('Referer') || '/'
        return c.redirect(referer + '?status=success')

    } catch (e) {
        console.error('[PUBLIC API] Form submission error:', e.message)
        return c.text('Error: ' + e.message, 500)
    }
})

/**
 * CHECKOUT
 * POST /api/public/checkout
 */
app.post('/api/public/checkout', async (c) => {
    try {
        console.log('[PUBLIC API] Checkout initiated')

        const { page_id, customer, items, total, shipping, slug_payment } = await c.req.json()

        if (!page_id || !customer || !items || !total) {
            console.log('[PUBLIC API] Missing required checkout data')
            return c.json({
                success: false,
                message: 'Data tidak lengkap'
            }, 400)
        }

        const orderId = `ORD-${Date.now()}-${Math.floor(Math.random() * 1000)}`

        console.log(`[PUBLIC API] Creating order: ${orderId}`)

        await c.env.DB.prepare(`
            INSERT INTO orders (
                order_id,
                page_id,
                customer_name,
                customer_phone,
                customer_address,
                items_json,
                total_amount,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
        `).bind(
            orderId,
            page_id,
            customer.name || '',
            customer.phone || '',
            JSON.stringify(shipping || {}),
            JSON.stringify(items || []),
            total
        ).run()

        console.log(`[PUBLIC API] Order created: ${orderId}`)

        const payload = {
            order_id: orderId,
            amount: total,
            customer: customer,
            items: items,
            shipping: shipping
        }

        const provider = slug_payment || 'whatsapp'

        console.log(`[PUBLIC API] Processing payment with provider: ${provider}`)

        const paymentResult = await executeGenericAPI(c, 'payment', provider, payload)

        console.log(`[PUBLIC API] Payment result received for order: ${orderId}`)

        return c.json({
            success: true,
            message: 'Order berhasil dibuat',
            order_id: orderId,
            payment: paymentResult
        })

    } catch (e) {
        console.error('[PUBLIC API] Checkout error:', e.message, e.stack)
        return c.json({
            success: false,
            message: e.message
        }, 500)
    }
})

/**
 * PUBLIC SHIPPING
 * POST /api/public/shipping
 */
app.post('/api/public/shipping', async (c) => {
    try {
        console.log('[PUBLIC API] Shipping calculation requested')

        const body = await c.req.json()

        if (!body.slug_shipping) {
            return c.json({
                success: false,
                message: 'Slug shipping harus diisi'
            }, 400)
        }

        const result = await executeGenericAPI(c, 'shipping', body.slug_shipping, body)

        return c.json({
            success: true,
            data: result
        })

    } catch (e) {
        console.error('[PUBLIC API] Shipping error:', e.message)
        return c.json({
            success: false,
            message: e.message
        }, 500)
    }
})

// ===============================================
// 6. PUBLIC RENDER & FALLBACK
// ===============================================

/**
 * ROOT PATH
 * GET /
 */
app.get('/', async (c) => {
    try {
        console.log('[ROUTE] Root path requested')

        const s = await c.env.DB.prepare(
            "SELECT value FROM settings WHERE key = 'homepage_slug'"
        ).first()

        if (s && s.value) {
            console.log(`[ROUTE] Homepage slug found: ${s.value}`)

            const page = await c.env.DB.prepare(
                "SELECT * FROM pages WHERE slug = ?"
            ).bind(s.value).first()

            if (page) {
                console.log(`[ROUTE] Rendering homepage: ${s.value}`)
                return renderPage(c, page)
            }
        }

        console.log('[ROUTE] No homepage set, serving index.html')
        return serveAsset(c, '/index.html')

    } catch (e) {
        console.error('[ROUTE] Root path error:', e.message)
        return serveAsset(c, '/index.html')
    }
})

/**
 * PAGE BY SLUG
 * GET /:slug
 */
app.get('/:slug', async (c) => {
    try {
        const slug = c.req.param('slug')
        console.log(`[ROUTE] Page requested: ${slug}`)

        if (slug.includes('.')) {
            console.log(`[ROUTE] File request detected: ${slug}`)
            return c.env.ASSETS.fetch(c.req.raw)
        }

        const page = await c.env.DB.prepare(
            "SELECT * FROM pages WHERE slug = ?"
        ).bind(slug).first()

        if (!page) {
            console.log(`[ROUTE] Page not found: ${slug}`)
            return c.text('404 Not Found', 404)
        }

        console.log(`[ROUTE] Page found: ${slug}`)

        c.env.DB.prepare(`
            INSERT INTO analytics (page_id, event_type, referrer, created_at)
            VALUES (?, 'view', ?, datetime('now'))
        `).bind(
            page.id,
            c.req.header('Referer') || 'direct'
        ).run().catch((e) => {
            console.error('[ANALYTICS] Error logging view:', e.message)
        })

        return renderPage(c, page)

    } catch (e) {
        console.error('[ROUTE] Page render error:', e.message)
        return c.env.ASSETS.fetch(c.req.raw)
    }
})

/**
 * RENDER PAGE FUNCTION
 * Mengubah page data menjadi HTML render
 */
async function renderPage(c, page) {
    try {
        console.log(`[RENDER] Rendering page: ${page.slug}`)

        let config = {}
        try {
            config = JSON.parse(page.product_config_json || '{}')
        } catch (e) {
            console.error('[RENDER] Error parsing product config:', e.message)
            config = {}
        }

        const settings = config.settings || {}
        const url = c.req.url

        let headScripts = ''

        // Facebook Pixel
        if (settings.fb_pixel_id) {
            console.log(`[RENDER] Adding Facebook Pixel: ${settings.fb_pixel_id}`)
            headScripts += `<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('init', '${settings.fb_pixel_id}');fbq('track', 'PageView');</script><noscript><img height="1" width="1" style="display:none" src="https://www.facebook.com/tr?id=${settings.fb_pixel_id}&ev=PageView&noscript=1"/></noscript>`
        }

        // TikTok Pixel
        if (settings.tiktok_pixel_id) {
            console.log(`[RENDER] Adding TikTok Pixel: ${settings.tiktok_pixel_id}`)
            headScripts += `<script>!function (w, d, t) { w.TiktokAnalyticsObject=t;var ttq=w[t]=w[t]||[];ttq.methods=["page","track","identify","instances","debug","on","off","once","ready","alias","group","enableCookie","disableCookie"],ttq.setAndDefer=function(t,e){t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}};for(var i=0;i<ttq.methods.length;i++)ttq.setAndDefer(ttq,ttq.methods[i]);ttq.instance=function(t){for(var e=ttq.methods[i],n=0;n<ttq.methods.length;n++)ttq.setAndDefer(e,ttq.methods[n]);return e},ttq.load=function(e,n){var i="https://analytics.tiktok.com/i18n/pixel/events.js";ttq._i=ttq._i||{},ttq._i[e]=[],ttq._i[e]._u=i,ttq._t=ttq._t||{},ttq._t[e]=+new Date,ttq._o=ttq._o||{},ttq._o[e]=n||{};var o=document.createElement("script");o.type="text/javascript",o.async=!0,o.src=i+"?sdkid="+e+"&lib="+t;var a=document.getElementsByTagName("script")[0];a.parentNode.insertBefore(o,a)};ttq.load('${settings.tiktok_pixel_id}');ttq.page();}(window, document, 'ttq');</script>`
        }

        // Custom head scripts
        if (settings.custom_head) {
            console.log('[RENDER] Adding custom head scripts')
            headScripts += settings.custom_head
        }

        // App script dengan config
        const appScript = `
        <script>
            window.PAGE_ID = ${page.id};
            window.PRODUCT_TYPE = "${page.product_type || 'physical'}";
            window.PRODUCT_VARIANTS = ${JSON.stringify(config.variants || [])};
            window.ORDER_BUMP = ${JSON.stringify(config.order_bump || { active: false })};
            window.SHIPPING_CONFIG = ${JSON.stringify(config.shipping || { weight: 1000 })};

            document.addEventListener('DOMContentLoaded', () => {
                const checkoutContainer = document.querySelector('[data-gjs-type="checkout-widget"]');
                if(checkoutContainer) {
                    console.log('Checkout Widget Detected');
                }
            });
        </script>`

        // Build HTML
        const html = `
        <!DOCTYPE html>
        <html lang="id" style="margin:0; padding:0;">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${escapeHtml(settings.seo_title || page.title)}</title>
            <meta name="description" content="${escapeHtml(settings.seo_description || '')}">
            ${settings.favicon ? `<link rel="icon" href="${escapeHtml(settings.favicon)}">` : ''}
            <meta property="og:type" content="website" />
            <meta property="og:url" content="${escapeHtml(url)}" />
            <meta property="og:title" content="${escapeHtml(settings.og_title || settings.seo_title || page.title)}" />
            <meta property="og:description" content="${escapeHtml(settings.og_description || settings.seo_description || '')}" />
            ${settings.og_image ? `<meta property="og:image" content="${escapeHtml(settings.og_image)}" />` : ''}
            <script src="https://cdn.tailwindcss.com"><\/script>
            <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"><\/script>
            <style>
                html, body { margin: 0 !important; padding: 0 !important; width: 100%; height: 100%; overflow-x: hidden; }
                body::before { content: ""; display: table; }
                ${page.css_content || ''}
                [x-cloak] { display: none !important; }
            </style>
            ${headScripts}
        </head>
        <body class="antialiased" style="margin:0; padding:0;">
            ${page.html_content || ''}
            ${appScript}
            ${settings.custom_footer || ''}
        </body>
        </html>`

        console.log(`[RENDER] Page rendered successfully: ${page.slug}`)

        return c.html(html)

    } catch (e) {
        console.error('[RENDER] Page render error:', e.message, e.stack)
        return c.text('Error rendering page', 500)
    }
}

/**
 * ESCAPE HTML - Prevent XSS
 */
function escapeHtml(text) {
    if (!text) return ''
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    }
    return String(text).replace(/[&<>"']/g, m => map[m])
}

/**
 * FALLBACK - Serve static assets
 * GET *
 */
app.get('*', (c) => {
    console.log(`[FALLBACK] Asset request: ${c.req.path}`)
    return c.env.ASSETS.fetch(c.req.raw)
})

// ===============================================
// EXPORT
// ===============================================

export const onRequest = handle(app)
