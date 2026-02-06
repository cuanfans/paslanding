import { decryptJSON } from './utils';

/**
 * ENGINE PENGENDALI API (GENERIC)
 * Mengurus semua request ke pihak ketiga (Payment & Shipping)
 * berdasarkan resep yang ada di Database.
 */
export async function executeGenericAPI(c, type, slug, payload) {
    // Tentukan tabel target berdasarkan tipe
    const tableName = type === 'payment' ? 'payment_templates' : 'shipping_templates';
    
    // 1. Ambil Resep API & Kredensial dari DB
    const template = await c.env.DB.prepare(`SELECT * FROM ${tableName} WHERE slug = ?`).bind(slug).first();
    const credRow = await c.env.DB.prepare("SELECT * FROM credentials WHERE provider_slug = ?").bind(slug).first();
    
    // Error handling yang jelas
    if (!template) throw new Error(`Template '${slug}' (${type}) tidak ditemukan di database.`);
    if (!credRow) throw new Error(`Kredensial untuk '${slug}' belum diatur di settings.`);

    // 2. Dekripsi Kredensial (Server Key, API Key, dll)
    const creds = await decryptJSON(credRow.encrypted_data, credRow.iv, c.env.APP_MASTER_KEY);
    if (!creds) throw new Error("Gagal mendekripsi kredensial API. Cek APP_MASTER_KEY.");

    // 3. Gabungkan Data (Payload dari Frontend + Kredensial dari DB)
    const context = {
        ...payload,      // data order_id, amount, weight, destination, dll
        ...creds,        // server_key, client_key, api_key
        timestamp: Date.now(),
        // Helper khusus: seringkali API butuh base64 dari server_key (misal Midtrans/Xendit)
        auth_basic: creds.server_key ? btoa(creds.server_key + ':') : '' 
    };

    // FUNGSI HYDRATOR: Mengganti {{variable}} dengan data asli
    // Mendukung nested object misal {{customer.email}} atau {{shipping.courier}}
    const hydrate = (str) => {
        if (!str || typeof str !== 'string') return str || '';
        return str.replace(/{{(.*?)}}/g, (_, key) => {
            const keys = key.trim().split('.');
            let value = context;
            for (const k of keys) {
                value = value?.[k];
            }
            return value !== undefined ? value : '';
        });
    };

    // 4. Rakit Header
    const headersRaw = JSON.parse(template.headers_json || '{}');
    const headers = {};
    Object.keys(headersRaw).forEach(k => {
        headers[k] = hydrate(headersRaw[k]);
    });

    // 5. Rakit Body (Jika bukan GET)
    let bodyData = null;
    if (template.method !== 'GET') {
        // Kita hydrate string JSON-nya dulu, baru di-parse atau dikirim string
        // Namun fetch body butuh string, jadi kita hydrate text-nya saja.
        bodyData = hydrate(template.body_json);
    }

    // 6. TEMBAK API PIHAK KETIGA
    console.log(`[GenericEngine] ${template.method} to ${template.api_endpoint}`);
    
    const res = await fetch(template.api_endpoint, {
        method: template.method,
        headers: headers,
        body: bodyData
    });

    // Handle jika response bukan JSON (kadang error HTML)
    const contentType = res.headers.get("content-type");
    let jsonResponse = {};
    if (contentType && contentType.indexOf("application/json") !== -1) {
        jsonResponse = await res.json();
    } else {
        const text = await res.text();
        throw new Error(`API Error (${res.status}): ${text.substring(0, 100)}`);
    }

    // 7. NORMALISASI RESPON (Response Mapping)
    // Agar frontend menerima format yang konsisten (success, token, cost, dll)
    // terlepas dari apapun bentuk respon vendor.
    const mapping = JSON.parse(template.response_mapping || '{}');
    const finalResult = { 
        success: true, 
        raw: jsonResponse // Sertakan raw data untuk debugging user admin
    };

    // Jalankan mapping: Ambil data dari path JSON vendor -> Masukkan ke key standar kita
    Object.keys(mapping).forEach(targetKey => {
        const sourcePath = mapping[targetKey]; // misal "rajaongkir.results.0.costs"
        const keys = sourcePath.split('.');
        let value = jsonResponse;
        
        for (const k of keys) {
            // Handle array index jika ada, misal "results.0"
            if (Array.isArray(value) && !isNaN(k)) {
                value = value[parseInt(k)];
            } else {
                value = value?.[k];
            }
            if (value === undefined) break;
        }
        finalResult[targetKey] = value;
    });

    return finalResult;
}
