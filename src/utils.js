// HASHING (Password Admin)
export async function sha256(text) {
    const msgBuffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// HASHING (Signature Cloudinary)
export async function sha1(str) {
    const enc = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-1', enc.encode(str));
    return Array.from(new Uint8Array(hash)).map(v => v.toString(16).padStart(2, '0')).join('');
}

// ENKRIPSI (AES-GCM untuk Kredensial API)
const toHex = (buf) => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

async function getCryptoKey(secret) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "PBKDF2" }, false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: enc.encode("fixed-salt-landing"), iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

export async function encryptJSON(jsonObj, masterSecret) {
    const str = JSON.stringify(jsonObj);
    const key = await getCryptoKey(masterSecret);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(str));
    return { encrypted: toHex(encrypted), iv: toHex(iv) };
}

export async function decryptJSON(encryptedHex, ivHex, masterSecret) {
    try {
        if (!encryptedHex || !ivHex) return null;
        const key = await getCryptoKey(masterSecret);
        const encrypted = fromHex(encryptedHex);
        const iv = fromHex(ivHex);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
        const decStr = new TextDecoder().decode(decrypted);
        return JSON.parse(decStr);
    } catch (e) {
        console.error("Decryption Failed:", e);
        return null;
    }
}
