import { Redis } from '@upstash/redis';
import crypto from 'crypto';

const kv = new Redis({
    url: process.env.KV_REST_API_URL,
    token: process.env.KV_REST_API_TOKEN,
});

function cors(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Secret');
}

function generateKey() {
    const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
    return `GB-${seg()}-${seg()}-${seg()}`;
}

export default async function handler(req, res) {
    cors(res);
    if (req.method === 'OPTIONS') return res.status(200).end();

    const url = new URL(req.url, `https://${req.headers.host}`);
    const pathname = url.pathname;

    // ── VALIDATE LICENSE ─────────────────────────────────────
    // POST /api/validate-license
    // Body: { "license_key": "GB-XXXX-XXXX-XXXX" }
    if (pathname === '/api/validate-license') {
        if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
        const { license_key } = req.body;
        if (!license_key) return res.status(400).json({ ok: false, error: 'license_key required' });

        const record = await kv.get(`license:${license_key}`);
        if (!record) return res.status(200).json({ ok: false, error: 'Invalid license key' });
        if (!record.active) return res.status(200).json({ ok: false, error: 'License revoked' });

        // Обновить last_used
        await kv.set(`license:${license_key}`, {
            ...record,
            last_used: new Date().toISOString()
        });

        return res.status(200).json({ ok: true });
    }

    // ── ADMIN: create license ─────────────────────────────────
    // POST /api/admin/create-license
    // Headers: X-Admin-Secret
    // Body: { "label": "Client Name" }
    if (pathname === '/api/admin/create-license') {
        if (req.headers['x-admin-secret'] !== process.env.ADMIN_SECRET)
            return res.status(403).json({ error: 'Forbidden' });
        if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

        const { label } = req.body;
        const license_key = generateKey();
        const record = {
            label: label || 'Unknown',
            created_at: new Date().toISOString(),
            last_used: null,
            active: true
        };
        await kv.set(`license:${license_key}`, record);
        return res.status(200).json({ ok: true, license_key, ...record });
    }

    // ── ADMIN: revoke license ─────────────────────────────────
    if (pathname === '/api/admin/revoke-license') {
        if (req.headers['x-admin-secret'] !== process.env.ADMIN_SECRET)
            return res.status(403).json({ error: 'Forbidden' });
        if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

        const { license_key } = req.body;
        if (!license_key) return res.status(400).json({ error: 'license_key required' });
        const record = await kv.get(`license:${license_key}`);
        if (!record) return res.status(404).json({ error: 'License not found' });
        await kv.set(`license:${license_key}`, { ...record, active: false });
        return res.status(200).json({ ok: true, message: `License ${license_key} revoked` });
    }

    // ── ADMIN: reactivate license ─────────────────────────────
    // (этого не было в BF сервере — добавлено здесь)
    if (pathname === '/api/admin/reactivate-license') {
        if (req.headers['x-admin-secret'] !== process.env.ADMIN_SECRET)
            return res.status(403).json({ error: 'Forbidden' });
        if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

        const { license_key } = req.body;
        if (!license_key) return res.status(400).json({ error: 'license_key required' });
        const record = await kv.get(`license:${license_key}`);
        if (!record) return res.status(404).json({ error: 'License not found' });
        await kv.set(`license:${license_key}`, { ...record, active: true });
        return res.status(200).json({ ok: true, message: `License ${license_key} reactivated` });
    }

    // ── ADMIN: list licenses ──────────────────────────────────
    if (pathname === '/api/admin/list-licenses') {
        if (req.headers['x-admin-secret'] !== process.env.ADMIN_SECRET)
            return res.status(403).json({ error: 'Forbidden' });

        const keys = await kv.keys('license:*');
        const records = await Promise.all(keys.map(async (k) => {
            const data = await kv.get(k);
            return { key: k.replace('license:', ''), ...data };
        }));
        return res.status(200).json({ ok: true, licenses: records });
    }

    return res.status(404).json({ error: 'Unknown endpoint' });
}
