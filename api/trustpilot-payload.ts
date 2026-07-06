import type { VercelRequest, VercelResponse } from '@vercel/node';
import { createCipheriv, createHash, createHmac, randomBytes } from 'crypto';

type CustomerData = { name: string; email: string; reference: string };
type EncryptedPayload = { data: string; iv: string; tag: string; sig: string };

const createPayload = (secret: string, customerData: CustomerData): EncryptedPayload => {
  const iv = randomBytes(12);
  const jsonData = JSON.stringify(customerData);
  const key = createHash('sha256').update(secret).digest();

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(jsonData, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const tag = cipher.getAuthTag().toString('base64');
  const signatureData = secret + customerData.email + customerData.reference;
  const signature = createHmac('sha256', secret).update(signatureData).digest('hex');

  return { data: encrypted, iv: iv.toString('base64'), tag, sig: signature };
};

const ALLOWED_ORIGIN = 'https://jerusalemsandals.com';

export default function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { name, email, reference } = req.query;
  if (typeof email !== 'string' || typeof reference !== 'string') {
    return res.status(400).json({ error: 'Missing email or reference' });
  }

  const secret = process.env.TRUSTPILOT_SECRET;
  if (!secret) return res.status(500).json({ error: 'Server misconfiguration' });

  const payload = createPayload(secret, {
    name: typeof name === 'string' ? name : '',
    email,
    reference,
  });

  res.status(200).json(payload);
}
