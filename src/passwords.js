import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const parameters = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function passwordProblem(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) return 'Use a password containing 12–128 characters.';
  return null;
}

export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = await scrypt(password, salt, 64, parameters);
  return `scrypt$32768$8$1$${salt}$${hash.toString('hex')}`;
}

// A fixed, non-account dummy hash keeps unknown-account verification on the same KDF path.
const dummyHashPromise = hashPassword(randomBytes(32).toString('hex'));

export async function verifyPassword(password, stored) {
  const encoded = stored || await dummyHashPromise;
  const [algorithm, n, r, p, salt, expected] = encoded.split('$');
  if (algorithm !== 'scrypt' || n !== '32768' || r !== '8' || p !== '1' || !/^[a-f0-9]{32}$/.test(salt) || !/^[a-f0-9]{128}$/.test(expected)) return false;
  const actual = await scrypt(typeof password === 'string' ? password : '', salt, 64, parameters);
  return timingSafeEqual(actual, Buffer.from(expected, 'hex')) && Boolean(stored);
}
