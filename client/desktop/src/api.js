// VITE_API_URL is set in client/desktop/.env (dev) or the build environment (prod).
// Keep its value in sync with SERVER_URL in client/config.js.
const BASE_URL = import.meta.env.VITE_API_URL;

function getToken() {
  return localStorage.getItem('authToken');
}

// Decode user_id from the stored JWT without a library
export function getMyUserId() {
  const token = getToken();
  if (!token) return null;
  try {
    return JSON.parse(atob(token.split('.')[1])).sub;
  } catch {
    return null;
  }
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Request failed');
  }

  return res.json();
}

export const api = {
  register: (username, password, publicKey) =>
    request('POST', '/api/auth/register', { username, password, public_key: publicKey }),

  login: (username, password) =>
    request('POST', '/api/auth/login', { username, password }),

  // TODO: ciphertext/nonce/digest should come from the crypto layer once integrated
  sendMessage: (recipient, ciphertext, nonce, digest) =>
    request('POST', '/api/messages', { recipient, ciphertext, nonce, digest }),

  fetchMessages: () =>
    request('GET', '/api/messages'),
};
