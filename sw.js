// Serves the signed-in site. Each request under app/ is fetched from vault/ and decrypted in the browser.
const BASE = new URL('./', self.location).pathname;
const APP = BASE + 'app/';
const TYPES = {
  html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8',
  json: 'application/json', map: 'application/json', md: 'text/plain; charset=utf-8', txt: 'text/plain; charset=utf-8', csv: 'text/csv; charset=utf-8',
  yaml: 'text/plain; charset=utf-8', yml: 'text/plain; charset=utf-8', svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', ico: 'image/x-icon',
  pdf: 'application/pdf', gif: 'image/gif', webp: 'image/webp', woff: 'font/woff', woff2: 'font/woff2', xml: 'application/xml', gz: 'application/gzip',
};

// Read on every request, so signing out takes effect at once in every tab.
function getKeys() {
  return new Promise((ok) => {
    const open = indexedDB.open('gate-v1', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onerror = () => ok(null);
    open.onsuccess = () => {
      const get = open.result.transaction('keys').objectStore('keys').get('k');
      get.onerror = () => ok(null);
      get.onsuccess = () => { open.result.close(); ok(get.result || null); };
    };
  });
}
function dropKeys() {
  return new Promise((ok) => {
    const open = indexedDB.open('gate-v1', 1);
    open.onerror = () => ok();
    open.onsuccess = () => { const del = open.result.transaction('keys', 'readwrite').objectStore('keys').delete('k'); del.onsuccess = del.onerror = () => ok(); };
  });
}
function hex(buf) { return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join(''); }
const toLogin = (path) => Response.redirect(BASE + 'index.html?next=' + encodeURIComponent(path), 302);

async function open(keys, path) {
  const label = new TextEncoder().encode(path);
  const name = hex(await crypto.subtle.sign('HMAC', keys.mac, label)).slice(0, 40);
  const res = await fetch(BASE + 'vault/' + name + '.bin', { cache: 'no-cache' });
  if (!res.ok) return null;
  const body = await res.arrayBuffer();
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: body.slice(0, 12), additionalData: label }, keys.aes, body.slice(12));
}
function reply(path, data, status) {
  const type = TYPES[path.split('.').pop().toLowerCase()] || 'application/octet-stream';
  return new Response(data, { status: status || 200, headers: { 'Content-Type': type } });
}
async function serve(request, url) {
  const keys = await getKeys();
  const navigating = request.mode === 'navigate';
  if (!keys) return navigating ? toLogin(url.pathname) : new Response('Sign in first', { status: 401 });
  let path = decodeURIComponent(url.pathname.slice(APP.length));
  if (!path || path.endsWith('/')) path += 'index.html';
  try {
    const data = await open(keys, path);
    if (data) return reply(path, data);
    const missing = navigating ? await open(keys, '404.html') : null;
    return missing ? reply('404.html', missing, 404) : new Response('Not found', { status: 404 });
  } catch (err) {
    if (err.name !== 'OperationError') return new Response('Could not load this page', { status: 502 });
    await dropKeys(); // The password changed since this browser signed in.
    return navigating ? toLogin(url.pathname) : new Response('Sign in again', { status: 401 });
  }
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin === self.location.origin && url.pathname.startsWith(APP)) e.respondWith(serve(e.request, url));
});
