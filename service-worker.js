const CACHE='maria-music-shell-v3';
const SHELL=['./','./index.html','./php-client.js','./firebase-upload.js','./manifest.json','./icon.svg','./cover.svg','./icon-192.png','./icon-512.png','./apple-touch-icon.png'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(SHELL)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{
  const request=event.request;
  if(request.method!=='GET'||new URL(request.url).origin!==self.location.origin)return;
  if(new URL(request.url).pathname.startsWith('/api/'))return;
  event.respondWith(fetch(request).then(response=>{
    if(response.ok&&request.destination!=='audio')caches.open(CACHE).then(cache=>cache.put(request,response.clone()));
    return response;
  }).catch(()=>caches.match(request).then(cached=>cached||caches.match('./index.html'))));
});
