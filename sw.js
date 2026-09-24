const CACHE='my-finance-v1.3';
const ASSETS=['./','./index.html','./styles.css?v=1.3','./app.js?v=1.3','./manifest.webmanifest','./icon-192.png','./icon-512.png','./bofa.png','./scb.png','./ktb.png','./kbank.png','./gsb.png','./ttb.png','./bbl.png','./baac.png','./honda.png','./mitsubishi.png','./gpf.png','./gold.png','./land.png','./house.png','./vehicle.png','./other.png','./wallet.png','./fund.png'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  e.respondWith(fetch(e.request).then(r=>{const copy=r.clone();caches.open(CACHE).then(c=>c.put(e.request,copy));return r}).catch(()=>caches.match(e.request).then(r=>r||caches.match('./index.html'))));
});
