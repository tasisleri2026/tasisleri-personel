// Kurulabilir uygulama için gerekli asgari servis çalışanı; veriler önbelleğe alınmaz.
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',()=>{});
