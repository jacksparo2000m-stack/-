const C='pt2-v1';
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(['./','index.html','manifest.json','icon-192.png'])).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;e.respondWith(fetch(e.request).then(n=>{const cp=n.clone();caches.open(C).then(c=>c.put(e.request,cp));return n}).catch(()=>caches.match(e.request).then(r=>r||caches.match('index.html'))))});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window'}).then(l=>l[0]?l[0].focus():clients.openWindow('./')))});
self.addEventListener('notificationclose',e=>{const d=e.notification.data;if(d&&d.pin)e.waitUntil(self.registration.showNotification(d.title,{body:d.body,tag:e.notification.tag,icon:'icon-192.png',requireInteraction:true,silent:true,data:d}))});
