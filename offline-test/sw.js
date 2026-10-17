const CACHE='dhamani-pages-offline-test-v29';
const FILES=['./','./index.html','./styles.css','./manifest.webmanifest','./jsQR.min.js','./zxing.min.js','./ocr/pdf.min.js','./ocr/pdf.worker.min.js','./ocr/tesseract.min.js','./ocr/worker.min.js','./ocr/tesseract-core-simd-lstm.wasm.js','./ocr/tesseract-core-simd-lstm.wasm','./ocr/ara.traineddata.gz','./ocr/eng.traineddata.gz'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(FILES)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('dhamani-pages-offline-test-')&&key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{
 const request=event.request,url=new URL(request.url);
 if(request.method!=='GET'||url.origin!==self.location.origin)return;
 const scope=new URL(self.registration.scope);
 if(!url.pathname.startsWith(scope.pathname))return;
 if(request.mode==='navigate'){
  event.respondWith(fetch(request).then(response=>response.ok?response:Promise.reject(Error('Offline fallback'))).catch(()=>caches.match(new URL('index.html',scope).href)));
  return;
 }
 event.respondWith(caches.match(request).then(hit=>hit||fetch(request)));
});