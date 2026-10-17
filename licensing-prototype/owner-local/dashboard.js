// Local test-only owner dashboard; no credentials or invoice data stored.
const columns={orders:['id','status','payment_reference'],licenses:['id','status','device_bound'],events:['event_type','created_at','license_id']};
const state=document.getElementById('state');
async function load(name){
 const tbody=document.getElementById(name);
 try{
  const response=await fetch('/owner/'+name+'?limit=50&offset=0',{credentials:'same-origin',cache:'no-store'});
  if(response.status===403){state.textContent='انتهت الجلسة أو لم يتم تسجيل الدخول.';throw Error('unauthorized');}
  if(!response.ok)throw Error('request_failed');
  const data=await response.json();
  tbody.replaceChildren();
  if(!Array.isArray(data.items)||data.items.length===0){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=3;td.textContent='لا توجد سجلات';tr.append(td);tbody.append(tr);return;}
  for(const item of data.items){
   const tr=document.createElement('tr');
   for(const key of columns[name]){const td=document.createElement('td');td.textContent=String(item[key]??'—');tr.append(td);}
   tbody.append(tr);
  }
 }catch{tbody.replaceChildren();const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=3;td.textContent='تعذر عرض البيانات';tr.append(td);tbody.append(tr);state.textContent='تعذر تحميل بعض البيانات؛ تحقق من الجلسة والخادم المحلي.';}
}
Promise.all(Object.keys(columns).map(load)).then(()=>{if(state.textContent==='جاري تحميل بيانات الجلسة...')state.textContent='تم تحميل بيانات الإدارة للقراءة فقط.';});
