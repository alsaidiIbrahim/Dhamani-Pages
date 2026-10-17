// Local demonstration only; do not persist passwords, TOTP or challenges.
const passwordForm=document.getElementById('passwordForm');
const totpForm=document.getElementById('totpForm');
const status=document.getElementById('status');
let challenge=null;
async function post(path,data){
 const res=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'content-type':'application/json'},body:JSON.stringify(data)});
 if(!res.ok)throw Error('authentication_failed');
 return res.json();
}
passwordForm.addEventListener('submit',async event=>{
 event.preventDefault();const button=passwordForm.querySelector('button');button.disabled=true;
 try{
  const password=document.getElementById('password');
  const response=await post('/owner/login/password',{password:password.value});
  password.value='';challenge=response.challenge;
  passwordForm.hidden=true;totpForm.hidden=false;document.getElementById('totp').focus();
  status.textContent='أدخل رمز المصادقة الثنائية المعروض في نافذة الاختبار المحلية.';
 }catch{status.textContent='تعذر التحقق من كلمة المرور.';}finally{button.disabled=false;}
});
totpForm.addEventListener('submit',async event=>{
 event.preventDefault();const button=totpForm.querySelector('button');button.disabled=true;
 try{
  const input=document.getElementById('totp');
  await post('/owner/login/totp',{challenge,code:input.value});
  input.value='';challenge=null;
  window.location.assign('/owner/dashboard');
 }catch{status.textContent='رمز التحقق غير صحيح أو انتهت صلاحيته. أعد المحاولة أو حدّث الصفحة.';}finally{button.disabled=false;}
});
