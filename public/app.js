const ITERATIONS=600000;
const enc=new TextEncoder();
const $=s=>document.querySelector(s);
const b64=b=>{let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s)};
const random=n=>crypto.getRandomValues(new Uint8Array(n));
async function derive(password,salt){
  const base=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:ITERATIONS,hash:'SHA-256'},base,512);
  const all=new Uint8Array(bits);
  const key=await crypto.subtle.importKey('raw',all.slice(0,32),{name:'AES-GCM'},false,['encrypt','decrypt']);
  return {key,token:b64(all.slice(32))};
}
async function seal(key,data){
  const iv=random(12);
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(data)));
  return {iv:b64(iv),ciphertext:b64(new Uint8Array(ct))};
}
$('#setup').addEventListener('submit',async e=>{
  e.preventDefault();
  const p=$('#password').value;
  const c=$('#confirm').value;
  const m=$('#msg');
  if(p!==c){m.textContent='Passwords do not match.';return}
  if(p.length<14){m.textContent='Use at least 14 characters.';return}
  if(p.length>256){m.textContent='Use 256 characters or fewer.';return}
  if(passwordStrength(p)<3){m.textContent='Choose a stronger master password: use a longer passphrase and avoid repeated or predictable patterns.';return}
  const button=e.submitter;
  if(button)button.disabled=true;
  try{
    m.textContent='Creating encrypted vault…';
    const salt=random(16);
    const d=await derive(p,salt);
    const blob=await seal(d.key,{version:1,createdAt:new Date().toISOString(),items:[]});
    const response=await fetch('/api/vault',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({salt:b64(salt),iv:blob.iv,ciphertext:blob.ciphertext,auth_verifier:await digestToken(d.token)})});
    let data=null;try{data=await response.json()}catch{}
    if(!response.ok)throw new Error(data?.error||`Server error (${response.status})`);
    if(!data?.id)throw new Error('Server did not return a vault ID.');
    sessionStorage.setItem('iknow_vault_id',data.id);
    location.assign('/vault.html');
  }catch(e){
    console.error('Vault setup failed:',e);
    m.textContent=e?.message||'Vault creation failed. Please try again.';
  }finally{if(button)button.disabled=false}
});
function passwordStrength(p){
  let score=0;
  if(p.length>=16)score++;
  if(p.length>=24)score++;
  if(/[a-z]/.test(p)&&/[A-Z]/.test(p))score++;
  if(/\d/.test(p)&&/[^A-Za-z0-9]/.test(p))score++;
  if(/(.)\1{3,}/.test(p)||/^(?:password|qwerty|123456|letmein|welcome)/i.test(p))score=Math.max(0,score-2);
  return Math.min(4,score);
}
function updateStrength(){
  const p=$('#password').value,s=$('#strength');
  if(!p){s.textContent='Use a long passphrase with a mix of characters.';return}
  const n=passwordStrength(p);
  s.textContent=n<2?'Weak — add length and unpredictability.':n<3?'Fair — make it longer or less predictable.':n<4?'Strong — good master password.':'Very strong — excellent.';
}
$('#password').addEventListener('input',updateStrength);
async function digestToken(t){
  const bytes=await crypto.subtle.digest('SHA-256',Uint8Array.from(atob(t),c=>c.charCodeAt(0)));
  return b64(new Uint8Array(bytes));
}
