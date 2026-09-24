
const ITERATIONS=600000,enc=new TextEncoder();
const b64=b=>{let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s)};
const random=n=>crypto.getRandomValues(new Uint8Array(n));
async function derive(password,salt){const base=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:ITERATIONS,hash:'SHA-256'},base,512);const all=new Uint8Array(bits),key=await crypto.subtle.importKey('raw',all.slice(0,32),{name:'AES-GCM'},false,['encrypt','decrypt']);return{key,token:b64(all.slice(32))}}
async function seal(key,data){const iv=random(12),ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(data)));return{iv:b64(iv),ciphertext:b64(new Uint8Array(ct))}}
async function digestToken(t){return b64(new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(atob(t),c=>c.charCodeAt(0))))))}
const $=s=>document.querySelector(s);
$('#setup').onsubmit=async e=>{e.preventDefault();const p=$('#password').value,c=$('#confirm').value,m=$('#msg');if(p!==c){m.textContent='Passwords do not match.';return}if(p.length<14){m.textContent='Use at least 14 characters.';return}try{m.textContent='Creating encrypted vault…';const salt=random(16),d=await derive(p,salt),blob=await seal(d.key,{version:1,createdAt:new Date().toISOString(),items:[]}),x=await fetch('/api/vault',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({salt:b64(salt),iv:blob.iv,ciphertext:blob.ciphertext,auth_verifier:await digestToken(d.token)})});if(!x.ok)throw Error('Could not create vault');const r=await x.json();sessionStorage.setItem('iknow_vault_id',r.id);location.href='/vault.html'}catch(e){m.textContent=e.message}};
