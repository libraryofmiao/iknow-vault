const SECURITY_HEADERS={
 'X-Content-Type-Options':'nosniff',
 'X-Frame-Options':'DENY',
 'Referrer-Policy':'no-referrer',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
 'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
 'Cache-Control':'no-store'
};
const json=(x,init={})=>new Response(JSON.stringify(x),{...init,headers:{'Content-Type':'application/json',...SECURITY_HEADERS,...(init.headers||{})}});
function valid(s,max=3000000){return typeof s==='string'&&s.length>0&&s.length<=max}
function fromB64(s){try{const x=atob(s),a=new Uint8Array(x.length);for(let i=0;i<x.length;i++)a[i]=x.charCodeAt(i);return a}catch{return null}}
function toB64(b){let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s)}
async function hashToken(t){const bytes=fromB64(t);if(!bytes)throw Error('invalid token');return toB64(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)))}
async function hashText(t){return toB64(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t))))}
function equal(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0}
async function rateLimit(request,env,kind,limit,windowMs){
 const ip=request.headers.get('CF-Connecting-IP')||'unknown';
 const bucket=kind+':'+(await hashText(ip)).slice(0,32);
 const now=Date.now(),reset=now+windowMs;
 const row=await env.DB.prepare('INSERT INTO rate_limits(bucket,count,reset_at) VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN reset_at<=? THEN 1 ELSE count+1 END, reset_at=CASE WHEN reset_at<=? THEN ? ELSE reset_at END RETURNING count,reset_at').bind(bucket,1,reset,now,now,reset).first();
 return !!row&&row.count<=limit
}
async function authorized(request,row){const h=request.headers.get('authorization')||'';if(!h.startsWith('Bearer '))return false;const t=h.slice(7);return valid(t,500)&&equal(await hashToken(t),row.auth_verifier||'')}
export async function onRequestPost({request,env}){
 if(!(await rateLimit(request,env,'create',5,900000)))return json({error:'Too many requests. Try again later.'},{status:429});
 let b;try{b=await request.json()}catch{return json({error:'Invalid JSON'},{status:400})}
 if(!valid(b.salt,100)||!valid(b.iv,100)||!valid(b.ciphertext)||!valid(b.auth_verifier,100))return json({error:'Invalid payload'},{status:400});
 const existing=await env.DB.prepare('SELECT id FROM vaults LIMIT 1').first();if(existing)return json({error:'A vault already exists. Sign in to the existing vault.'},{status:409});
 const id=crypto.randomUUID();
 try{await env.DB.prepare("INSERT INTO vaults (id,salt,iv,ciphertext,auth_verifier,version,created_at,updated_at) VALUES (?,?,?,?,?,1,datetime('now'),datetime('now'))").bind(id,b.salt,b.iv,b.ciphertext,b.auth_verifier).run()}catch(e){if(String(e?.message||e).includes('Only one vault'))return json({error:'A vault already exists. Sign in to the existing vault.'},{status:409});throw e}
 return json({id},{status:201})
}
export async function onRequestGet({request,env}){
 if(!(await rateLimit(request,env,'read',120,900000)))return json({error:'Too many requests. Try again later.'},{status:429});
 const params=new URL(request.url).searchParams;
 if(params.get('meta')==='1'){const row=await env.DB.prepare('SELECT id,salt FROM vaults ORDER BY created_at ASC LIMIT 1').first();if(!row)return json({error:'No vault exists'},{status:404});return json({id:row.id,salt:row.salt},{status:200})}
 const id=params.get('id');if(!id||id.length>100)return json({error:'Missing id'},{status:400});
 const row=await env.DB.prepare('SELECT id,salt,iv,ciphertext,auth_verifier,version FROM vaults WHERE id=?').bind(id).first();if(!row)return json({error:'Not found'},{status:404});
 if(!(await authorized(request,row)))return json({error:'Unauthorized'},{status:401});
 return json({id:row.id,salt:row.salt,iv:row.iv,ciphertext:row.ciphertext,version:row.version})
}
export async function onRequestPut({request,env}){
 if(!(await rateLimit(request,env,'write',60,900000)))return json({error:'Too many requests. Try again later.'},{status:429});
 let b;try{b=await request.json()}catch{return json({error:'Invalid JSON'},{status:400})}
 if(!valid(b.id,100)||!valid(b.iv,100)||!valid(b.ciphertext)||!valid(b.auth_token,500)||!Number.isInteger(b.version)||b.version<1)return json({error:'Invalid payload'},{status:400});
 const changingAuth=typeof b.salt==='string'||typeof b.auth_verifier==='string';if(changingAuth&&(!valid(b.salt,100)||!valid(b.auth_verifier,100)))return json({error:'Invalid credential update'},{status:400});
 const row=await env.DB.prepare('SELECT auth_verifier,version FROM vaults WHERE id=?').bind(b.id).first();if(!row)return json({error:'Not found'},{status:404});
 if(!(await authorized(new Request(request.url,{headers:{authorization:'Bearer '+b.auth_token}}),row)))return json({error:'Unauthorized'},{status:401});
 const next=row.version+1;
 const r=changingAuth?await env.DB.prepare("UPDATE vaults SET salt=?,auth_verifier=?,iv=?,ciphertext=?,version=?,updated_at=datetime('now') WHERE id=? AND version=?").bind(b.salt,b.auth_verifier,b.iv,b.ciphertext,next,b.id,b.version).run():await env.DB.prepare("UPDATE vaults SET iv=?,ciphertext=?,version=?,updated_at=datetime('now') WHERE id=? AND version=?").bind(b.iv,b.ciphertext,next,b.id,b.version).run();
 if(!r.meta?.changes)return json({error:'Vault changed elsewhere'},{status:409});
 return json({ok:true,version:next})
}