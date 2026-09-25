const json=(x,init={})=>new Response(JSON.stringify(x),{headers:{'Content-Type':'application/json','Cache-Control':'no-store',...(init.headers||{})},...init});
function valid(s,max=3000000){return typeof s==='string'&&s.length>0&&s.length<=max}
function fromB64(s){const x=atob(s),a=new Uint8Array(x.length);for(let i=0;i<x.length;i++)a[i]=x.charCodeAt(i);return a}
function toB64(b){let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s)}
async function hashToken(t){return toB64(new Uint8Array(await crypto.subtle.digest('SHA-256',fromB64(t))))}
async function hashText(t){return toB64(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t))))}
function equal(a,b){if(a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0}
async function rateLimit(request,env,kind,limit,windowMs){
 const ip=request.headers.get('CF-Connecting-IP')||'unknown';
 const bucket=kind+':'+(await hashText(ip)).slice(0,32);
 const now=Date.now();
 const row=await env.DB.prepare('SELECT count,reset_at FROM rate_limits WHERE bucket=?').bind(bucket).first();
 if(!row||row.reset_at<=now){
  await env.DB.prepare('INSERT OR REPLACE INTO rate_limits (bucket,count,reset_at) VALUES (?,?,?)').bind(bucket,1,now+windowMs).run();
  return true
 }
 if(row.count>=limit)return false;
 await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE bucket=?').bind(bucket).run();
 return true
}
async function authorized(request,row){
 const h=request.headers.get('authorization')||'';
 if(!h.startsWith('Bearer '))return false;
 const t=h.slice(7);
 return valid(t,500)&&equal(await hashToken(t),row.auth_verifier||'')
}
export async function onRequestPost({request,env}){
 if(!(await rateLimit(request,env,'create',5,900000)))return json({error:'Too many requests. Try again later.'},{status:429});
 let b;try{b=await request.json()}catch{return json({error:'Invalid JSON'},{status:400})}
 if(!valid(b.salt,100)||!valid(b.iv,100)||!valid(b.ciphertext)||!valid(b.auth_verifier,100))return json({error:'Invalid payload'},{status:400});
 const id=crypto.randomUUID();
 await env.DB.prepare("INSERT INTO vaults (id,salt,iv,ciphertext,auth_verifier,version,created_at,updated_at) VALUES (?,?,?,?,?,1,datetime('now'),datetime('now'))").bind(id,b.salt,b.iv,b.ciphertext,b.auth_verifier).run();
 return json({id},{status:201})
}
export async function onRequestGet({request,env}){
 if(!(await rateLimit(request,env,'read',120,900000)))return json({error:'Too many requests. Try again later.'},{status:429});
 const id=new URL(request.url).searchParams.get('id');
 if(!id||id.length>100)return json({error:'Missing id'},{status:400});
 const row=await env.DB.prepare('SELECT id,salt,iv,ciphertext,auth_verifier,version FROM vaults WHERE id=?').bind(id).first();
 if(!row)return json({error:'Not found'},{status:404});
 if(!((request.headers.get('authorization')||'').startsWith('Bearer ')))return json({id:row.id,salt:row.salt},{status:200});
 if(!(await authorized(request,row)))return json({error:'Unauthorized'},{status:401});
 return json({id:row.id,salt:row.salt,iv:row.iv,ciphertext:row.ciphertext,version:row.version})
}
export async function onRequestPut({request,env}){
 if(!(await rateLimit(request,env,'write',60,900000)))return json({error:'Too many requests. Try again later.'},{status:429});
 let b;try{b=await request.json()}catch{return json({error:'Invalid JSON'},{status:400})}
 if(!valid(b.id,100)||!valid(b.iv,100)||!valid(b.ciphertext)||!valid(b.auth_token,500)||!Number.isInteger(b.version)||b.version<1)return json({error:'Invalid payload'},{status:400});
 const changingAuth=typeof b.salt==='string'||typeof b.auth_verifier==='string';
 if(changingAuth&&(!valid(b.salt,100)||!valid(b.auth_verifier,100)))return json({error:'Invalid credential update'},{status:400});
 const row=await env.DB.prepare('SELECT auth_verifier,version FROM vaults WHERE id=?').bind(b.id).first();
 if(!row)return json({error:'Not found'},{status:404});
 if(!(await authorized(new Request(request.url,{headers:{authorization:'Bearer '+b.auth_token}}),row)))return json({error:'Unauthorized'},{status:401});
 const next=row.version+1;
 const r=changingAuth
  ? await env.DB.prepare("UPDATE vaults SET salt=?,auth_verifier=?,iv=?,ciphertext=?,version=?,updated_at=datetime('now') WHERE id=? AND version=?").bind(b.salt,b.auth_verifier,b.iv,b.ciphertext,next,b.id,b.version).run()
  : await env.DB.prepare("UPDATE vaults SET iv=?,ciphertext=?,version=?,updated_at=datetime('now') WHERE id=? AND version=?").bind(b.iv,b.ciphertext,next,b.id,b.version).run();
 if(!r.meta?.changes)return json({error:'Vault changed elsewhere'},{status:409});
 return json({ok:true,version:next})
}
