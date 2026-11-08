interface Env {
  DB: D1Database;
  MEDIA_BUCKET: R2Bucket;
  ASSETS: Fetcher;
  SESSION_SECRET: string;
  AUDIO_TOKEN_SECRET?: string;
  AUDIO_TOKEN_TTL_SECONDS?: string;
  MEDIA_KEY_PREFIX?: string;
  HEALTH_TOKEN?: string;
  BEAT_ACCESS?: string;
  CSP_MODE?: string;
}
const TRACKS: Record<number,{id:number;folder:string;files:string[];mime:string}> = {
  1:{id:1,folder:"Songs",files:["dont-be-dumb.wav","Don't Be Dumb.wav"],mime:"audio/wav"},
  2:{id:2,folder:"Songs",files:["ekseni.wav","Ekseni.wav"],mime:"audio/wav"},
  3:{id:3,folder:"Songs",files:["masambe.wav","Masambe.wav"],mime:"audio/wav"},
  4:{id:4,folder:"Songs",files:["money-moves.wav","Money Moves.wav","Money Moves (3).wav"],mime:"audio/wav"},
  5:{id:5,folder:"Songs",files:["drip.wav","Drip.wav"],mime:"audio/wav"},
  6:{id:6,folder:"Beats",files:["Ace.wav","ace.wav"],mime:"audio/wav"},
  7:{id:7,folder:"Beats",files:["Authentic.wav","authentic.wav"],mime:"audio/wav"},
  8:{id:8,folder:"Beats",files:["Old School.wav","old-school.wav","Old_School.wav"],mime:"audio/wav"},
  9:{id:9,folder:"Beats",files:["Escape.wav"],mime:"audio/wav"},
  10:{id:10,folder:"Beats",files:["Grand Keys.wav"],mime:"audio/wav"},
  11:{id:11,folder:"Beats",files:["Pablo.wav"],mime:"audio/wav"},
  12:{id:12,folder:"Beats",files:["Stuck.wav","Stick.wav"],mime:"audio/wav"},
  13:{id:13,folder:"Beats",files:["Vision.wav"],mime:"audio/wav"},
  14:{id:14,folder:"Beats",files:["2000s voice sample.wav"],mime:"audio/wav"},
  15:{id:15,folder:"Beats",files:["Alive.wav"],mime:"audio/wav"},
  16:{id:16,folder:"Beats",files:["Chopper.wav"],mime:"audio/wav"},
  17:{id:17,folder:"Beats",files:["Coming Back.wav"],mime:"audio/wav"},
  18:{id:18,folder:"Beats",files:["Complications.wav"],mime:"audio/wav"},
  19:{id:19,folder:"Beats",files:["Digital.wav"],mime:"audio/wav"},
  20:{id:20,folder:"Beats",files:["Dreamy Keys.wav"],mime:"audio/wav"},
  21:{id:21,folder:"Beats",files:["Energy.wav"],mime:"audio/wav"},
  22:{id:22,folder:"Beats",files:["Essense.wav"],mime:"audio/wav"},
  23:{id:23,folder:"Beats",files:["Floodin'.wav"],mime:"audio/wav"},
  24:{id:24,folder:"Beats",files:["Globe.wav"],mime:"audio/wav"},
  25:{id:25,folder:"Beats",files:["Grateful.wav"],mime:"audio/wav"},
  26:{id:26,folder:"Beats",files:["Hard beat.wav"],mime:"audio/wav"},
  27:{id:27,folder:"Beats",files:["Let's goo.wav"],mime:"audio/wav"},
  28:{id:28,folder:"Beats",files:["Lost.wav"],mime:"audio/wav"},
  29:{id:29,folder:"Beats",files:["Reborn.wav"],mime:"audio/wav"},
  30:{id:30,folder:"Beats",files:["Slice.wav"],mime:"audio/wav"},
  31:{id:31,folder:"Beats",files:["Soulful Trap.wav"],mime:"audio/wav"},
  32:{id:32,folder:"Beats",files:["Take it easy.wav"],mime:"audio/wav"},
  33:{id:33,folder:"Beats",files:["Trampet.wav"],mime:"audio/wav"}
};
const isBeat=(t:{folder:string})=>t.folder==="Beats";
const json=(data:unknown,status=200,headers:HeadersInit={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"private, no-store",...headers}});
const enc=(s:string)=>new TextEncoder().encode(s);
const b64url=(b:ArrayBuffer)=>b64(b).replaceAll("+","-").replaceAll("/","_");
const b64=(b:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=+$/,"");

const tooMany=(seconds:number)=>json({error:"Too many attempts. Please wait a few minutes and try again."},429,{"retry-after":String(seconds)});
function safeEqual(a:string,b:string){const x=enc(a),y=enc(b);let d=x.length^y.length;const n=Math.max(x.length,y.length);for(let i=0;i<n;i++)d|=(x[i]||0)^(y[i]||0);return d===0;}
async function readJson(req:Request,maxBytes=16384):Promise<any|null>{
  const declared=Number(req.headers.get("content-length")||0);
  if(declared>maxBytes)return null;
  const text=await req.text().catch(()=>null);
  if(text===null||text.length>maxBytes)return null;
  try{return JSON.parse(text);}catch{return null;}
}
async function clientKey(req:Request,env:Env){return (await hmac(env.SESSION_SECRET,"ip:"+(req.headers.get("cf-connecting-ip")||"unknown"))).slice(0,22);}
// Fixed-window rate limiter stored in D1. Fails open (and logs) if the table is missing so a bad deploy cannot lock everyone out.
async function allow(env:Env,key:string,limit:number,windowSeconds:number){
  try{
    const now=Math.floor(Date.now()/1000),bucket=Math.floor(now/windowSeconds);
    const row=await env.DB.prepare("INSERT INTO akt_rate_limits(key,count,expires_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count")
      .bind(key+":"+bucket,(bucket+1)*windowSeconds+60).first<{count:number}>();
    if(Math.random()<0.02)await env.DB.prepare("DELETE FROM akt_rate_limits WHERE expires_at<?").bind(now).run();
    return (row?.count??1)<=limit;
  }catch(error){console.error("AKT Media rate limiter unavailable",error);return true;}
}
const PAGE_CSP_COMMON="base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-src https://maps.google.com https://www.google.com; worker-src 'self' blob:; manifest-src 'self'; upgrade-insecure-requests";
const STYLE_SRC="style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com";
const APP_CSP="default-src 'self'; script-src 'self'; "+STYLE_SRC+"; "+PAGE_CSP_COMMON;
// sample.html still has inline scripts and loads the Tailwind CDN, so it needs a looser script policy. Compile Tailwind + move the script to a file to tighten this.
const SAMPLE_CSP="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "+STYLE_SRC+"; "+PAGE_CSP_COMMON;
function secure(res:Response,req:Request,env:Env){
  const url=new URL(req.url),h=new Headers(res.headers);
  const isHtml=(h.get("content-type")||"").includes("text/html");
  if(isHtml){
    const csp=url.pathname.startsWith("/sample")?SAMPLE_CSP:APP_CSP;
    h.set(env.CSP_MODE==="report-only"?"content-security-policy-report-only":"content-security-policy",csp);
  }else if(!h.has("content-security-policy")){
    h.set("content-security-policy","default-src 'none'; frame-ancestors 'none'");
  }
  h.set("strict-transport-security","max-age=31536000; includeSubDomains");
  h.set("x-content-type-options","nosniff");
  h.set("x-frame-options","DENY");
  h.set("referrer-policy","strict-origin-when-cross-origin");
  h.set("permissions-policy","camera=(), microphone=(), geolocation=(), usb=(), payment=(self), interest-cohort=()");
  h.set("cross-origin-opener-policy","same-origin");
  if(!h.has("cross-origin-resource-policy"))h.set("cross-origin-resource-policy","same-origin");
  return new Response(res.body,{status:res.status,statusText:res.statusText,headers:h});
}

async function hmac(secret:string,value:string){const k=await crypto.subtle.importKey("raw",enc(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);return b64(await crypto.subtle.sign("HMAC",k,enc(value)));}
async function hmacUrl(secret:string,value:string){const k=await crypto.subtle.importKey("raw",enc(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return b64url(await crypto.subtle.sign("HMAC",k,enc(value)));}
async function digest(value:string){return b64url(await crypto.subtle.digest("SHA-256",enc(value)));}
function cookieMap(req:Request){
  const out:Record<string,string>={};
  for(const part of (req.headers.get("cookie")||"").split(";")){
    const i=part.indexOf("=");
    if(i<1)continue;
    const name=part.slice(0,i).trim();
    const value=part.slice(i+1).trim();
    try{out[name]=decodeURIComponent(value);}
    catch{out[name]=value;}
  }
  return out;
}
async function session(req:Request,env:Env){const c=cookieMap(req).akt_playlist_session||"";const raw=c.startsWith("s:")?c.slice(2):"";const i=raw.lastIndexOf(".");let id=i>0?raw.slice(0,i):"";const sig=i>0?raw.slice(i+1):"";const valid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)&&!!sig&&safeEqual(await hmac(env.SESSION_SECRET,id),sig);if(!valid)id=crypto.randomUUID();const headers=new Headers({"cache-control":"private, no-store"});if(!valid){const signed="s:"+id+"."+await hmac(env.SESSION_SECRET,id);headers.append("set-cookie", "akt_playlist_session="+encodeURIComponent(signed)+"; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000");}return {id,headers};}
function sameSite(req:Request){const self=new URL(req.url).origin;const origin=req.headers.get("origin");const referer=req.headers.get("referer");const site=req.headers.get("sec-fetch-site");try{if(origin&&(origin==="null"||new URL(origin).origin!==self))return false;if(referer&&new URL(referer).origin!==self)return false;}catch{return false;}return site?site==="same-origin":!!(origin||referer);}
function withHeaders(res:Response,headers:Headers){const h=new Headers(res.headers);headers.forEach((v,k)=>{if(k.toLowerCase()==="set-cookie")h.append(k,v);else h.set(k,v);});return new Response(res.body,{status:res.status,statusText:res.statusText,headers:h});}
function mediaKeyPrefix(env:Env){
  return (env.MEDIA_KEY_PREFIX||"").split("/").filter(Boolean).join("/");
}
function normalizeMediaName(value:string){
  let base=value.split("/").pop()||value;
  const dot=base.lastIndexOf(".");
  if(dot>0)base=base.slice(0,dot);
  return base.toLowerCase().replace(/[^a-z0-9]/g,"");
}
async function audioSecret(env:Env){return env.AUDIO_TOKEN_SECRET||await hmac(env.SESSION_SECRET,"akt:audio-token:v1");}
function fullAccess(env:Env,t:{folder:string},member:any){
  if(!isBeat(t))return true;
  if(env.BEAT_ACCESS==="open")return true;
  const m=member?.membership;
  return !!m&&(m.status==="active"||m.status==="trialing")&&(!m.currentPeriodEnd||Date.parse(m.currentPeriodEnd)>Date.now());
}
async function findPreview(env:Env,t:{files:string[]}){
  const prefix=mediaKeyPrefix(env);
  for(const file of t.files){
    const stem=file.replace(/\.[^.]+$/,"");
    for(const key of [[prefix,"Previews",stem+".mp3"].filter(Boolean).join("/")]){
      const obj=await env.MEDIA_BUCKET.get(key);
      if(obj)return obj;
    }
  }
  return null;
}
async function findObject(env:Env,track:{folder:string;files:string[]}){
  const prefix=mediaKeyPrefix(env);
  const candidates:string[]=[];
  for(const file of track.files){
    candidates.push([prefix,track.folder,file].filter(Boolean).join("/"));
    candidates.push([prefix,file].filter(Boolean).join("/"));
  }
  for(const key of candidates){
    const obj=await env.MEDIA_BUCKET.get(key);
    if(obj)return obj;
  }
  let cursor:string|undefined;
  const targets=track.files.map(normalizeMediaName);
  for(let page=0;page<10;page++){
    const listed=await env.MEDIA_BUCKET.list({prefix:prefix?prefix+"/":undefined,limit:1000,cursor});
    const found=listed.objects.find(o=>{
      const key=o.key;
      const parts=key.split("/");
      const name=normalizeMediaName(key);
      const inExpectedFolder=parts.length===1||parts[parts.length-2]===track.folder;
      return inExpectedFolder&&targets.includes(name);
    });
    if(found)return await env.MEDIA_BUCKET.get(found.key);
    if(!listed.truncated||!listed.cursor)break;
    cursor=listed.cursor;
  }
  return null;
}
async function media(req:Request,env:Env,trackId:number,token?:string,owner?:string){const t=TRACKS[trackId];if(!t)return json({error:"Track not found."},404);if(!owner||!token)return json({error:"This audio link is invalid or has expired."},403);const [exp,variant,sig]=token.split(".");const expiry=Number(exp);const ua=await digest(req.headers.get("user-agent")||"");if(!Number.isFinite(expiry)||expiry<=Date.now()||(variant!=="f"&&variant!=="p")||!sig||!safeEqual(await hmacUrl(await audioSecret(env),[trackId,expiry,variant,owner,ua.slice(0,22)].join(".")),sig))return json({error:"This audio link is invalid or has expired."},403);const full=variant==="f";const obj=full?await findObject(env,t):await findPreview(env,t);if(!obj)return json({error:full?"Audio file is not available.":"A preview of this track is not available yet."},404);const mime=full?t.mime:"audio/mpeg";const range=req.headers.get("range");const options:HeadersInit={"content-type":mime,"content-disposition":"inline","cache-control":"private, no-store, max-age=0","accept-ranges":"bytes","content-security-policy":"default-src 'none'","cross-origin-resource-policy":"same-origin","x-content-type-options":"nosniff","x-robots-tag":"noindex, nofollow"};if(range){const m=/^bytes=(\d*)-(\d*)$/.exec(range);if(!m)return json({error:"The requested audio range is not available."},416);const start=m[1]?Number(m[1]):Math.max(0,obj.size-Number(m[2]));const end=m[2]&&m[1]?Math.min(Number(m[2]),obj.size-1):obj.size-1;if(start>end||start>=obj.size)return new Response(null,{status:416,headers:{"content-range":`bytes */${obj.size}`}});const part=await env.MEDIA_BUCKET.get(obj.key,{range:{offset:start,length:end-start+1}});if(!part)return json({error:"Audio storage is unavailable."},502);return new Response(part.body,{status:206,headers:{...options,"content-length":String(end-start+1),"content-range":`bytes ${start}-${end}/${obj.size}`}});}return new Response(obj.body,{headers:{...options,"content-length":String(obj.size)}});}

const MEMBER_COOKIE="akt_member_session";
const MEMBER_SESSION_DAYS=30;
const MAX_SESSIONS_PER_MEMBER=10;
const PASSWORD_ITERATIONS=310000;
const DUMMY_SALT=new Uint8Array(16);
const NOW_ISO="strftime('%Y-%m-%dT%H:%M:%fZ','now')";
const hex=(bytes:Uint8Array)=>Array.from(bytes).map(x=>x.toString(16).padStart(2,"0")).join("");
function fromHex(value:string){return new Uint8Array(value.match(/.{2}/g)?.map(x=>parseInt(x,16))||[]);}
function randomToken(){const bytes=crypto.getRandomValues(new Uint8Array(32));return b64url(bytes.buffer);}
async function passwordHash(password:string,salt:Uint8Array,iterations=PASSWORD_ITERATIONS){
  const key=await crypto.subtle.importKey("raw",enc(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations,hash:"SHA-256"},key,256);
  return new Uint8Array(bits);
}
async function saveMemberSession(env:Env,userId:string){
  const token=randomToken(),tokenHash=await digest(token);
  const expiresAt=new Date(Date.now()+MEMBER_SESSION_DAYS*86400000).toISOString();
  // keep only the newest sessions per member and occasionally purge expired ones
  await env.DB.prepare("DELETE FROM akt_member_sessions WHERE user_id=? AND id NOT IN (SELECT id FROM akt_member_sessions WHERE user_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?)").bind(userId,userId,MAX_SESSIONS_PER_MEMBER-1).run();
  if(Math.random()<0.05)await env.DB.prepare("DELETE FROM akt_member_sessions WHERE expires_at<"+NOW_ISO).run();
  await env.DB.prepare("INSERT INTO akt_member_sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)")
    .bind(crypto.randomUUID(),userId,tokenHash,expiresAt).run();
  const headers=new Headers({"cache-control":"private, no-store"});
  headers.append("set-cookie",MEMBER_COOKIE+"="+token+"; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age="+(MEMBER_SESSION_DAYS*86400));
  return headers;
}
async function membershipFor(env:Env,userId:string){
  const s=await env.DB.prepare("SELECT plan_code,status,current_period_end FROM akt_member_subscriptions WHERE user_id=?").bind(userId).first<any>();
  return {plan:s?.plan_code||"free",status:s?.status||"free",currentPeriodEnd:s?.current_period_end||null};
}
async function currentMember(req:Request,env:Env){
  const token=cookieMap(req)[MEMBER_COOKIE]||"";
  if(!/^[A-Za-z0-9_-]{40,60}$/.test(token))return null;
  const row=await env.DB.prepare("SELECT m.id,m.email,m.display_name,m.email_verified,s.plan_code,s.status,s.current_period_end FROM akt_member_sessions ms JOIN akt_members m ON m.id=ms.user_id LEFT JOIN akt_member_subscriptions s ON s.user_id=m.id WHERE ms.token_hash=? AND ms.expires_at>"+NOW_ISO)
    .bind(await digest(token)).first<any>();
  if(!row)return null;
  return {id:row.id,email:row.email,displayName:row.display_name,emailVerified:!!row.email_verified,membership:{plan:row.plan_code||"free",status:row.status||"free",currentPeriodEnd:row.current_period_end||null}};
}
async function auth(req:Request,env:Env,path:string){
  if(path==="/api/auth/me"&&req.method==="GET"){
    const member=await currentMember(req,env);
    return member?json({authenticated:true,member}):json({authenticated:false,member:null},200);
  }
  if(path==="/api/auth/logout"&&req.method==="POST"){
    if(!sameSite(req))return json({error:"This request was not allowed."},403);
    const token=cookieMap(req)[MEMBER_COOKIE]||"";
    if(token)await env.DB.prepare("DELETE FROM akt_member_sessions WHERE token_hash=?").bind(await digest(token)).run();
    const response=json({ok:true});
    response.headers.append("set-cookie",MEMBER_COOKIE+"=; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
    return response;
  }
  if(path==="/api/auth/register"&&req.method==="POST"){
    if(!sameSite(req))return json({error:"This request was not allowed."},403);
    const ip=await clientKey(req,env);
    if(!await allow(env,"register:ip:"+ip,5,3600))return tooMany(3600);
    const body=await readJson(req,4096);
    const email=typeof body?.email==="string"?body.email.trim().toLowerCase():"";
    const displayName=typeof body?.displayName==="string"?body.displayName.trim().replace(/[\u0000-\u001f\u007f]/g,"").slice(0,80):"";
    const password=typeof body?.password==="string"?body.password:"";
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||!displayName||password.length<10||password.length>128||!/[A-Za-z]/.test(password)||!/[0-9]/.test(password)||password.toLowerCase()===email)
      return json({error:"Enter a valid email, display name, and password of at least 10 characters containing a letter and a number."},400);
    const exists=await env.DB.prepare("SELECT id FROM akt_members WHERE email=?").bind(email).first<any>();
    if(exists)return json({error:"An account with this email already exists."},409);
    const id=crypto.randomUUID(),salt=crypto.getRandomValues(new Uint8Array(16));
    const hash=await passwordHash(password,salt);
    try{
      await env.DB.batch([
        env.DB.prepare("INSERT INTO akt_members(id,email,display_name,password_hash,password_salt,password_iterations) VALUES(?,?,?,?,?,?)").bind(id,email,displayName,hex(hash),hex(salt),PASSWORD_ITERATIONS),
        env.DB.prepare("INSERT INTO akt_member_subscriptions(user_id,plan_code,status) VALUES(?,?,?)").bind(id,"free","free")
      ]);
    }catch(error){
      const duplicate=await env.DB.prepare("SELECT id FROM akt_members WHERE email=?").bind(email).first<any>();
      if(duplicate)return json({error:"An account with this email already exists."},409);
      throw error;
    }
    const headers=await saveMemberSession(env,id);
    return withHeaders(json({ok:true,member:{id,email,displayName,emailVerified:false,membership:{plan:"free",status:"free",currentPeriodEnd:null}}},201),headers);
  }
  if(path==="/api/auth/login"&&req.method==="POST"){
    if(!sameSite(req))return json({error:"This request was not allowed."},403);
    const ip=await clientKey(req,env);
    if(!await allow(env,"login:ip:"+ip,30,900))return tooMany(900);
    const body=await readJson(req,4096);
    const email=typeof body?.email==="string"?body.email.trim().toLowerCase():"";
    const password=typeof body?.password==="string"?body.password:"";
    const bad=()=>json({error:"Email or password is incorrect."},401);
    if(!email||email.length>254||!password||password.length>128)return bad();
    if(!await allow(env,"login:em:"+(await hmac(env.SESSION_SECRET,"em:"+email)).slice(0,22),8,900))return tooMany(900);
    const row=await env.DB.prepare("SELECT id,email,display_name,email_verified,password_hash,password_salt,password_iterations FROM akt_members WHERE email=?").bind(email).first<any>();
    // Always do the same amount of hashing work so response time does not reveal whether an email has an account.
    const actual=await passwordHash(password,row?fromHex(row.password_salt):DUMMY_SALT,row?Number(row.password_iterations):PASSWORD_ITERATIONS);
    const expected=row?fromHex(row.password_hash):new Uint8Array(32);
    let diff=actual.length^expected.length;
    for(let i=0;i<Math.max(actual.length,expected.length);i++)diff|=(actual[i]||0)^(expected[i]||0);
    if(!row||diff!==0)return bad();
    const headers=await saveMemberSession(env,row.id);
    return withHeaders(json({ok:true,member:{id:row.id,email:row.email,displayName:row.display_name,emailVerified:!!row.email_verified,membership:await membershipFor(env,row.id)}}),headers);
  }
  return json({error:"Not found."},404);
}

async function owned(env:Env,owner:string,id:string){const p=await env.DB.prepare("SELECT * FROM akt_playlists WHERE id=? AND owner_id=?").bind(id,owner).first<any>();if(!p)return null;const {results=[]}=await env.DB.prepare("SELECT track_id AS trackId, position, added_at AS addedAt FROM akt_playlist_tracks WHERE playlist_id=? ORDER BY position, added_at").bind(id).all<any>();return {...p,createdAt:new Date(p.created_at.replace(" ","T")+"Z").toISOString(),updatedAt:new Date(p.updated_at.replace(" ","T")+"Z").toISOString(),tracks:results.map((x:any)=>({...x,addedAt:new Date(x.addedAt.replace(" ","T")+"Z").toISOString()})),trackCount:results.length};}
async function playlists(req:Request,env:Env,owner:string,path:string){const method=req.method;const parts=path.replace(/^\/api\/playlists\/?/,"").split("/").filter(Boolean);const id=parts[0];const body=method==="GET"||method==="DELETE"?{}:await readJson(req,8192) as any;if(!id&&method==="GET"){const {results=[]}=await env.DB.prepare("SELECT * FROM akt_playlists WHERE owner_id=? ORDER BY updated_at DESC,name ASC").bind(owner).all<any>();const rows=[];for(const p of results)rows.push(await owned(env,owner,p.id));return json(rows);}if(!id&&method==="POST"){if(!body||typeof body.name!=="string"||!body.name.trim()||body.name.trim().length>80||typeof body.description==="string"&&body.description.length>500)return json({error:"Invalid playlist details."},400);const count=await env.DB.prepare("SELECT COUNT(*) n FROM akt_playlists WHERE owner_id=?").bind(owner).first<any>();if(count.n>=100)return json({error:"This browser has reached its playlist limit."},409);const pid=crypto.randomUUID();await env.DB.prepare("INSERT INTO akt_playlists(id,owner_id,name,description) VALUES(?,?,?,?)").bind(pid,owner,body.name.trim(),body.description?.trim()||null).run();return json(await owned(env,owner,pid),201);}if(!id)return json({error:"Not found."},404);if(parts.length===1&&method==="GET"){const p=await owned(env,owner,id);return p?json(p):json({error:"Playlist not found."},404);}if(parts.length===1&&method==="PATCH"){if(!body||(!("name"in body)&&!("description"in body))||body.name!==undefined&&(typeof body.name!=="string"||!body.name.trim()||body.name.trim().length>80)||body.description!==undefined&&body.description!==null&&(typeof body.description!=="string"||body.description.length>500))return json({error:"Invalid playlist details."},400);const p=await owned(env,owner,id);if(!p)return json({error:"Playlist not found."},404);await env.DB.prepare("UPDATE akt_playlists SET name=COALESCE(?,name), description=CASE WHEN ? THEN ? ELSE description END, updated_at=CURRENT_TIMESTAMP WHERE id=? AND owner_id=?").bind(body.name?.trim()||null,"description"in body?1:0,body.description?.trim()||null,id,owner).run();return json(await owned(env,owner,id));}if(parts.length===1&&method==="DELETE"){const r=await env.DB.prepare("DELETE FROM akt_playlists WHERE id=? AND owner_id=?").bind(id,owner).run();return r.meta.changes?new Response(null,{status:204}):json({error:"Playlist not found."},404);}if(parts[1]==="tracks"&&parts.length===2&&method==="POST"){const tid=Number(body?.trackId);if(!TRACKS[tid])return json({error:"This track is not available in the current library."},400);const p=await owned(env,owner,id);if(!p)return json({error:"Playlist not found."},404);if(p.tracks.some((x:any)=>x.trackId===tid))return json(p,201);if(p.trackCount>=500)return json({error:"This playlist has reached its track limit."},409);await env.DB.prepare("INSERT INTO akt_playlist_tracks(id,playlist_id,track_id,position) VALUES(?,?,?,?)").bind(crypto.randomUUID(),id,tid,p.trackCount).run();await env.DB.prepare("UPDATE akt_playlists SET updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();return json(await owned(env,owner,id),201);}if(parts[1]==="tracks"&&parts.length===3&&method==="DELETE"){const tid=Number(parts[2]);const p=await owned(env,owner,id);if(!p)return json({error:"Playlist not found."},404);if(!p.tracks.some((x:any)=>x.trackId===tid))return json({error:"Track was not found in this playlist."},404);const remaining=p.tracks.filter((x:any)=>x.trackId!==tid);const stmts=[env.DB.prepare("DELETE FROM akt_playlist_tracks WHERE playlist_id=? AND track_id=?").bind(id,tid),env.DB.prepare("UPDATE akt_playlist_tracks SET position=position+1000 WHERE playlist_id=?").bind(id)];remaining.forEach((x:any,i:number)=>stmts.push(env.DB.prepare("UPDATE akt_playlist_tracks SET position=? WHERE playlist_id=? AND track_id=?").bind(i,id,x.trackId)));stmts.push(env.DB.prepare("UPDATE akt_playlists SET updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id));await env.DB.batch(stmts);return json(await owned(env,owner,id));}if(parts[1]==="track-order"&&parts.length===2&&method==="PUT"){const ids=body?.trackIds;if(!Array.isArray(ids)||ids.length>500||ids.some((x:any)=>!Number.isInteger(x)))return json({error:"Invalid track order."},400);const p=await owned(env,owner,id);if(!p)return json({error:"Playlist not found."},404);if(ids.length!==p.trackCount||new Set(ids).size!==ids.length||ids.some((x:number)=>!p.tracks.some((t:any)=>t.trackId===x)))return json({error:"The playlist changed. Reload it and try again."},409);const stmts=[env.DB.prepare("UPDATE akt_playlist_tracks SET position=position+1000 WHERE playlist_id=?").bind(id)];ids.forEach((tid:number,i:number)=>stmts.push(env.DB.prepare("UPDATE akt_playlist_tracks SET position=? WHERE playlist_id=? AND track_id=?").bind(i,id,tid)));stmts.push(env.DB.prepare("UPDATE akt_playlists SET updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id));await env.DB.batch(stmts);return json(await owned(env,owner,id));}return json({error:"Not found."},404);}
async function assets(req:Request,env:Env,path:string){
  const parts=path.split("/");
  if(parts.length!==5||parts[1]!=="api"||parts[2]!=="assets")return json({error:"Not found."},404);
  let folder:string,file:string;
  try{folder=decodeURIComponent(parts[3]);file=decodeURIComponent(parts[4]);}
  catch{return json({error:"Not found."},404);}
  const allowed=["Artist Profiles","Beat Animations","Beat Covers","Site Images","Song Cover"];
  if(!allowed.includes(folder)||file.includes("..")||file.includes("/")||file.includes(String.fromCharCode(92)))return json({error:"Not found."},404);
  const prefix=mediaKeyPrefix(env);
  const folderPrefix=[prefix,folder].filter(Boolean).join("/")+"/";
  let cursor:string|undefined;
  let match:R2Object|null=null;
  const normalize=(value:string)=>{
    let base=value.split("/").pop()||value;
    const dot=base.lastIndexOf(".");
    if(dot>0)base=base.slice(0,dot);
    return base.toLowerCase().replace(/[^a-z0-9]/g,"");
  };
  const wanted=normalize(file);
  const isMedia=(key:string)=>{
    const dot=key.lastIndexOf(".");
    const ext=dot>=0?key.slice(dot+1).toLowerCase():"";
    return ["jpg","jpeg","png","webp","gif","svg","mp4","webm"].includes(ext);
  };
  const exact=await env.MEDIA_BUCKET.head(folderPrefix+file);
  if(exact&&isMedia(exact.key))match=exact;
  if(!match&&!await allow(env,"asset-miss:"+await clientKey(req,env),60,600))return tooMany(600);
  for(let page=0;page<10&&!match;page++){
    const listed=await env.MEDIA_BUCKET.list({prefix:folderPrefix,limit:1000,cursor});
    const candidates=listed.objects.filter(o=>{
      return !o.key.slice(folderPrefix.length).includes("/")&&isMedia(o.key);
    });
    match=candidates.find(o=>o.key===folderPrefix+file)||candidates.find(o=>normalize(o.key)===wanted)||null;
    if(!match){
      const partial=candidates.filter(o=>{
        const n=normalize(o.key);
        return n.startsWith(wanted)||wanted.startsWith(n);
      });
      if(partial.length===1)match=partial[0];
    }
    if(!match){
      if(!listed.truncated||!listed.cursor)break;
      cursor=listed.cursor;
    }
  }
  if(!match)return json({error:"Asset not found."},404);
  const dot=match.key.lastIndexOf(".");
  const ext=dot>=0?match.key.slice(dot+1).toLowerCase():"";
  const types:Record<string,string>={jpg:"image/jpeg",jpeg:"image/jpeg",png:"image/png",webp:"image/webp",gif:"image/gif",svg:"image/svg+xml",mp4:"video/mp4",webm:"video/webm"};
  const headers:Record<string,string>={"content-type":types[ext]||"application/octet-stream","cache-control":"public, max-age=300","accept-ranges":"bytes"};
  const range=req.headers.get("range");
  if(range){
    const parsed=/^bytes=([0-9]*)-([0-9]*)$/.exec(range);
    const meta=await env.MEDIA_BUCKET.head(match.key);
    if(!meta)return json({error:"Asset not found."},404);
    if(!parsed)return new Response(null,{status:416,headers:{"content-range":`bytes */${meta.size}`}});
    const start=parsed[1]?Number(parsed[1]):Math.max(0,meta.size-Number(parsed[2]));
    const end=parsed[2]&&parsed[1]?Math.min(Number(parsed[2]),meta.size-1):meta.size-1;
    if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||start>end||start>=meta.size)return new Response(null,{status:416,headers:{"content-range":`bytes */${meta.size}`}});
    const obj=await env.MEDIA_BUCKET.get(match.key,{range:{offset:start,length:end-start+1}});
    if(!obj)return json({error:"Asset storage is unavailable."},502);
    headers["content-length"]=String(end-start+1);
    headers["content-range"]=`bytes ${start}-${end}/${meta.size}`;
    return new Response(obj.body,{status:206,headers});
  }
  const obj=await env.MEDIA_BUCKET.get(match.key);
  if(!obj)return json({error:"Asset not found."},404);
  headers["content-length"]=String(obj.size);
  return new Response(obj.body,{headers});
}
const inner={
  async fetch(req:Request,env:Env):Promise<Response>{
    const url=new URL(req.url);
    try{
      if(url.pathname==="/api/healthz"||url.pathname==="/api/healthz/"){
        if(!env.HEALTH_TOKEN||!safeEqual(req.headers.get("x-health-token")||"",env.HEALTH_TOKEN))return json({status:"ok"});
        let r2Readable=false,r2ObjectCount=0,d1Readable=false;
        try{
          const result=await env.MEDIA_BUCKET.list({limit:1});
          r2Readable=true;
          r2ObjectCount=result.objects.length;
        }catch(error){
          console.error("AKT Media R2 health check failed",error);
        }
        try{
          await env.DB.prepare("SELECT 1 AS ok").first();
          d1Readable=true;
        }catch(error){
          console.error("AKT Media D1 health check failed",error);
        }
        return json({
          status:"ok",
          bindings:{
            sessionSecret:!!env.SESSION_SECRET,
            audioTokenSecret:!!env.AUDIO_TOKEN_SECRET,
            mediaBucket:!!env.MEDIA_BUCKET,
            database:!!env.DB,
            r2Readable,
            r2HasObjects:r2ObjectCount>0,
            d1Readable,
            mediaKeyPrefixConfigured:!!env.MEDIA_KEY_PREFIX
          }
        });
      }
      if(url.pathname.startsWith("/api/")){
        if(!env.SESSION_SECRET||env.SESSION_SECRET.length<32){console.error("SESSION_SECRET is missing or shorter than 32 characters");return json({error:"Service is not configured."},503);}
        const {id,headers}=await session(req,env);
        let res:Response;
        if(url.pathname.startsWith("/api/auth/")){
          res=await auth(req,env,url.pathname);
        }else if(url.pathname==="/api/playlists"||url.pathname.startsWith("/api/playlists/")){
          if(req.method!=="GET"&&req.method!=="HEAD"){
            if(!sameSite(req))res=json({error:"This request was not allowed."},403);
            else if(!await allow(env,"pl:"+await clientKey(req,env),300,600))res=tooMany(600);
            else res=await playlists(req,env,id,url.pathname);
          }else res=await playlists(req,env,id,url.pathname);
        }else if(url.pathname.startsWith("/api/assets/")){
          res=await assets(req,env,url.pathname);
        }else if(url.pathname==="/api/audio/token"&&req.method==="POST"){
          if(!sameSite(req))res=json({error:"This audio request was not allowed."},403);
          else if(!await allow(env,"tok:s:"+id,120,600)||!await allow(env,"tok:ip:"+await clientKey(req,env),300,600))res=tooMany(600);
          else{
            const body=(await readJson(req,1024)||{}) as any;
            const t=TRACKS[Number(body.trackId)];
            if(!t)res=json({error:"Track not found."},404);
            else{
              const ttl=Math.max(1,Math.min(Number(env.AUDIO_TOKEN_TTL_SECONDS)||600,3600));
              const expiresAt=Date.now()+ttl*1000;
              const variant=fullAccess(env,t,await currentMember(req,env))?"f":"p";
              const ua=await digest(req.headers.get("user-agent")||"");
              const sig=await hmacUrl(await audioSecret(env),[t.id,expiresAt,variant,id,ua.slice(0,22)].join("."));
              res=json({url:`/api/audio/stream/${t.id}?token=${expiresAt}.${variant}.${sig}`,expiresAt:new Date(expiresAt).toISOString(),expiresIn:ttl,preview:variant==="p"});
            }
          }
        }else if(url.pathname.startsWith("/api/audio/stream/")&&req.method==="GET"){
          if(!sameSite(req))res=json({error:"This audio request was not allowed."},403);
          else if(!await allow(env,"stream:s:"+id,600,600))res=tooMany(600);
          else res=await media(req,env,Number(url.pathname.split("/").pop()),url.searchParams.get("token")||"",id);
        }else{
          res=json({error:"Not found."},404);
        }
        return withHeaders(res,headers);
      }
      return env.ASSETS.fetch(req);
    }catch(error){
      const message=error instanceof Error?error.message:String(error);
      const stack=error instanceof Error?error.stack:undefined;
      console.error("AKT Media Worker request failed",{path:url.pathname,message,stack});
      return json({error:"Worker request failed.",path:url.pathname},500);
    }
  }
};
export default {
  async fetch(req:Request,env:Env):Promise<Response>{
    return secure(await inner.fetch(req,env),req,env);
  }
};
