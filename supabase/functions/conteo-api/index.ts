
const CORS={'Access-Control-Allow-Origin':'https://fravier3.github.io','Access-Control-Allow-Headers':'content-type, authorization, apikey','Access-Control-Allow-Methods':'GET, POST, OPTIONS','Cache-Control':'no-store'};
const url=Deno.env.get('SUPABASE_URL')!;
const service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const headers={apikey:service,Authorization:'Bearer '+service,'Content-Type':'application/json'};
const attempts=new Map<string,{count:number,until:number}>();
function json(data:unknown,status=200){return new Response(JSON.stringify(data),{status,headers:{...CORS,'Content-Type':'application/json'}});}
async function db(path:string,init:RequestInit={}){const r=await fetch(url+'/rest/v1/'+path,{...init,headers:{...headers,...init.headers}});if(!r.ok)throw new Error('database');return r.status===204?null:await r.json();}
function valid(c:any){if(!c||typeof c!=='object'||Array.isArray(c))return false;
 const limits:Record<string,number>={brand:60,eyebrow:100,title:140,description:500,closing:200,finishedMessage:200,date:10,time:5,zone:6,accent:7,background:2800000};
 for(const [k,max]of Object.entries(limits))if(typeof c[k]!=='string'||c[k].length>max)return false;
 if(!c.title.trim()||!c.finishedMessage.trim()||!/^\d{4}-\d{2}-\d{2}$/.test(c.date)||!/^\d{2}:\d{2}$/.test(c.time)||!['-04:00','-05:00','+00:00'].includes(c.zone)||!/^#[\da-f]{6}$/i.test(c.accent)||!Number.isFinite(Date.parse(c.date+'T'+c.time+':00'+c.zone)))return false;
 if(c.background&&!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(c.background))return false;
 return ['showEyebrow','showDescription','showDate','showSeconds','showClosing'].every(k=>typeof c[k]==='boolean')&&Object.keys(c).length===16;
}
Deno.serve(async(req:Request)=>{
 if(req.method==='OPTIONS')return new Response(null,{headers:CORS});
 try{
 if(req.method==='GET'){
 const since=new URL(req.url).searchParams.get('since');
 const [row]=await db('conteo_settings?id=eq.main&select=revision,updated_at');
 if(!row)return json({error:'Configuración no disponible.'},503);
 if(since===String(row.revision))return new Response(null,{status:204,headers:CORS});
 const [full]=await db('conteo_settings?id=eq.main&select=config,revision,updated_at');
 return json(full);
 }
 if(req.method!=='POST')return json({error:'Método no permitido.'},405);
 const text=await req.text();if(text.length>3000000)return json({error:'La imagen es demasiado grande.'},413);
 let body;try{body=JSON.parse(text);}catch{return json({error:'Solicitud inválida.'},400);}
 const ip=req.headers.get('x-forwarded-for')?.split(',')[0]||'unknown';
 const now=Date.now();let attempt=attempts.get(ip);if(!attempt||now>attempt.until){attempt={count:0,until:now+60000};attempts.set(ip,attempt);}
 if(attempt.count>=20)return json({error:'Demasiados intentos. Espera un minuto.'},429);
 attempt.count++;
 const [admin]=await db('conteo_admin?id=eq.main&select=password_hash');
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(typeof body.password==='string'?body.password:''));
 const hash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
 if(!admin||hash!==admin.password_hash)return json({error:'Contraseña incorrecta. Inténtalo de nuevo.'},401);
 if(body.action==='unlock')return json({ok:true});
 if(body.action!=='save'||!valid(body.config)||!Number.isSafeInteger(body.revision)||body.revision<1)return json({error:'Revisa los campos y la fecha.'},400);
 const rows=await db('conteo_settings?id=eq.main&revision=eq.'+body.revision+'&select=config,revision,updated_at',{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({config:body.config,revision:body.revision+1,updated_at:new Date().toISOString()})});
 if(!rows?.length)return json({error:'Los ajustes cambiaron en otro dispositivo. Revisa la versión más reciente antes de guardar.'},409);
 return json(rows[0]);
 }catch{return json({error:'No pudimos conectar. Inténtalo de nuevo.'},503);}
});
