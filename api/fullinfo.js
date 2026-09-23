const SERVER = 'http://161.202.221.10:30106';

async function upstream(path, apiKey, payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25000);
  let r;
  try {
    r = await fetch(`${SERVER}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
  } finally { clearTimeout(timer); }
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!r.ok) throw new Error(data?.message || data?.error || `Upstream HTTP ${r.status}`);
  return data;
}

function first(obj, ...keys) {
  for (const k of keys) if (obj && obj[k] !== undefined && obj[k] !== null && obj[k] !== '') return obj[k];
  return null;
}
function roleZone(ban) {
  const d = ban?.data;
  const x = Array.isArray(d) ? d[0] : (d && typeof d === 'object' ? d : ban);
  return { role: first(x,'role_id','roleId','Role ID','account_id','uid'), zone: first(x,'zone_id','zoneId','Zone ID') };
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({error:'POST only'});
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const apiKey = String(body.apiKey || '').trim();
    const deviceId = String(body.deviceId || '').trim();
    const mode = String(body.mode || 'full');
    if (!apiKey) return res.status(400).json({error:'API Key required'});
    if (!/^(and_|ios_)[A-Za-z0-9-]+$/i.test(deviceId)) return res.status(400).json({error:'Invalid device ID'});
    if (!['valid','ban','full'].includes(mode)) return res.status(400).json({error:'Unsupported mode'});
    if (mode === 'valid') return res.status(200).json(await upstream('/device_id',apiKey,{device_id:deviceId,mode:'valid'}));
    if (mode === 'ban') return res.status(200).json(await upstream('/device_id',apiKey,{device_id:deviceId,mode:'ban'}));
    const ban = await upstream('/device_id',apiKey,{device_id:deviceId,mode:'ban'});
    const {role,zone} = roleZone(ban);
    let info = null;
    if (role !== null && zone !== null) info = await upstream('/info',apiKey,{role_id:String(role),zone_id:String(zone),type:'lookup'});
    return res.status(200).json({device_id:deviceId,ban,info});
  } catch (e) {
    return res.status(502).json({error:e.message || 'Server request failed'});
  }
};
