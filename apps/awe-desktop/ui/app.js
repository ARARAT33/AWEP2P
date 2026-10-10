const view=document.getElementById("view"),title=document.getElementById("pageTitle"),navs=[...document.querySelectorAll(".nav")];
const pages={dashboard:["Home","Everything important in one place"],browser:["Browser","Open AWE sites and the web in a separate browser view"],node:["My Node","Your identity, runtime and listening endpoint"],network:["Peers & Connections","Discover and connect to AWEp2P nodes"],federation:["AWENET","Build Nodes, Data Centres and Data Groups"],storage:["Storage","Local and distributed data plane"],messenger:["Messenger","Peer-to-peer messaging"],communities:["Groups & Channels","Real peer communities over AWE transport"],store:["AWEStore","AWE modules and services"],security:["Security","Identity, transport and trust"],diagnostics:["Diagnostics","Health checks and runtime inspection"],settings:["Settings","Application configuration"]};
let live={status:"starting",node_id:"loading",node_address:"loading",transport:"loading",ui:"connecting",peers:[],node:{},storage:{},security:{},federation:{}};

function apiBase(){
 if(location.protocol==="http:"||location.protocol==="https:")return location.origin;
 return "http://127.0.0.1:41800";
}
async function api(path,options={}){
 const controller=new AbortController();
 const timer=setTimeout(()=>controller.abort(),8000);
 try{
  const r=await fetch(apiBase()+path,{...options,signal:controller.signal,cache:"no-store"});
  const text=await r.text();
  if(!r.ok)throw new Error(text||("HTTP "+r.status));
  try{return JSON.parse(text)}catch(_){throw new Error("Invalid API response")}
 }catch(e){
  if(e.name==="AbortError")throw new Error("API request timed out");
  throw e;
 }finally{clearTimeout(timer)}
}
const call={pc:null,id:null,remote:null,last:0,seen:new Set(),active:false};
let activeBrowserObjectUrl=null;
async function sendCallSignal(type,data){
 if(!call.remote||!call.id)return;
 await api("/api/call/signal",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({recipient:call.remote,call_id:call.id,signal_type:type,data:JSON.stringify(data)})});
}
async function startCall(kind){
 const remote=document.getElementById("callRecipient")?.value.trim();
 if(!remote)return toast("Enter the recipient AWE ID");
 if(!window.RTCPeerConnection||!navigator.mediaDevices?.getUserMedia)return toast("This runtime does not provide WebRTC media");
 await stopCall(); call.id=crypto.randomUUID();call.remote=remote;call.active=true;
 const status=document.getElementById("callStatus");if(status)status.textContent="Starting "+kind+" call…";
 const pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});call.pc=pc;
 pc.onicecandidate=e=>{if(e.candidate)sendCallSignal("ice",e.candidate).catch(()=>{})};
 pc.ontrack=e=>{if(e.streams[0]){const v=document.getElementById("remoteVideo"),a=document.getElementById("remoteAudio");if(e.track.kind==="video"&&v){v.srcObject=e.streams[0];v.style.display="block"}else if(a)a.srcObject=e.streams[0}}};
 pc.onconnectionstatechange=()=>{if(status)status.textContent="Call: "+pc.connectionState};
 const stream=await navigator.mediaDevices.getUserMedia({audio:true,video:kind==="video"});
 stream.getTracks().forEach(t=>pc.addTrack(t,stream));const lv=document.getElementById("localVideo");if(lv&&kind==="video"){lv.srcObject=stream;lv.style.display="block"}
 const offer=await pc.createOffer();await pc.setLocalDescription(offer);
 await sendCallSignal("offer",{sdp:offer.sdp,type:offer.type,media:kind});
 if(status)status.textContent="Calling…";
}
async function acceptCall(signal){
 await stopCall();call.id=signal.call_id;call.remote=signal.sender;call.active=true;
 const status=document.getElementById("callStatus");if(status)status.textContent="Incoming "+(signal.data.media||"voice")+" call…";
 const pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});call.pc=pc;
 pc.onicecandidate=e=>{if(e.candidate)sendCallSignal("ice",e.candidate).catch(()=>{})};
 pc.ontrack=e=>{const audio=document.getElementById("remoteAudio");if(audio&&e.streams[0])audio.srcObject=e.streams[0]};
 pc.onconnectionstatechange=()=>{if(status)status.textContent="Call: "+pc.connectionState};
 const stream=await navigator.mediaDevices.getUserMedia({audio:true,video:signal.data.media==="video"});
 stream.getTracks().forEach(t=>pc.addTrack(t,stream));
 await pc.setRemoteDescription(signal.data);
 const answer=await pc.createAnswer();await pc.setLocalDescription(answer);
 await sendCallSignal("answer",{sdp:answer.sdp,type:answer.type});
}
async function stopCall(){
 if(call.active&&call.remote&&call.id){try{await sendCallSignal("hangup",{})}catch(_){}}
 if(call.pc){call.pc.getSenders().forEach(s=>s.track?.stop());call.pc.close()}
 call.pc=null;call.id=null;call.remote=null;call.active=false;
 const audio=document.getElementById("remoteAudio");if(audio)audio.srcObject=null;const lv=document.getElementById("localVideo");if(lv){lv.srcObject=null;lv.style.display="none"}const rv=document.getElementById("remoteVideo");if(rv){rv.srcObject=null;rv.style.display="none"}
 const status=document.getElementById("callStatus");if(status)status.textContent="No active call";
}
async function pollCallSignals(){
 try{
  const r=await api("/api/call/signals?since="+encodeURIComponent(call.last));
  for(const s of (r.signals||[])){
   if(call.seen.has(s.id))continue;call.seen.add(s.id);call.last=Math.max(call.last,Number(s.timestamp)||0);
   let data={};try{data=JSON.parse(s.data||"{}")}catch(_){}
   if(s.signal_type==="offer"&&!call.active){await acceptCall({...s,data})}
   else if(call.pc&&s.call_id===call.id&&s.signal_type==="answer"){await call.pc.setRemoteDescription(data)}
   else if(call.pc&&s.call_id===call.id&&s.signal_type==="ice"){try{await call.pc.addIceCandidate(data)}catch(_){}}
   else if(call.active&&s.call_id===call.id&&s.signal_type==="hangup"){await stopCall()}
  }
 }catch(_){}
}
async function loadMessenger(){
 try{
  const d=await api("/api/messenger");
  const box=document.getElementById("messageList");
  if(box)box.innerHTML=d.messages?.length?d.messages.map(m=>'<div class="list-row"><span>'+esc(m.recipient||m.sender)+'</span><b>'+esc(m.state)+'</b><span>'+esc(m.text)+'</span></div>').join(""):'<div class="empty">No messages yet.</div>';
 }catch(e){
  const box=document.getElementById("messageList");
  if(box)box.innerHTML='<div class="empty">Messenger is unavailable: '+esc(e.message)+'</div>';
 }
}
async function refresh(){
 const results=await Promise.allSettled([
  api("/api/status"),api("/api/node"),api("/api/storage"),api("/api/security"),api("/api/federation")
 ]);
 const [status,node,storage,security,federation]=results.map(x=>x.status==="fulfilled"?x.value:null);
 if(status||node){
  live={
   ...live,
   ...(status||{}),
   node:node||live.node,
   storage:storage||live.storage,
   security:security||live.security,
   federation:federation||live.federation
  };
  if(!status)live.status=live.status||"online";
  setConnection(true);
 }else{
  live={...live,status:"offline",ui:"disconnected",peers:[]};
  setConnection(false);
 }
}
function setConnection(on){document.getElementById("sideDot").classList.toggle("online",on);document.getElementById("sideState").textContent=on?"Node online":"Disconnected";document.getElementById("sideTransport").textContent=on?live.transport:"API unavailable";document.getElementById("apiBadge").textContent="API · "+(on?live.ui:"offline")}
function esc(x){return String(x??"").replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[c]))}
function card(a,b,c="Live runtime"){return '<div class="card"><div class="metric-label">'+a+'</div><div class="metric">'+esc(b)+'</div><div class="muted">'+c+'</div></div>'}
function panel(h,body,extra=""){return '<div class="section panel"><div class="section-head"><h2>'+h+'</h2>'+extra+'</div>'+body+'</div>'}
function peerRows(){return live.peers.length?live.peers.map(p=>'<tr><td><div class="peer"><i class="peer-dot"></i><b>'+esc(p.id)+'</b></div></td><td>'+esc(p.address)+'</td><td>'+esc(p.last_seen)+'</td><td><span class="status"><i></i>Discovered</span></td></tr>').join(""):'<tr><td colspan="4" class="empty">No peers are currently known to this node.</td></tr>'}
function render(k){
 const p=pages[k]||pages.dashboard;navs.forEach(n=>n.classList.toggle("active",n.dataset.view===k));title.textContent=p[0];
 let body="";
 if(k==="browser"){
  body=panel("Browser",'<div class="browser-bar"><input id="browserUrl" value="awe://home" placeholder="awe://fid-64hex, awe://site-id or https://example.com"><button class="primary" id="browserGo">Open</button><button class="secondary" id="browserExternal">↗ External</button></div><div class="browser-hint">AWE resources use native <b>awe://</b> IDs. Stored files can be opened as <b>awe://fid-&lt;64hex&gt;</b>.</div><iframe id="browserFrame" class="browser-frame" title="AWE Browser" referrerpolicy="no-referrer" src="about:blank"></iframe>');
 } else if(k==="dashboard"){
  body='<div class="grid">'+card("Node status",live.status.toUpperCase())+card("Data centre",live.node?.descriptor?"Node registered":"Local node","Live node descriptor")+card("Node ID",live.node_id,"AWE identity")+card("Connected peers",live.status?.active_connections||0,"Authenticated live connections")+card("Transport",live.transport,"Node transport")+'</div>'+
  '<div class="section two">'+panel("Network topology",'<div class="network-map"><div class="node-point main" style="left:49%;top:47%"></div>'+live.peers.slice(0,8).map((_,i)=>{const a=i*45;return '<div class="line" style="left:51%;top:51%;width:105px;transform:rotate('+a+'deg)"></div><div class="node-point" style="left:'+(50+34*Math.cos(a*Math.PI/180))+'%;top:'+(50+34*Math.sin(a*Math.PI/180))+'%"></div>'}).join("")+'</div>'),panel("Runtime health",'<div class="big-status"><div class="big-orb">'+(live.status==="online"?"✓":"!")+'</div><div><b>'+esc(live.status==="online"?"Node operational":"Node unavailable")+'</b><div class="detail">'+esc(live.node_address)+'</div></div></div><div class="list section"><div class="list-row"><span>Core API</span><span class="status"><i></i>'+esc(live.ui)+'</span></div><div class="list-row"><span>Known peers</span><b>'+live.peers.length+'</b></div></div>'))+
  panel("Known peers",'<table class="table"><thead><tr><th>Peer</th><th>Address</th><th>Last seen</th><th>State</th></tr></thead><tbody>'+peerRows()+'</tbody></table>','<button class="secondary" id="goNetwork">Manage</button>');
 } else if(k==="node"){
  body='<div class="grid">'+card("Status",live.status.toUpperCase())+card("Identity",live.node_id,"Public AWE identity")+card("Listen",live.node_address,"Local node endpoint")+card("Transport",live.transport,"Active protocol")+'</div>'+
  panel("Identity",'<div class="list"><div class="list-row"><span>AWE Node ID</span><b>'+esc(live.node_id)+'</b></div><div class="list-row"><span>Listen address</span><b>'+esc(live.node_address)+'</b></div><div class="list-row"><span>Transport</span><b>'+esc(live.transport)+'</b></div><div class="list-row"><span>Known peers</span><b>'+live.peers.length+'</b></div></div>')+
  panel("Runtime",'<div class="notice">This screen represents the actual local Rust node. Identity and endpoint values come from the running node API.</div>');
 } else if(k==="network"){
  body=panel("Connect to node",'<div class="peer-form"><input id="peerAddress" placeholder="127.0.0.1:41000"><button class="primary" id="connectBtn">Connect</button></div><div class="muted" style="margin-top:8px">Enter a reachable AWEp2P node address. The Rust node performs bootstrap/discovery.</div>')+
  panel("Known peers",'<table class="table"><thead><tr><th>Peer</th><th>Address</th><th>Last seen</th><th>State</th></tr></thead><tbody>'+peerRows()+'</tbody></table>','<button class="secondary" id="peerRefresh">Refresh</button>')+
  panel("Topology",'<div class="network-map"><div class="node-point main" style="left:49%;top:47%"></div>'+live.peers.map((_,i)=>{const a=i*(360/Math.max(live.peers.length,1));return '<div class="line" style="left:51%;top:51%;width:100px;transform:rotate('+a+'deg)"></div><div class="node-point" style="left:'+(50+35*Math.cos(a*Math.PI/180))+'%;top:'+(50+35*Math.sin(a*Math.PI/180))+'%"></div>'}).join("")+'</div>');
 else if(k==="federation"){
  body=panel("AWENET identity",'<div class="grid">'+card("Node",live.node_id,"Current local identity")+card("Data centre",live.federation?.data_centre_id||"Not joined","Current membership")+card("Data group",live.federation?.data_group_id||"Not joined","Current membership")+card("Centres",live.federation?.joined_data_centres?.length||0,"Imported .awenode/.awedc memberships")+card("Live links",live.status?.active_connections||0,"Authenticated transport connections")+card("Groups",live.federation?.joined_data_groups?.length||0,"Imported .dgc memberships")+'</div>')+
  panel("1 · Create .awenode",'<div class="peer-form"><input id="fedNodeName" placeholder="Data centre name"><input id="fedNodeDcId" placeholder="Existing Data centre ID (optional)"><input id="fedEndpoint" placeholder="'+esc(live.node_address)+'"><input id="fedBootstrap" placeholder="Owner endpoints: host:41000,host2:41000"><button class="primary" id="genNode">Generate</button></div><div class="muted" style="margin-top:8px">Install this configuration on another AWEp2P node and import it from this screen to join the same data centre.</div>')+
  panel("2 · Create .awedc",'<div class="peer-form"><input id="fedDcId" placeholder="Data centre ID"><input id="fedDcName" placeholder="Data centre name"><input id="fedEndpoints" placeholder="host:41000,host2:41000"><button class="primary" id="genDc">Generate</button></div><div class="muted" style="margin-top:8px">The data-centre package describes the owner, member nodes and reachable transport endpoints.</div>')+
  panel("3 · Create .dgc",'<div class="peer-form"><input id="fedOwnerDc" placeholder="Owner data centre ID"><input id="fedGroupName" placeholder="Data group name"><input id="fedCentres" placeholder="dc-1,dc-2,dc-3"><button class="primary" id="genDgc">Generate</button></div><div class="muted" style="margin-top:8px">A data group joins data centres into a higher-level AWENET group.</div>')+
  panel("Import configuration",'<div class="peer-form"><select id="fedKind"><option value="awenode">.awenode — Node → Data Centre</option><option value="awedc">.awedc — Data Centre → Data Centre</option><option value="dgc">.dgc — Data Group → Data Group</option></select><input type="file" id="fedFile" accept=".awenode,.awedc,.dgc,application/json"><button class="primary" id="importFed">Import & Join</button></div><div id="fedResult" class="notice" style="margin-top:10px">Choose a configuration file. The Rust core validates its format before accepting it.</div>');
 } else if(k==="storage"){
  const used=localStorage.getItem("aweStoragePath")||"Node-managed storage";
  const free=live.storage.free_bytes||0;
  const usedBytes=live.storage.used_bytes||0;
  const fmt=n=>{n=Number(n)||0;if(n<1024)return n+" B";if(n<1048576)return (n/1024).toFixed(1)+" KB";if(n<1073741824)return (n/1048576).toFixed(1)+" MB";return (n/1073741824).toFixed(2)+" GB"};
  body='<div class="grid">'+card("Data plane","Active","Storage subsystem")+card("Used",fmt(usedBytes),"Local content-addressed objects")+card("Free",fmt(free),"Available disk space")+card("Policy",String(live.storage.shards||"Adaptive"),"Shards × replicas")+'</div>'+
  panel("Upload file",'<div class="peer-form"><input type="file" id="storageFile"><button class="primary" id="uploadStorage">Upload & Replicate</button></div><div id="storageUploadResult" class="notice" style="margin-top:10px">The node stores, verifies and replicates the selected bytes. The UI never manages shard placement itself.</div>')+
  panel("Download / reconstruct",'<div class="peer-form"><input id="downloadFileId" placeholder="File ID (64 hex characters)"><button class="primary" id="downloadStorage">Reconstruct & Download</button></div><div id="storageDownloadResult" class="notice" style="margin-top:10px">AWEp2P will retrieve missing remote shards when needed and reconstruct the original file.</div>')+
  panel("Storage details",'<div class="list"><div class="list-row"><span>Storage root</span><b>'+esc(live.storage.root||used)+'</b></div><div class="list-row"><span>Objects</span><b>'+esc(live.storage.objects||0)+'</b></div><div class="list-row"><span>Healthy replicas</span><b>'+esc(live.storage.healthy_replicas||0)+'</b></div><div class="list-row"><span>Repaired chunks</span><b>'+esc(live.storage.repaired_chunks||0)+'</b></div></div>');
 } else if(k==="messenger"){
  body=panel("Messenger",'<div class="peer-form"><input id="msgRecipient" placeholder="Recipient AWE ID"><input id="msgText" placeholder="Message"><button class="primary" id="sendMsg">Send</button></div><div id="msgState" class="muted" style="margin-top:8px">Messages use authenticated AWE peer transport; delivery appears when the remote node receives the message.</div>')+
  panel("Realtime calls",'<div class="peer-form"><input id="callRecipient" placeholder="Recipient AWE ID"><button class="primary" id="voiceCall">Voice call</button><button class="secondary" id="videoCall">Video call</button><button class="secondary" id="hangupCall">Hang up</button></div><div id="callStatus" class="notice" style="margin-top:10px">No active call</div><video id="localVideo" autoplay muted playsinline style="display:none;max-width:320px"></video><video id="remoteVideo" autoplay playsinline style="display:none;max-width:480px"></video><audio id="remoteAudio" autoplay playsinline></audio>')+
  panel("Local message queue",'<div id="messageList" class="list"><div class="empty">Loading…</div></div>');
 } else if(k==="communities"){
  body=panel("Create group",'<div class="peer-form"><input id="groupTitle" placeholder="Group name"><input id="groupMembers" placeholder="Member AWE IDs, comma separated"><button class="primary" id="createGroup">Create group</button></div>')+
  panel("Groups",'<div id="groupList" class="list"><div class="empty">Loading…</div></div>')+
  panel("Send group message",'<div class="peer-form"><input id="groupMessageId" placeholder="Group ID (gid-…)"><input id="groupMessageText" placeholder="Message"><button class="primary" id="sendGroupMessage">Send</button></div>')+
  panel("Create channel",'<div class="peer-form"><input id="channelTitle" placeholder="Channel name"><button class="primary" id="createChannel">Create channel</button></div>')+
  panel("Channels",'<div id="channelList" class="list"><div class="empty">Loading…</div></div>')+
  panel("Subscribe / publish",'<div class="peer-form"><input id="channelId" placeholder="Channel ID (cid-…)"><button class="secondary" id="subscribeChannel">Subscribe</button><input id="channelMessageText" placeholder="Owner message"><button class="primary" id="publishChannel">Publish</button></div>');
 } else if(k==="store"){
  body=panel("AWEStore",'<div id="storeCatalog" class="store-grid"><div class="empty">Loading verified packages…</div></div>','<button class="secondary" id="storeRefresh">Refresh</button>')+
  panel("Security",'<div class="notice">Only packages that pass AWE package integrity and developer-signature verification are shown. Installation grants only the capabilities you explicitly approve.</div>');

 } else if(k==="security"){
  body='<div class="grid">'+card("Identity",live.node_id,"Public node identity")+card("Transport",live.transport,"Network layer")+card("Peer count",live.peers.length,"Known peers")+card("Trust","Core-managed","No UI-only security state")+'</div>'+
  panel("Security model",'<div class="list"><div class="list-row"><span>Node identity</span><b>Rust core</b></div><div class="list-row"><span>Authentication</span><b>Core protocol</b></div><div class="list-row"><span>Transport</span><b>'+esc(live.transport)+'</b></div><div class="list-row"><span>Secrets</span><b>Local identity vault</b></div></div>');
 } else if(k==="diagnostics"){
  body='<div class="grid">'+card("Node",live.status.toUpperCase(),"Live API status")+card("API",live.ui,"Dashboard connection")+card("Peers",live.peers.length,"Known peers")+card("Endpoint",live.node_address,"Listen endpoint")+'</div>'+
  panel("Runtime diagnostics",'<div class="terminal"><div>$ GET /api/status</div><div class="green">200 · '+esc(live.status)+'</div><div>$ node</div><div class="green">'+esc(live.node_id)+'</div><div>$ peers</div><div class="green">'+live.peers.length+' known peer(s)</div></div>','<button class="primary" id="healthBtn">Run health check</button>')+
  panel("Result",'<div id="healthResult" class="notice">Press “Run health check” to query the live node health endpoint.</div>');
 } else if(k==="settings"){
  body=panel("Automatic runtime",'<div class="list"><div class="list-row"><span>Node API</span><b>'+esc(apiBase())+'</b></div><div class="list-row"><span>Connection</span><b>Automatic</b></div><div class="list-row"><span>Auto refresh</span><b>5 seconds</b></div><div class="list-row"><span>Storage</span><b>Node-managed</b></div></div>')+
  panel("Identity & security",'<div class="notice">AWEp2P manages the local node, identity, transport and storage automatically. There is no manual API endpoint configuration in the product UI.</div>');
 }
 view.innerHTML='<div class="content"><div class="hero"><div><h1>'+p[0]+'</h1><p>'+p[1]+'</p></div><div class="actions"><button class="secondary" id="refreshBtn">Refresh</button></div></div>'+body+'</div>';
 bind(k);
}
function bind(k){
  async function openBrowser(){
    const input=document.getElementById("browserUrl")?.value.trim()||"";
    const frame=document.getElementById("browserFrame");
    if(!input||!frame)return;
    frame.referrerPolicy="no-referrer";
    const awe=input.match(/^awe:\/\/fid-([0-9a-f]{64})$/i);
    if(awe){
      try{
        const r=await api("/api/storage/get?file_id="+encodeURIComponent(awe[1]));
        const raw=String(r.data_hex||"");
        if(!/^(?:[0-9a-f]{2})*$/i.test(raw))throw new Error("Malformed object data");
        const bytes=new Uint8Array(raw.length/2);
        for(let i=0;i<bytes.length;i++)bytes[i]=parseInt(raw.slice(i*2,i*2+2),16);
        const name=String(r.filename||"").toLowerCase();
        const type=/\.html?$/.test(name)?"text/html":/\.svg$/.test(name)?"image/svg+xml":/\.json$/.test(name)?"application/json":"application/octet-stream";
        // A stored site is untrusted content. Keep its origin opaque and deny
        // access to the AWENET parent window and loopback API.
        frame.setAttribute("sandbox","allow-scripts allow-forms allow-popups");
        if(activeBrowserObjectUrl)URL.revokeObjectURL(activeBrowserObjectUrl);
        activeBrowserObjectUrl=URL.createObjectURL(new Blob([bytes],{type}));
        frame.src=activeBrowserObjectUrl;
        return;
      }catch(e){toast("AWE resource unavailable: "+e.message);return}
    }
    if(input.startsWith("awe://")){
      frame.setAttribute("sandbox","");
      frame.srcdoc='<h2>AWENET resource</h2><p>Resolved address: '+esc(input)+'</p><p>Use an <b>awe://fid-&lt;64hex&gt;</b> resource ID for a network-native stored object.</p>';
      return;
    }
    const external=/^https?:\/\//i.test(input)?input:"https://"+input;
    let parsed;
    try{parsed=new URL(external)}catch(_){toast("Enter a valid http(s) URL or AWE resource ID");return}
    if(parsed.protocol!=="http:"&&parsed.protocol!=="https:"){toast("Only http(s) external URLs are supported");return}
    // External pages stay cross-origin; no-referrer avoids leaking the local UI URL.
    frame.removeAttribute("sandbox");
    frame.src=parsed.href;
  }
 const bg=document.getElementById("browserGo");if(bg)bg.onclick=openBrowser;
 const be=document.getElementById("browserExternal");if(be)be.onclick=()=>openBrowser();
 const bu=document.getElementById("browserUrl");if(bu)bu.addEventListener("keydown",e=>{if(e.key==="Enter")bg?.click()});
 const r=document.getElementById("refreshBtn");if(r)r.onclick=async()=>{await refresh();render(k)};
 const g=document.getElementById("goNetwork");if(g)g.onclick=()=>render("network");
 const pr=document.getElementById("peerRefresh");if(pr)pr.onclick=async()=>{await refresh();render("network")};
 const cb=document.getElementById("connectBtn");if(cb)cb.onclick=async()=>{const a=document.getElementById("peerAddress").value.trim();if(!a)return toast("Enter a node address");cb.disabled=true;try{const x=await api("/api/connect?address="+encodeURIComponent(a),{method:"POST"});toast("Bootstrap complete");await refresh();render("network")}catch(e){toast("Connection failed: "+e.message)}finally{cb.disabled=false}};
 const vc=document.getElementById("voiceCall");if(vc)vc.onclick=()=>startCall("voice");
 const vdc=document.getElementById("videoCall");if(vdc)vdc.onclick=()=>startCall("video");
 const hc=document.getElementById("hangupCall");if(hc)hc.onclick=()=>stopCall();
 const sr=document.getElementById("storeRefresh");if(sr)sr.onclick=()=>render("store");
 const up=document.getElementById("uploadStorage");if(up)up.onclick=async()=>{const file=document.getElementById("storageFile").files[0],box=document.getElementById("storageUploadResult");if(!file)return toast("Choose a file first");if(file.size>64*1024*1024)return toast("Maximum upload size is 64 MB");up.disabled=true;try{const buf=await file.arrayBuffer(),bytes=new Uint8Array(buf);let hex="";for(const b of bytes)hex+=b.toString(16).padStart(2,"0");const r=await api("/api/storage/put",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({filename:file.name,data_hex:hex})});box.textContent="Stored: "+r.file_id+" · "+r.status+" · "+(r.sent_remote||0)+" remote replica transfers";document.getElementById("downloadFileId").value=r.file_id;await refresh();render("storage")}catch(e){box.textContent="Upload failed: "+e.message}finally{up.disabled=false}};
 const dl=document.getElementById("downloadStorage");if(dl)dl.onclick=async()=>{const id=document.getElementById("downloadFileId").value.trim(),box=document.getElementById("storageDownloadResult");if(!/^[0-9a-fA-F]{64}$/.test(id))return toast("Enter a valid 64-hex file ID");dl.disabled=true;try{const r=await api("/api/storage/get?file_id="+encodeURIComponent(id));const raw=r.data_hex||"";const bytes=new Uint8Array(raw.length/2);for(let i=0;i<bytes.length;i++)bytes[i]=parseInt(raw.slice(i*2,i*2+2),16);const blob=new Blob([bytes],{type:"application/octet-stream"}),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=r.filename||"awep2p-file";a.click();URL.revokeObjectURL(a.href);box.textContent="Reconstructed and downloaded: "+r.filename+" · "+r.size+" bytes"}catch(e){box.textContent="Download failed: "+e.message}finally{dl.disabled=false}};
 const hb=document.getElementById("healthBtn");if(hb)hb.onclick=async()=>{const box=document.getElementById("healthResult");try{const x=await api("/api/health");box.innerHTML='<span class="status"><i></i>Health check passed</span><div class="detail" style="margin-top:8px">'+esc(JSON.stringify(x))+'</div>'}catch(e){box.textContent="Health check failed: "+e.message}};
  const gen=async(kind,payload)=>{try{const r=await api("/api/federation/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({kind,...payload})});if(r.status!=="generated")throw new Error(r.error||"generation failed");const blob=new Blob([r.content],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=r.filename;a.click();URL.revokeObjectURL(a.href);toast("Generated "+r.filename)}catch(e){toast("Generation failed: "+e.message)}};
  const gn=document.getElementById("genNode");if(gn)gn.onclick=()=>gen("awenode",{name:document.getElementById("fedNodeName").value.trim()||"AWE Data Centre",endpoint:document.getElementById("fedEndpoint").value.trim()||live.node_address,bootstrap:document.getElementById("fedBootstrap").value.split(",").map(x=>x.trim()).filter(Boolean),data_centre_id:document.getElementById("fedNodeDcId")?.value.trim()||live.federation?.data_centre_id||""});
  const gd=document.getElementById("genDc");if(gd)gd.onclick=()=>gen("awedc",{data_centre_id:document.getElementById("fedDcId").value.trim(),name:document.getElementById("fedDcName").value.trim()||"AWE Data Centre",endpoints:document.getElementById("fedEndpoints").value.split(",").map(x=>x.trim()).filter(Boolean)});
  const gg=document.getElementById("genDgc");if(gg)gg.onclick=()=>gen("dgc",{owner_data_centre_id:document.getElementById("fedOwnerDc").value.trim(),name:document.getElementById("fedGroupName").value.trim()||"AWE Data Group",data_centre_ids:document.getElementById("fedCentres").value.split(",").map(x=>x.trim()).filter(Boolean)});
  const imp=document.getElementById("importFed");if(imp)imp.onclick=async()=>{const file=document.getElementById("fedFile").files[0],box=document.getElementById("fedResult");if(!file)return toast("Choose a configuration file");imp.disabled=true;try{const content=await file.text(),kind=document.getElementById("fedKind").value,r=await api("/api/federation/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({kind,content})});if(r.status!=="imported")throw new Error(r.error||"import failed");box.textContent="Imported successfully. AWENET membership is now stored in this running node.";await refresh();render("federation");toast("AWENET configuration imported")}catch(e){box.textContent="Import failed: "+e.message}finally{imp.disabled=false}};
 if(k==="messenger")loadMessenger(); if(k==="communities"){
  const load=async()=>{try{const [g,c]=await Promise.all([api("/api/groups"),api("/api/channels")]);document.getElementById("groupList").innerHTML=(g.groups||[]).map(x=>'<div class="list-row"><b>'+esc(x.title)+'</b><span>'+esc(x.members?.length||0)+' members</span></div>').join("")||'<div class="empty">No groups yet.</div>';document.getElementById("channelList").innerHTML=(c.channels||[]).map(x=>'<div class="list-row"><b>'+esc(x.title)+'</b><span>'+esc(x.subscribers?.length||0)+' subscribers</span></div>').join("")||'<div class="empty">No channels yet.</div>'}catch(e){toast("Community load failed: "+e.message)}};
  const cg=document.getElementById("createGroup");if(cg)cg.onclick=async()=>{try{await api("/api/groups/create",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:document.getElementById("groupTitle").value.trim(),members:document.getElementById("groupMembers").value.split(",").map(x=>x.trim()).filter(Boolean)})});await load()}catch(e){toast(e.message)}};
  const cc=document.getElementById("createChannel");if(cc)cc.onclick=async()=>{try{await api("/api/channels/create",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:document.getElementById("channelTitle").value.trim()})});await load()}catch(e){toast(e.message)}};
  const sg=document.getElementById("sendGroupMessage");if(sg)sg.onclick=async()=>{try{await api("/api/groups/send",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({group_id:document.getElementById("groupMessageId").value.trim(),text:document.getElementById("groupMessageText").value.trim()})});await load()}catch(e){toast(e.message)}};
  const scb=document.getElementById("subscribeChannel");if(scb)scb.onclick=async()=>{try{await api("/api/channels/subscribe",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({channel_id:document.getElementById("channelId").value.trim()})});await load()}catch(e){toast(e.message)}};
  const pcb=document.getElementById("publishChannel");if(pcb)pcb.onclick=async()=>{try{await api("/api/channels/publish",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({channel_id:document.getElementById("channelId").value.trim(),text:document.getElementById("channelMessageText").value.trim()})});await load()}catch(e){toast(e.message)}};
  load();
 }

 const sc=document.getElementById("storeCatalog");if(sc)loadStore();
 const sm=document.getElementById("sendMsg");if(sm)sm.onclick=async()=>{const recipient=document.getElementById("msgRecipient").value.trim(),message=document.getElementById("msgText").value.trim(),state=document.getElementById("msgState");if(!recipient||!message)return toast("Recipient and message are required");sm.disabled=true;try{const r=await api("/api/messenger/send",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({recipient,text:message})});state.textContent="Queued: "+r.message.id;document.getElementById("msgText").value="";await loadMessenger()}catch(e){state.textContent="Send failed: "+e.message}finally{sm.disabled=false}};
}
async function loadStore(){
 const box=document.getElementById("storeCatalog");if(!box)return;
 try{
  const data=await api("/api/store/catalog");
  const installed=new Map((data.installed||[]).map(x=>[x.id,x.version]));
  const apps=data.apps||[];
  if(!apps.length){box.innerHTML='<div class="empty">No verified packages are cached on this node yet.</div>';return}
  box.innerHTML=apps.map(item=>{
   const m=item.manifest||{}, perms=(m.permissions||[]).map(esc), current=installed.get(m.id);
   const installedText=current?'<span class="status"><i></i>Installed '+esc(current)+'</span>':'<button class="primary store-install" data-hash="'+esc(item.package_hash)+'">Install</button>';
   return '<div class="card store-card"><div class="store-icon">◈</div><b>'+esc(m.name||m.id)+'</b><p>'+esc(m.id)+' · v'+esc(m.version)+' · '+esc(m.kind)+' · '+esc(m.size)+' bytes</p><div class="muted">Permissions: '+(perms.length?perms.join(", "):"none")+'</div><div style="margin-top:12px">'+installedText+'</div></div>';
  }).join("");
  box.querySelectorAll(".store-install").forEach(btn=>btn.onclick=async()=>{
   const item=apps.find(x=>x.package_hash===btn.dataset.hash);if(!item)return;
   const perms=item.manifest?.permissions||[];
   if(perms.length&&!confirm("This package requests: "+perms.join(", ")+"\n\nGrant these capabilities and install it?"))return;
   btn.disabled=true;
   try{const r=await api("/api/store/install",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({package_hash:btn.dataset.hash,granted_permissions:perms})});if(r.status!=="installed")throw new Error(r.error||"installation failed");toast("Installed "+r.app.id);await loadStore()}catch(e){toast("Install failed: "+e.message)}finally{btn.disabled=false}
  });
 }catch(e){box.innerHTML='<div class="empty">AWEStore unavailable: '+esc(e.message)+'</div>'}
}
function toast(t){const e=document.createElement("div");e.textContent=t;e.style="position:fixed;right:22px;bottom:22px;background:#111829;color:#fff;padding:11px 15px;border-radius:9px;font-size:11px;z-index:10";document.body.appendChild(e);setTimeout(()=>e.remove(),2200)}
navs.forEach(n=>n.addEventListener("click",e=>{e.preventDefault();render(n.dataset.view)}));
(async()=>{render("dashboard");await refresh();render("dashboard");setInterval(async()=>{await refresh();if(title.textContent===pages.dashboard[0])render("dashboard")},5000);setInterval(pollCallSignals,1000)})();