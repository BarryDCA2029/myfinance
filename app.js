const DB_KEY='myfinance_v1';
const VAULT_KEY='myfinance_secure_v122';
const APP_VERSION='1.4';
const expenseCats=['อาหาร','เดินทาง','ครอบครัว','สุขภาพ','การศึกษา','ท่องเที่ยว','ภาษี','ของใช้ส่วนตัว','ค่าสาธารณูปโภค','ค่าซ่อม/บำรุง','ค่าแรง','วัสดุ/อุปกรณ์','ปุ๋ย/ต้นไม้','อาหารสัตว์','อื่น ๆ'];
const projects=['ส่วนตัว/ทั่วไป','บ้าน กทม.','บ้าน เกษตรวิสัย','เลี้ยงไก่','ป่ายาง','Polar Farm'];
const incomeCats=['เงินเดือน','รายได้พิเศษ','ปันผล','ดอกเบี้ย','ค่าเช่า','ขายทรัพย์สิน','อื่น ๆ'];
const defaultData={
  version:APP_VERSION,
  pin:null,
  autoLock:true,
  autoLockMinutes:1,
  lastActive:Date.now(),
  transactions:[],
  assets:[],
  goals:[{id:'g1',name:'เงินสำรองฉุกเฉิน',target:300000,current:0}],
  budgets:{},
  projectBudgets:{},
  snapshots:[],
  reconciliations:[],
  auditLog:[],
  settings:{currency:'THB',hideZeroDebt:true}
};

let data=load();
let currentPin=null;
let hasSecureVault=!!localStorage.getItem(VAULT_KEY);
let legacyPin=data.pin||null;
let page='dashboard';
let txFilter='all';
let assetFilter='all';
let txDraftType='expense';
let unlocked=!hasSecureVault&&!legacyPin;
let modal=null;
let editId=null;

const THB=n=>new Intl.NumberFormat('th-TH',{style:'currency',currency:'THB',minimumFractionDigits:0,maximumFractionDigits:2}).format(Number(n||0));
const num=n=>new Intl.NumberFormat('th-TH',{minimumFractionDigits:0,maximumFractionDigits:2}).format(Number(n||0));
function parseMoney(v){
  let s=String(v??'').trim().replace(/\s/g,'');
  if(!s)return 0;
  // รองรับทั้ง 1046.93 และ 1046,93 รวมถึง comma คั่นหลักพัน
  if(s.includes('.') && s.includes(',')) s=s.replace(/,/g,'');
  else if(s.includes(',') && !s.includes('.')){
    const parts=s.split(',');
    if(parts.length===2 && parts[1].length<=2) s=parts[0]+'.'+parts[1];
    else s=s.replace(/,/g,'');
  }
  s=s.replace(/[^0-9.-]/g,'');
  const n=Number(s);
  return Number.isFinite(n)?Math.round((n+Number.EPSILON)*100)/100:NaN;
}
const $=(s)=>document.querySelector(s);
const $$=(s)=>[...document.querySelectorAll(s)];

function clone(obj){return JSON.parse(JSON.stringify(obj))}
function migrate(raw){
  const merged={...clone(defaultData),...raw};
  merged.transactions=Array.isArray(raw.transactions)?raw.transactions:[];
  merged.assets=(Array.isArray(raw.assets)?raw.assets:[]).map(a=>({...a,cost:Number(a.cost??a.value??0),units:Number(a.units||0),price:Number(a.price||0),liquid:a.liquid!==false,liquidity:a.liquidity||((a.kind==='cash')?'ready':(a.kind==='stock'||a.kind==='gold')?'limited':'low')}));
  merged.goals=Array.isArray(raw.goals)&&raw.goals.length?raw.goals:clone(defaultData.goals);
  merged.budgets=raw.budgets&&typeof raw.budgets==='object'?raw.budgets:{};
  merged.projectBudgets=raw.projectBudgets&&typeof raw.projectBudgets==='object'?raw.projectBudgets:{};
  merged.snapshots=Array.isArray(raw.snapshots)?raw.snapshots:[];
  merged.reconciliations=Array.isArray(raw.reconciliations)?raw.reconciliations:[];
  merged.auditLog=Array.isArray(raw.auditLog)?raw.auditLog:[];
  merged.settings={...defaultData.settings,...(raw.settings||{})};
  merged.version=APP_VERSION;
  return merged;
}
function load(){
  try{return migrate(JSON.parse(localStorage.getItem(DB_KEY)||'{}'))}
  catch{return clone(defaultData)}
}
const te=new TextEncoder(), td=new TextDecoder();
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function deriveKey(secret,salt,usage=['encrypt','decrypt']){
  const base=await crypto.subtle.importKey('raw',te.encode(secret),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:210000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,usage);
}
async function encryptObject(obj,secret){
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveKey(secret,salt);
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,te.encode(JSON.stringify(obj)));
  return {format:'MYFINANCE-ENC-1',kdf:'PBKDF2-SHA256',iterations:210000,cipher:'AES-256-GCM',salt:b64(salt),iv:b64(iv),ciphertext:b64(ct)};
}
async function decryptObject(box,secret){
  const salt=unb64(box.salt),iv=unb64(box.iv),ct=unb64(box.ciphertext);
  const key=await deriveKey(secret,salt);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct);
  return JSON.parse(td.decode(pt));
}
let saveSeq=Promise.resolve();
function save(){
  data.version=APP_VERSION; data.lastActive=Date.now();
  if(currentPin){
    const snap=clone(data); delete snap.pin;
    saveSeq=saveSeq.then(async()=>{const box=await encryptObject(snap,currentPin);localStorage.setItem(VAULT_KEY,JSON.stringify(box));localStorage.removeItem(DB_KEY);hasSecureVault=true}).catch(()=>{});
  }else if(!hasSecureVault){ localStorage.setItem(DB_KEY,JSON.stringify(data)); }
}
async function unlockSecure(pin){
  const box=JSON.parse(localStorage.getItem(VAULT_KEY));
  data=migrate(await decryptObject(box,pin)); data.pin=null; currentPin=pin; unlocked=true; return true;
}
async function secureLegacy(pin){
  if(pin!==legacyPin)throw new Error('bad pin');
  currentPin=pin; data.pin=null; legacyPin=null; unlocked=true; save(); await saveSeq; localStorage.removeItem(DB_KEY);
}
function uid(){return Math.random().toString(36).slice(2)+Date.now().toString(36)}
function today(){return new Date().toISOString().slice(0,10)}
function monthKey(d=new Date()){return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`}
function inCurrentMonth(t){return (t.date||'').slice(0,7)===monthKey()}
function esc(s=''){return String(s).replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function typeLabel(t){return ({income:'รายรับ',expense:'รายจ่าย',reimbursement:'คืนค่าใช้จ่าย',transfer:'โอนเงิน',investment:'ลงทุน'})[t]||t}
function cashAssets(){return data.assets.filter(a=>a.kind==='cash')}
function findAsset(id){return data.assets.find(a=>a.id===id)}
function reverseTxAssetEffect(tx){
  const amt=Number(tx?.amount||0);
  const src=findAsset(tx?.sourceAssetId), dst=findAsset(tx?.destinationAssetId);
  if(tx?.type==='expense'&&src)src.value=round2(Number(src.value||0)+amt);
  else if(tx?.type==='income'&&src)src.value=round2(Number(src.value||0)-amt);
  else if(tx?.type==='reimbursement'&&src)src.value=round2(Number(src.value||0)-amt);
  else if(tx?.type==='transfer'){if(src)src.value=round2(Number(src.value||0)+amt);if(dst)dst.value=round2(Number(dst.value||0)-amt)}
}
function applyTxAssetEffect(tx){
  const amt=Number(tx?.amount||0);
  const src=findAsset(tx?.sourceAssetId), dst=findAsset(tx?.destinationAssetId);
  if(tx?.type==='expense'&&src)src.value=round2(Number(src.value||0)-amt);
  else if(tx?.type==='income'&&src)src.value=round2(Number(src.value||0)+amt);
  else if(tx?.type==='reimbursement'&&src)src.value=round2(Number(src.value||0)+amt);
  else if(tx?.type==='transfer'){if(src)src.value=round2(Number(src.value||0)-amt);if(dst)dst.value=round2(Number(dst.value||0)+amt)}
}
function round2(n){return Math.round((Number(n||0)+Number.EPSILON)*100)/100}
function iconFor(cat){const m={'อาหาร':'🍜','เดินทาง':'🚗','ครอบครัว':'👨‍👩‍👧','สุขภาพ':'🩺','การศึกษา':'📚','ท่องเที่ยว':'✈️','ภาษี':'🧾','ของใช้ส่วนตัว':'🧴','ค่าสาธารณูปโภค':'💡','ค่าซ่อม/บำรุง':'🛠️','ค่าแรง':'👷','วัสดุ/อุปกรณ์':'🧰','ปุ๋ย/ต้นไม้':'🌱','อาหารสัตว์':'🌾','เงินเดือน':'💼','ปันผล':'💹','ดอกเบี้ย':'🏦','รายได้พิเศษ':'✨','ค่าเช่า':'🏠','ขายทรัพย์สิน':'🏷️','ลงทุน':'📈','โอนเงิน':'🔄','อื่น ๆ':'•'};return m[cat]||'•'}
function audit(action,detail=''){data.auditLog=Array.isArray(data.auditLog)?data.auditLog:[];data.auditLog.push({id:uid(),at:new Date().toISOString(),action,detail});data.auditLog=data.auditLog.slice(-500)}
function liquidityLabel(v){return ({ready:'พร้อมใช้',limited:'มีข้อจำกัด',low:'สภาพคล่องต่ำ'})[v]||'พร้อมใช้'}
function assetKindLabel(k){return ({cash:'เงินสด/ธนาคาร',stock:'หุ้น/กองทุน',gold:'ทอง',property:'ที่ดิน/อสังหาฯ',vehicle:'รถ/ยานพาหนะ',other:'ทรัพย์สินอื่น',debt:'หนี้สิน'})[k]||k}

function totals(){
  const m=data.transactions.filter(inCurrentMonth);
  const income=m.filter(x=>x.type==='income').reduce((s,x)=>s+Number(x.amount||0),0);
  const grossExpense=m.filter(x=>x.type==='expense').reduce((s,x)=>s+Number(x.amount||0),0);
  const reimbursements=m.filter(x=>x.type==='reimbursement').reduce((s,x)=>s+Number(x.amount||0),0);
  const expense=round2(grossExpense-reimbursements);
  const assetsOnly=data.assets.filter(x=>x.kind!=='debt');
  const debts=data.assets.filter(x=>x.kind==='debt');
  const assetTotal=assetsOnly.reduce((s,x)=>s+Number(x.value||0),0);
  const debtTotal=debts.reduce((s,x)=>s+Number(x.value||0),0);
  const liquidMoney=assetsOnly.filter(x=>x.kind==='cash'&&(x.liquidity||'ready')==='ready').reduce((s,x)=>s+Number(x.value||0),0);
  return {income,expense,cashflow:income-expense,assetTotal,debtTotal,netWorth:assetTotal-debtTotal,liquidMoney};
}
function monthlyExpenseByCategory(){
  const sums={};
  data.transactions.filter(x=>inCurrentMonth(x)&&(x.type==='expense'||x.type==='reimbursement')).forEach(x=>{const sign=x.type==='reimbursement'?-1:1;sums[x.category]=round2((sums[x.category]||0)+sign*Number(x.amount||0));});
  return sums;
}
function currentBudgetMap(){return data.budgets[monthKey()]||{}}
function currentProjectBudgetMap(){return data.projectBudgets[monthKey()]||{}}
function projectStats(name){const tx=data.transactions.filter(x=>inCurrentMonth(x)&&(x.project||'ส่วนตัว/ทั่วไป')===name);const income=tx.filter(x=>x.type==='income').reduce((s,x)=>s+Number(x.amount||0),0);const grossExpense=tx.filter(x=>x.type==='expense').reduce((s,x)=>s+Number(x.amount||0),0);const reimbursements=tx.filter(x=>x.type==='reimbursement').reduce((s,x)=>s+Number(x.amount||0),0);const expense=round2(grossExpense-reimbursements);return {income,expense,net:income-expense}}
function snapshotCurrentMonth(){
  const t=totals(); const key=monthKey();
  const row={month:key,netWorth:t.netWorth,assetTotal:t.assetTotal,debtTotal:t.debtTotal,updatedAt:new Date().toISOString()};
  const i=data.snapshots.findIndex(s=>s.month===key);
  if(i>=0)data.snapshots[i]=row; else data.snapshots.push(row);
  data.snapshots=data.snapshots.sort((a,b)=>a.month.localeCompare(b.month)).slice(-60);
}

function render(){document.getElementById('app').innerHTML=!unlocked?lockView():appView();bind()}
function lockView(){
  const first=!(hasSecureVault||legacyPin||currentPin);
  return `<div class="lock"><div class="lock-card"><div class="lock-logo">฿</div><h1>MY FINANCE</h1><p>Private Financial Planner<br>ข้อมูลอยู่ในเครื่องนี้ผ่านพื้นที่จัดเก็บของ Safari/PWA</p>${first?`<div class="notice">ยังไม่ได้ตั้ง PIN หากต้องการล็อกแอป ให้เข้า ⚙️ Settings หลังเปิดแอป แล้วเลือก “ตั้ง PIN”</div><button class="primary" id="enterWithoutPin">เข้าแอป</button>`:`<div class="field"><label>PIN</label><input id="unlockPin" class="pin" inputmode="numeric" maxlength="6" type="password" autofocus></div><button class="primary" id="unlockBtn">ปลดล็อก</button>`}<div class="notice">Local-only: ไม่มีระบบ Sync/iCloud ในแอปนี้ ควร Export Backup เป็นระยะ</div></div></div>`
}
function appView(){return `<main class="shell">${page==='dashboard'?dashboard():page==='transactions'?transactions():page==='assets'?assets():page==='plan'?plan():settings()}</main>${bottomNav()}${modal?sheet():''}`}
function header(title='MY FINANCE',sub='Personal Financial Planner'){
  return `<div class="header"><div class="brand"><h1>${title}</h1><p>${sub}</p></div><div class="head-actions"><button class="month-btn">${new Date().toLocaleDateString('en-US',{month:'short',year:'numeric'})}</button><button class="icon-btn" id="openSettings" aria-label="Settings">⚙️</button></div></div>`
}
function dashboard(){
  const t=totals();
  const prevKey=(()=>{const d=new Date();d.setMonth(d.getMonth()-1);return monthKey(d)})();
  const prev=data.snapshots.find(s=>s.month===prevKey);
  const pct=prev&&Number(prev.netWorth)!==0?((t.netWorth-Number(prev.netWorth))/Math.abs(Number(prev.netWorth))*100):null;
  return `${header()}<section class="hero"><div class="label">◆ NET WORTH</div><div class="value">${THB(t.netWorth)}</div><div class="delta">${t.netWorth>0?'●':'○'} Current snapshot ${pct!==null?`· ${pct>=0?'+':''}${pct.toFixed(1)}% vs เดือนก่อน`:''}</div></section><div class="grid4"><div class="mini liquid"><div class="t">◉ เงินพร้อมใช้</div><div class="v">${THB(t.liquidMoney)}</div></div><div class="mini income"><div class="t">↑ รายรับ</div><div class="v">${THB(t.income)}</div></div><div class="mini expense"><div class="t">↓ รายจ่าย</div><div class="v">${THB(t.expense)}</div></div><div class="mini cashflow"><div class="t">↕ Cash Flow</div><div class="v">${THB(t.cashflow)}</div></div></div>${financialPulse()}${cashChart()}${spendingCard()}${budgetSummary()}${projectDashboard()}${healthCard()}${goalsSummary()}${recentTx()}`
}

function financialPulse(){
  const t=totals(), budgets=currentBudgetMap();
  const budgetTotal=Object.values(budgets).reduce((s,v)=>s+Number(v||0),0);
  const status=t.cashflow>=0?'เดือนนี้ยังเป็นบวก':'เดือนนี้ใช้มากกว่ารายรับ';
  const budgetNote=budgetTotal>t.income&&t.income>0?` · ถ้าใช้เต็มงบจะเกินรายรับ ${THB(budgetTotal-t.income)}`:'';
  return `<section class="section"><div class="section-title"><h2>Financial Pulse</h2><span>ภาพรวมทันที</span></div><div class="card pulse"><b>${t.cashflow>=0?'✓':'!'} ${status}</b><p>รับ ${THB(t.income)} · จ่ายสุทธิ ${THB(t.expense)} · เหลือสุทธิ <strong class="${t.cashflow>=0?'pos':'neg'}">${t.cashflow>=0?'+':''}${THB(t.cashflow)}</strong>${budgetNote}</p></div></section>`
}
function cashChart(){
  const vals=[];
  for(let i=5;i>=0;i--){const d=new Date();d.setMonth(d.getMonth()-i);const k=monthKey(d);const inc=data.transactions.filter(x=>x.type==='income'&&x.date?.startsWith(k)).reduce((s,x)=>s+Number(x.amount||0),0);const exp=data.transactions.filter(x=>x.type==='expense'&&x.date?.startsWith(k)).reduce((s,x)=>s+Number(x.amount||0),0);vals.push(inc-exp)}
  const max=Math.max(...vals.map(v=>Math.abs(v)),1);
  const pts=vals.map((v,i)=>`${8+i*58},${72-(v/max)*48}`).join(' ');
  return `<section class="section"><div class="section-title"><h2>Monthly Cash Flow</h2><span>6 เดือน</span></div><div class="card chart-wrap"><svg viewBox="0 0 310 130"><defs><linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6F87A6" stop-opacity=".24"/><stop offset="1" stop-color="#6F87A6" stop-opacity="0"/></linearGradient></defs><g class="chart-grid"><line x1="8" y1="24" x2="298" y2="24"/><line x1="8" y1="72" x2="298" y2="72"/><line x1="8" y1="120" x2="298" y2="120"/></g><polygon class="chart-area" points="${pts} 298,120 8,120"/><polyline class="chart-line" points="${pts}"/></svg></div></section>`
}
function spendingCard(){
  const sums=monthlyExpenseByCategory();
  const entries=Object.entries(sums).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const total=entries.reduce((s,x)=>s+x[1],0)||1;
  const colors=['#6F8F7B','#C98383','#6F87A6','#C8A867','#88769A']; let acc=0;
  const stops=entries.length?entries.map(([k,v],i)=>{const a=acc;acc+=v/total*100;return `${colors[i]} ${a}% ${acc}%`}).join(','):'#E7E0D4 0 100%';
  return `<section class="section"><div class="section-title"><h2>Where My Money Goes</h2><span>เดือนนี้</span></div><div class="card donut-row"><div class="donut" style="background:conic-gradient(${stops})"></div><div class="legend">${entries.length?entries.map(([k,v],i)=>`<div class="legend-item"><span><i class="dot" style="background:${colors[i]}"></i>${esc(k)}</span><b>${Math.round(v/total*100)}% · ${THB(v)}</b></div>`).join(''):'<div class="empty compact">ยังไม่มีรายจ่าย</div>'}</div></div></section>`
}
function projectDashboard(){
  const active=projects.map(name=>({name,...projectStats(name)})).filter(x=>x.income||x.expense);
  if(!active.length)return `<section class="section"><div class="section-title"><h2>Projects & Properties</h2><span>เดือนนี้</span></div><div class="card budget-empty"><b>ยังไม่มีรายการแยกโครงการ</b><p>เวลาบันทึกรายรับ/รายจ่าย เลือก บ้าน กทม., บ้าน เกษตรวิสัย, เลี้ยงไก่, ป่ายาง หรือ Polar Farm ได้</p></div></section>`;
  return `<section class="section"><div class="section-title"><h2>Projects & Properties</h2><span>เดือนนี้</span></div><div class="card tx-list">${active.map(x=>`<div class="tx"><div class="tx-ico">${projectIcon(x.name)}</div><div class="tx-main"><b>${esc(x.name)}</b><small>รับ ${THB(x.income)} · จ่าย ${THB(x.expense)}</small></div><div class="amt ${x.net>=0?'pos':'neg'}">${x.net>=0?'+':''}${THB(x.net)}</div></div>`).join('')}</div></section>`
}
function projectIcon(n){return ({'บ้าน กทม.':'🏙️','บ้าน เกษตรวิสัย':'🏡','เลี้ยงไก่':'🐓','ป่ายาง':'🌳','Polar Farm':'🌾','ส่วนตัว/ทั่วไป':'👤'})[n]||'◆'}
function budgetSummary(){
  const budgets=currentBudgetMap(); const sums=monthlyExpenseByCategory();
  const cats=Object.keys(budgets).filter(k=>Number(budgets[k])>0);
  if(!cats.length)return `<section class="section"><div class="section-title"><h2>Budget vs Actual</h2><span>เดือนนี้</span></div><div class="card budget-empty"><b>ยังไม่ได้ตั้งงบ</b><p>ตั้งงบรายหมวดในหน้า Plan เพื่อเทียบงบกับรายจ่ายจริง</p><button class="secondary goPlan">ตั้งงบ</button></div></section>`;
  const budgetTotal=cats.reduce((s,k)=>s+Number(budgets[k]||0),0); const actual=cats.reduce((s,k)=>s+Number(sums[k]||0),0); const p=budgetTotal?Math.round(actual/budgetTotal*100):0;
  const gap=budgetTotal-totals().income; const warning=totals().income>0&&gap>0?`<div class="budget-warning">⚠ ถ้าใช้เต็มงบ จะสูงกว่ารายรับเดือนนี้ ${THB(gap)} — ยังไม่ใช่เงินที่ใช้จริง</div>`:''; return `<section class="section"><div class="section-title"><h2>◎ แผนใช้จ่ายเดือนนี้</h2><span>${p}% ของงบ</span></div><div class="card"><div class="budget-kpis"><div><small>งบที่ตั้ง</small><b>${THB(budgetTotal)}</b></div><div><small>ใช้จริง</small><b>${THB(actual)}</b></div><div><small>งบเหลือ</small><b>${THB(budgetTotal-actual)}</b></div></div><div class="bar budget ${p>100?'over':p>=80?'warn':''}"><i style="width:${Math.min(100,p)}%"></i></div>${warning}<small class="budget-note">งบคือเพดานการใช้ ไม่หักเงินเก็บจนกว่าจะมีรายจ่ายจริง</small></div></section>`
}
function healthCard(){
  const t=totals(); const txMonths=new Set(data.transactions.filter(x=>x.date).map(x=>x.date.slice(0,7))).size;
  const enough=t.income>0 && data.transactions.filter(x=>x.type==='expense').length>=3;
  const g=data.goals.find(x=>x.name.includes('ฉุกเฉิน'))||data.goals[0]||{target:1,current:0};
  const gp=Math.min(100,Math.round(Number(g.current||0)/(Number(g.target)||1)*100));
  if(!enough){
    return `<section class="section"><div class="section-title"><h2>Financial Health</h2><span>สูตรโปร่งใส</span></div><div class="card health"><div class="score neutral"><strong>—</strong></div><div class="health-copy"><h3>ข้อมูลยังไม่เพียงพอ</h3><p>ต้องมีรายรับอย่างน้อย 1 รายการ และรายจ่ายอย่างน้อย 3 รายการก่อน ระบบจึงจะให้คะแนน</p><div class="bar"><i style="width:${gp}%"></i></div><p style="margin-top:6px">${esc(g.name)} ${gp}%</p></div></div></section>`;
  }
  const savingRate=t.income>0?t.cashflow/t.income:0;
  const expenseRatio=t.income>0?t.expense/t.income:1;
  let score=0;
  score+=Math.max(0,Math.min(40,Math.round(savingRate*100)));
  score+=expenseRatio<=0.5?25:expenseRatio<=0.7?18:expenseRatio<=0.9?8:0;
  score+=t.debtTotal===0?20:Math.max(0,20-Math.round((t.debtTotal/Math.max(t.assetTotal,1))*100));
  score+=Math.round(gp*0.15);
  score=Math.max(0,Math.min(100,score));
  return `<section class="section"><div class="section-title"><h2>Financial Health</h2><span>คำนวณจากข้อมูลจริง</span></div><div class="card health"><div class="score" style="--score:${score}"><strong>${score}</strong></div><div class="health-copy"><h3>${score>=80?'Very Good':score>=60?'Good':'Needs Attention'} ${t.debtTotal===0?'· Debt Free ✓':''}</h3><p>Saving Rate ${Math.round(savingRate*100)}% · Expense Ratio ${Math.round(expenseRatio*100)}%${txMonths>1?` · มีข้อมูล ${txMonths} เดือน`:''}</p><div class="bar"><i style="width:${gp}%"></i></div><p style="margin-top:6px">${esc(g.name)} ${gp}%</p></div></div></section>`
}
function goalsSummary(){
  const list=data.goals.slice(0,3);
  return `<section class="section"><div class="section-title"><h2>Financial Goals</h2><span class="goPlan">ดูทั้งหมด</span></div><div class="card goal-list">${list.map(g=>{const p=Math.min(100,Math.round(Number(g.current||0)/(Number(g.target)||1)*100));return `<div class="goal-mini"><div><b>${esc(g.name)}</b><small>${THB(g.current)} / ${THB(g.target)}</small></div><strong>${p}%</strong></div>`}).join('')}</div></section>`
}
function recentTx(){const tx=[...data.transactions].sort((a,b)=>(b.date||'').localeCompare(a.date||'')).slice(0,5);return `<section class="section"><div class="section-title"><h2>Recent Transactions</h2><span id="seeAll">ดูทั้งหมด</span></div><div class="card tx-list">${tx.length?tx.map(txRow).join(''):'<div class="empty">เริ่มบันทึกรายการแรกด้วยปุ่ม +</div>'}</div></section>`}
function txRow(x){const sign=x.type==='income'?'+':x.type==='expense'?'-':x.type==='reimbursement'?'+':'';const cls=(x.type==='income'||x.type==='reimbursement')?'pos':x.type==='expense'?'neg':'';return `<button class="tx tx-button" data-id="${x.id}" aria-label="เปิดรายการ"><div class="tx-ico">${iconFor(x.category)}</div><div class="tx-main"><b>${esc(x.category||typeLabel(x.type))}</b><small>${x.type==='transfer'?`${esc(x.account||'ไม่ระบุต้นทาง')} → ${esc(x.destinationAccount||findAsset(x.destinationAssetId)?.name||'ไม่ระบุปลายทาง')}`:esc(x.account||'ไม่ระบุบัญชี')} · ${esc(x.project||'ส่วนตัว/ทั่วไป')} · ${esc(x.date||'')}</small></div><div class="amt ${cls}">${sign}${THB(x.amount)}</div></button>`}
function transactions(){let tx=[...data.transactions].sort((a,b)=>(b.date||'').localeCompare(a.date||''));if(txFilter!=='all')tx=tx.filter(x=>x.type===txFilter);return `${header('Transactions','รายรับ รายจ่าย โอน และลงทุน')}<div class="title-row"><h2 class="page-title">รายการทั้งหมด</h2><small>แตะรายการเพื่อแก้ไข/ลบ</small></div><div class="filters"><button class="chip ${txFilter==='all'?'active':''}" data-filter="all">ทั้งหมด</button><button class="chip ${txFilter==='income'?'active':''}" data-filter="income">รายรับ</button><button class="chip ${txFilter==='expense'?'active':''}" data-filter="expense">รายจ่าย</button><button class="chip ${txFilter==='reimbursement'?'active':''}" data-filter="reimbursement">คืนค่าใช้จ่าย</button><button class="chip ${txFilter==='transfer'?'active':''}" data-filter="transfer">โอน</button><button class="chip ${txFilter==='investment'?'active':''}" data-filter="investment">ลงทุน</button></div><div class="card tx-list">${tx.length?tx.map(txRow).join(''):'<div class="empty">ยังไม่มีรายการในหมวดนี้</div>'}</div>`}
function investmentSummary(){
  const list=data.assets.filter(a=>a.kind==='stock');
  const cost=list.reduce((s,a)=>s+Number(a.cost??a.value??0),0);
  const value=list.reduce((s,a)=>s+Number(a.value||0),0);
  return {cost,value,pl:value-cost,pct:cost?((value-cost)/cost*100):0};
}
function assets(){
  const t=totals(); const kinds=[['cash','เงินสด/ธนาคาร','💵'],['stock','หุ้น/กองทุน','📈'],['gold','ทอง','🌑'],['property','ที่ดิน/อสังหาฯ','🏡'],['vehicle','รถ/ยานพาหนะ','🚙'],['other','ทรัพย์สินอื่น','◆']];
  const filtered=assetFilter==='all'?data.assets:data.assets.filter(a=>a.kind===assetFilter);
  const title=assetFilter==='all'?'รายการทรัพย์สิน':assetKindLabel(assetFilter);
  const inv=investmentSummary();
  const investBox=assetFilter==='stock'?`<section class="section"><div class="card invest-summary"><small>Investment Portfolio</small><div class="invest-grid"><div><span>ต้นทุนรวม</span><b>${THB(inv.cost)}</b></div><div><span>มูลค่าปัจจุบัน</span><b>${THB(inv.value)}</b></div><div><span>Unrealized P/L</span><b class="${inv.pl>=0?'pos':'neg'}">${inv.pl>=0?'+':''}${THB(inv.pl)} (${inv.pct>=0?'+':''}${inv.pct.toFixed(2)}%)</b></div></div></div></section>`:'';
  return `${header('Assets','ทรัพย์สินและฐานะสุทธิ')}<div class="title-row"><h2 class="page-title">My Wealth</h2><small>Net Worth ${THB(t.netWorth)}</small></div><div class="asset-grid">${kinds.map(([k,n,ic])=>{const list=data.assets.filter(a=>a.kind===k);const v=list.reduce((s,a)=>s+Number(a.value||0),0);return `<button class="asset-card asset-card-btn ${assetFilter===k?'selected':''}" data-asset-kind="${k}"><div class="a-label">${ic} ${n}</div><div class="a-value">${THB(v)}</div><div class="a-sub">${list.length} รายการ · แตะเพื่อดู</div></button>`}).join('')}</div>${assetFilter!=='all'?`<button class="secondary asset-back" id="assetBack">← ดูทรัพย์สินทั้งหมด</button>`:''}${investBox}${t.debtTotal>0?`<section class="section"><div class="card debt-card"><small>หนี้สินรวม</small><b>${THB(t.debtTotal)}</b></div></section>`:''}<section class="section"><div class="section-title"><h2>${esc(title)}</h2><span id="addAsset">+ เพิ่ม</span></div><div class="card tx-list">${filtered.length?filtered.map(a=>{const pl=a.kind==='stock'?Number(a.value||0)-Number(a.cost??a.value??0):0;return `<button class="tx tx-button asset-row" data-asset-id="${a.id}"><div class="tx-ico">${a.kind==='debt'?'−':'◆'}</div><div class="tx-main"><b>${esc(a.name)}</b><small>${esc(assetKindLabel(a.kind))}${a.kind==='stock'?` · P/L <span class="${pl>=0?'pos':'neg'}">${pl>=0?'+':''}${THB(pl)}</span>`:''}</small></div><div class="amt ${a.kind==='debt'?'neg':''}">${THB(a.value)}</div></button>`}).join(''):'<div class="empty">ยังไม่มีรายการในหมวดนี้</div>'}</div></section>`
}
function plan(){
  const budgets=currentBudgetMap(); const sums=monthlyExpenseByCategory();
  const budgetRows=expenseCats.map(cat=>{const b=Number(budgets[cat]||0);const a=Number(sums[cat]||0);const p=b?Math.round(a/b*100):(a>0?999:0);return `<div class="budget-row"><div class="budget-head"><div><b>${esc(cat)}</b><small>ใช้จริง ${THB(a)}</small></div><button class="budget-edit" data-budget-cat="${esc(cat)}">${b?THB(b):'ตั้งงบ'}</button></div>${b?`<div class="bar budget ${p>100?'over':p>=80?'warn':''}"><i style="width:${Math.min(100,p)}%"></i></div><small class="budget-note">${p>100?`เกินงบ ${THB(a-b)}`:`เหลือ ${THB(b-a)} · ${p}%`}</small>`:''}</div>`}).join('');
  return `${header('Plan','Budget & Goals')}<div class="title-row"><h2 class="page-title">Financial Goals</h2><button class="mini-add" id="addGoal">+ เพิ่ม</button></div><div class="goal-cards">${data.goals.length?data.goals.map(g=>{const p=Math.min(100,Math.round(Number(g.current||0)/(Number(g.target)||1)*100));return `<button class="card goal-card" data-goal-id="${g.id}"><div><div class="label goal-label">${esc(g.name)}</div><div class="goal-value">${THB(g.current)}</div><small>เป้าหมาย ${THB(g.target)} · ${p}%</small><div class="bar"><i style="width:${p}%"></i></div></div><span>›</span></button>`}).join(''):'<div class="card empty">ยังไม่มีเป้าหมาย</div>'}</div>${projectPlan()}<section class="section"><div class="section-title"><h2>Budget vs Actual</h2><span>${new Date().toLocaleDateString('th-TH',{month:'long'})}</span></div><div class="card budget-list">${budgetRows}</div></section>`
}
function projectPlan(){
  const pb=currentProjectBudgetMap();
  const rows=projects.filter(x=>x!=='ส่วนตัว/ทั่วไป').map(name=>{const st=projectStats(name),b=Number(pb[name]||0),p=b?Math.round(st.expense/b*100):0;return `<div class="budget-row"><div class="budget-head"><div><b>${projectIcon(name)} ${esc(name)}</b><small>รับ ${THB(st.income)} · ใช้ ${THB(st.expense)} · สุทธิ ${THB(st.net)}</small></div><button class="budget-edit" data-project-budget="${esc(name)}">${b?THB(b):'ตั้งงบ'}</button></div>${b?`<div class="bar budget ${p>100?'over':p>=80?'warn':''}"><i style="width:${Math.min(100,p)}%"></i></div><small class="budget-note">${p>100?`เกินงบ ${THB(st.expense-b)}`:`เหลือ ${THB(b-st.expense)} · ${p}%`}</small>`:''}</div>`}).join('');
  return `<section class="section"><div class="section-title"><h2>Projects & Properties</h2><span>งบแยกพื้นที่/กิจการ</span></div><div class="card budget-list">${rows}</div></section>`
}
function settings(){
  const hasPin=!!(hasSecureVault||legacyPin||currentPin);
  return `${header('Settings','Privacy, Backup & App Lock')}<h2 class="page-title">ความเป็นส่วนตัวและข้อมูล</h2><div class="settings-list"><div class="setting"><div><b>App Lock</b><small>${hasPin?'เข้ารหัสข้อมูลแล้ว':'ยังไม่ได้ตั้ง PIN / Encryption'}</small></div><button id="${hasPin?'changePin':'setPin'}">${hasPin?'Change':'Set PIN'}</button></div><div class="setting"><div><b>Auto Lock</b><small>${hasPin?'ล็อกเมื่อออกจากแอปเกินเวลาที่กำหนด':'เปิดใช้ได้หลังตั้ง PIN'}</small></div><input class="toggle" id="autoLock" type="checkbox" ${data.autoLock?'checked':''} ${hasPin?'':'disabled'}></div><div class="setting"><div><b>เวลาล็อกอัตโนมัติ</b><small>หลังออกจากแอป</small></div><select id="lockMinutes" ${hasPin?'':'disabled'}><option value="1" ${data.autoLockMinutes==1?'selected':''}>1 นาที</option><option value="5" ${data.autoLockMinutes==5?'selected':''}>5 นาที</option><option value="15" ${data.autoLockMinutes==15?'selected':''}>15 นาที</option></select></div><div class="setting"><div><b>Encrypted Backup</b><small>ไฟล์สำรองเข้ารหัส AES-256-GCM และต้องใช้รหัสผ่านเพื่อเปิด</small></div><button id="exportBtn">Export</button></div><div class="setting"><div><b>Restore Encrypted Backup</b><small>นำไฟล์สำรองที่เข้ารหัสกลับเข้าแอป</small></div><button id="importBtn">Import</button></div><div class="setting"><div><b>บันทึก Snapshot เดือนนี้</b><small>เก็บ Net Worth เพื่อเทียบเดือนถัดไป</small></div><button id="snapshotBtn">Save</button></div>${hasPin?`<div class="setting"><div><b>ล็อกทันที</b><small>กลับไปหน้า PIN</small></div><button id="lockNow">Lock</button></div>`:''}</div><div class="notice"><b>Security v1.2.2</b><br>เมื่อเปิด App Lock ข้อมูลหลักในเครื่องถูกเข้ารหัสด้วย AES-256-GCM โดยคีย์ที่ derive จาก PIN ด้วย PBKDF2-SHA-256 (210,000 iterations) แอปนี้ไม่มี Cloud Sync/Analytics/API ส่งข้อมูลการเงินออกไป ควรเก็บ Encrypted Backup ไว้ในเครื่องอย่างปลอดภัย</div><div class="setting"><div><b>Audit Trail</b><small>เก็บประวัติการเพิ่ม แก้ไข ลบ และ Reconcile ล่าสุด</small></div><span>${(data.auditLog||[]).length} รายการ</span></div><div class="version">MY FINANCE v${APP_VERSION}</div>`
}
function bottomNav(){
  const items=[['dashboard','◆','Dashboard'],['transactions','≡','Transactions'],['add','+',''],['assets','◈','Assets'],['plan','◎','Plan']];
  return `<nav class="bottom">${items.map(([p,i,l])=>p==='add'?`<button class="add" id="quickAdd">+</button>`:`<button class="nav ${page===p?'active':''}" data-page="${p}"><span class="ico">${i}</span>${l}</button>`).join('')}</nav>`
}
function sheet(){
  if(modal==='tx'||modal==='editTx')return txSheet();
  if(modal==='asset'||modal==='editAsset')return assetSheet();
  if(modal==='goal'||modal==='editGoal')return goalSheet();
  if(modal==='budget')return budgetSheet();
  if(modal==='projectBudget')return projectBudgetSheet();
  if(modal==='pin')return pinSheet();
  if(modal==='reconcile')return reconcileSheet();
  return '';
}
function txSheet(){
  const editing=modal==='editTx';
  const x=editing?data.transactions.find(t=>t.id===editId):null;
  const type=x?.type||txDraftType||'expense';
  const cats=type==='income'?incomeCats:type==='investment'?['ลงทุน','อื่น ๆ']:type==='transfer'?['โอนเงิน']:expenseCats;
  const accountFields=type==='transfer'?`<div class="row2"><div class="field"><label>จากบัญชี</label><select id="sourceAsset" required><option value="">เลือกต้นทาง</option>${cashAssets().map(a=>`<option value="${esc(a.id)}" ${x?.sourceAssetId===a.id?'selected':''}>${esc(a.name)} · ${THB(a.value)}</option>`).join('')}</select></div><div class="field"><label>ไปบัญชี</label><select id="destinationAsset" required><option value="">เลือกปลายทาง</option>${cashAssets().map(a=>`<option value="${esc(a.id)}" ${x?.destinationAssetId===a.id?'selected':''}>${esc(a.name)} · ${THB(a.value)}</option>`).join('')}</select></div></div><small class="field-hint">โอนเงินจะลดต้นทาง เพิ่มปลายทาง และไม่ถูกนับเป็นรายรับ/รายจ่าย</small>`:`<div class="row2"><div class="field"><label>หมวด</label><select id="category">${cats.map(c=>`<option ${x?.category===c?'selected':''}>${esc(c)}</option>`).join('')}</select></div><div class="field"><label>แหล่งเงิน / บัญชี</label><select id="sourceAsset"><option value="">ไม่ผูกบัญชี</option>${cashAssets().map(a=>`<option value="${esc(a.id)}" ${(x?.sourceAssetId===a.id||(!x?.sourceAssetId&&x?.account===a.name))?'selected':''}>${esc(a.name)} · ${THB(a.value)}</option>`).join('')}</select><small class="field-hint">${type==='reimbursement'?'เงินคืนจะเพิ่มยอดบัญชี และหักออกจากรายจ่ายสุทธิ':'รายจ่ายหักยอด · รายรับเพิ่มยอดอัตโนมัติ'}</small></div></div>`;
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${editing?'แก้ไขรายการ':'เพิ่มรายการ'}</h3><div class="type-grid">${[['income','💚','รายรับ'],['expense','🩷','รายจ่าย'],['reimbursement','↩️','คืนค่าใช้จ่าย'],['transfer','🔄','โอนเงิน'],['investment','📈','ลงทุน']].map(([t,i,n])=>`<button class="type ${type===t?'sel':''}" data-txtype="${t}"><strong>${i}</strong>${n}</button>`).join('')}</div><form id="txForm"><input type="hidden" id="txType" value="${type}"><div class="field"><label>จำนวนเงิน</label><input id="amount" class="amount-input" inputmode="decimal" type="text" autocomplete="off" placeholder="0.00" value="${x?Number(x.amount||0):''}" required></div>${accountFields}<div class="field"><label>โครงการ / สถานที่</label><select id="project">${projects.map(c=>`<option ${((x?.project||'ส่วนตัว/ทั่วไป')===c)?'selected':''}>${esc(c)}</option>`).join('')}</select></div><div class="field"><label>วันที่</label><input id="date" type="date" value="${x?.date||today()}"></div><div class="field"><label>หมายเหตุ</label><input id="note" placeholder="ไม่บังคับ" value="${esc(x?.note||'')}"></div><button class="primary">${editing?'บันทึกการแก้ไข':'บันทึก'}</button>${editing?`<button type="button" class="danger" id="deleteTx">ลบรายการนี้</button>`:''}</form></div></div>`
}
function assetSheet(){
  const editing=modal==='editAsset'; const a=editing?data.assets.find(x=>x.id===editId):null;
  const stock=a?.kind==='stock'; const cost=Number(a?.cost??a?.value??0), value=Number(a?.value||0), pl=value-cost;
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${editing?'แก้ไขทรัพย์สิน':'เพิ่มทรัพย์สิน'}</h3><form id="assetForm"><div class="field"><label>ชื่อ</label><input id="assetName" required placeholder="เช่น TISCO หรือ KBank" value="${esc(a?.name||'')}"></div><div class="field"><label>ประเภท</label><select id="assetKind">${[['cash','เงินสด/ธนาคาร'],['stock','หุ้น/กองทุน'],['gold','ทอง'],['property','ที่ดิน/อสังหาฯ'],['vehicle','รถ/ยานพาหนะ'],['other','ทรัพย์สินอื่น'],['debt','หนี้สิน']].map(([v,n])=>`<option value="${v}" ${a?.kind===v?'selected':''}>${n}</option>`).join('')}</select></div><div id="stockFields" style="display:${stock?'block':'none'}">${`<div class="row2"><div class="field"><label>ต้นทุนรวม</label><input id="assetCost" type="text" inputmode="decimal" value="${cost}"></div><div class="field"><label>มูลค่าปัจจุบัน / NAV วันนี้</label><input id="assetValue" type="text" inputmode="decimal" value="${value}"></div></div><div class="row2"><div class="field"><label>จำนวนหุ้น/หน่วย (ถ้ามี)</label><input id="assetUnits" type="text" inputmode="decimal" value="${Number(a?.units||0)||''}"></div><div class="field"><label>ราคา/NAV ต่อหน่วย (ถ้ามี)</label><input id="assetPrice" type="text" inputmode="decimal" value="${Number(a?.price||0)||''}"></div></div><div class="notice"><b>Unrealized P/L:</b> <span class="${pl>=0?'pos':'neg'}">${pl>=0?'+':''}${THB(pl)}${cost?` (${pl/cost*100>=0?'+':''}${(pl/cost*100).toFixed(2)}%)`:''}</span></div>`}</div><div id="normalValueField" style="display:${stock?'none':'block'}"><div class="field"><label>มูลค่าปัจจุบัน</label><input id="assetValueNormal" class="amount-input" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${a?Number(a.value||0):''}"></div></div><div class="field"><label>สภาพคล่อง</label><select id="assetLiquidity"><option value="ready" ${(a?.liquidity||'ready')==='ready'?'selected':''}>◉ พร้อมใช้</option><option value="limited" ${a?.liquidity==='limited'?'selected':''}>◐ มีข้อจำกัด</option><option value="low" ${a?.liquidity==='low'?'selected':''}>◇ สภาพคล่องต่ำ</option></select></div>${editing&&a?.kind==='cash'?`<button type="button" class="secondary" id="reconcileAsset">Reconcile / ปรับยอดตามเงินจริง</button>`:''}<button class="primary">${editing?'บันทึกการแก้ไข':'บันทึก'}</button>${editing?`<button type="button" class="danger" id="deleteAsset">ลบรายการนี้</button>`:''}</form></div></div>`
}
function goalSheet(){
  const editing=modal==='editGoal'; const g=editing?data.goals.find(x=>x.id===editId):null;
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${editing?'แก้ไขเป้าหมาย':'เพิ่มเป้าหมาย'}</h3><form id="goalForm"><div class="field"><label>ชื่อเป้าหมาย</label><input id="goalName" value="${esc(g?.name||'')}" placeholder="เช่น เงินเที่ยวต่างประเทศ" required></div><div class="field"><label>เป้าหมาย</label><input id="goalTarget" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${g?Number(g.target||0):''}" required></div><div class="field"><label>ปัจจุบัน</label><input id="goalCurrent" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${g?Number(g.current||0):0}" required></div><button class="primary">บันทึก</button>${editing?`<button type="button" class="danger" id="deleteGoal">ลบเป้าหมายนี้</button>`:''}</form></div></div>`
}
function budgetSheet(){
  const cat=editId; const current=Number(currentBudgetMap()[cat]||0);
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>ตั้งงบ: ${esc(cat)}</h3><form id="budgetForm"><div class="field"><label>งบประมาณเดือนนี้</label><input id="budgetAmount" class="amount-input" type="text" inputmode="decimal" autocomplete="off" value="${current||''}" placeholder="0.00" required></div><button class="primary">บันทึกงบ</button>${current?`<button type="button" class="danger" id="clearBudget">ล้างงบหมวดนี้</button>`:''}</form></div></div>`
}
function projectBudgetSheet(){
  const name=editId,current=Number(currentProjectBudgetMap()[name]||0);
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>ตั้งงบ: ${projectIcon(name)} ${esc(name)}</h3><form id="projectBudgetForm"><div class="field"><label>งบรายจ่ายเดือนนี้</label><input id="projectBudgetAmount" class="amount-input" type="text" inputmode="decimal" autocomplete="off" value="${current||''}" placeholder="0.00" required></div><button class="primary">บันทึกงบ</button>${current?`<button type="button" class="danger" id="clearProjectBudget">ล้างงบโครงการนี้</button>`:''}</form></div></div>`
}
function reconcileSheet(){
  const a=findAsset(editId); if(!a)return '';
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>Reconcile · ${esc(a.name)}</h3><p class="field-hint">ใส่ยอดที่มีอยู่จริงตอนนี้ ระบบจะปรับ Asset โดยไม่สร้างรายรับ/รายจ่ายปลอม และเก็บบันทึกส่วนต่างไว้</p><form id="reconcileForm"><div class="field"><label>ยอดในแอป</label><input value="${Number(a.value||0)}" disabled></div><div class="field"><label>ยอดจริงตอนนี้</label><input id="actualBalance" type="text" inputmode="decimal" required></div><div class="field"><label>หมายเหตุ</label><input id="reconcileNote" value="ตรวจยอดตามเงินจริง"></div><button class="primary">ปรับยอด</button></form></div></div>`
}

function pinSheet(){
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${(hasSecureVault||legacyPin||currentPin)?'เปลี่ยน PIN / Encryption':'ตั้ง PIN / Encryption'}</h3><form id="pinForm"><div class="field"><label>PIN ใหม่ 4–6 หลัก</label><input id="newPin1" class="pin" type="password" inputmode="numeric" maxlength="6" required></div><div class="field"><label>ยืนยัน PIN</label><input id="newPin2" class="pin" type="password" inputmode="numeric" maxlength="6" required></div><button class="primary">บันทึก PIN</button></form></div></div>`
}
function updateCategoryOptions(type,selected=''){
  const c=$('#category'); if(!c)return;
  const cats=type==='income'?incomeCats:type==='investment'?['ลงทุน','อื่น ๆ']:type==='transfer'?['โอนเงิน','อื่น ๆ']:expenseCats;
  c.innerHTML=cats.map(x=>`<option ${selected===x?'selected':''}>${esc(x)}</option>`).join('');
}

function bind(){
  if(!unlocked){
    $('#enterWithoutPin')?.addEventListener('click',()=>{unlocked=true;render()});
    const unlock=async()=>{const pin=$('#unlockPin')?.value||'';try{if(hasSecureVault)await unlockSecure(pin);else await secureLegacy(pin);data.lastActive=Date.now();render()}catch{alert('PIN ไม่ถูกต้อง หรือข้อมูลเข้ารหัสไม่สามารถเปิดได้')}};
    $('#unlockBtn')?.addEventListener('click',unlock); $('#unlockPin')?.addEventListener('keydown',e=>e.key==='Enter'&&unlock());
    return;
  }
  $$('.nav').forEach(b=>b.addEventListener('click',()=>{page=b.dataset.page;render()}));
  $('#openSettings')?.addEventListener('click',()=>{page='settings';render()});
  $('#quickAdd')?.addEventListener('click',()=>{txDraftType='expense';modal='tx';editId=null;render()});
  $('#seeAll')?.addEventListener('click',()=>{page='transactions';render()});
  $$('.goPlan').forEach(b=>b.addEventListener('click',()=>{page='plan';render()}));
  $$('[data-filter]').forEach(b=>b.addEventListener('click',()=>{txFilter=b.dataset.filter;render()}));
  $$('[data-id]').forEach(b=>b.addEventListener('click',()=>{editId=b.dataset.id;modal='editTx';render()}));
  $$('[data-asset-kind]').forEach(b=>b.addEventListener('click',()=>{assetFilter=b.dataset.assetKind;render()}));
  $('#assetBack')?.addEventListener('click',()=>{assetFilter='all';render()});
  $('#addAsset')?.addEventListener('click',()=>{modal='asset';editId=null;render()});
  $$('[data-asset-id]').forEach(b=>b.addEventListener('click',()=>{editId=b.dataset.assetId;modal='editAsset';render()}));
  $('#addGoal')?.addEventListener('click',()=>{modal='goal';editId=null;render()});
  $$('[data-goal-id]').forEach(b=>b.addEventListener('click',()=>{editId=b.dataset.goalId;modal='editGoal';render()}));
  $$('[data-budget-cat]').forEach(b=>b.addEventListener('click',()=>{editId=b.dataset.budgetCat;modal='budget';render()}));
  $$('[data-project-budget]').forEach(b=>b.addEventListener('click',()=>{editId=b.dataset.projectBudget;modal='projectBudget';render()}));
  $('#sheetBack')?.addEventListener('click',e=>{if(e.target.id==='sheetBack'){modal=null;editId=null;render()}});
  $$('[data-txtype]').forEach(b=>b.addEventListener('click',()=>{if(modal==='editTx')return; txDraftType=b.dataset.txtype; render()}));

  $('#txForm')?.addEventListener('submit',e=>{
    e.preventDefault();
    const sourceAssetId=$('#sourceAsset')?.value||'';
    const sourceAsset=sourceAssetId?findAsset(sourceAssetId):null;
    const destinationAssetId=$('#destinationAsset')?.value||''; const destinationAsset=destinationAssetId?findAsset(destinationAssetId):null;
    const row={id:editId||uid(),type:$('#txType').value,amount:parseMoney($('#amount').value),category:$('#category')?.value||'โอนเงิน',account:sourceAsset?.name||'',sourceAssetId,destinationAssetId,destinationAccount:destinationAsset?.name||'',project:$('#project')?.value||'ส่วนตัว/ทั่วไป',date:$('#date').value,note:$('#note').value.trim()};
    if(!row.amount||row.amount<0)return alert('กรุณาใส่จำนวนเงินมากกว่า 0');
    if(row.type==='transfer'&&(!sourceAssetId||!destinationAssetId||sourceAssetId===destinationAssetId)){alert('กรุณาเลือกบัญชีต้นทางและปลายทางคนละบัญชี');return}
    if((row.type==='expense'||row.type==='income'||row.type==='reimbursement')&&!sourceAssetId){if(!confirm('ยังไม่ได้เลือกแหล่งเงิน/บัญชี รายการนี้จะไม่ปรับยอด Assets อัตโนมัติ ต้องการบันทึกต่อหรือไม่?'))return}
    if((row.type==='expense'||row.type==='transfer')&&sourceAsset&&Number(sourceAsset.value||0)<row.amount){if(!confirm(`ยอด ${sourceAsset.name} ปัจจุบัน ${THB(sourceAsset.value)} น้อยกว่ารายจ่าย ${THB(row.amount)} ต้องการให้ยอดติดลบและบันทึกต่อหรือไม่?`))return}
    if(modal==='editTx'){
      const i=data.transactions.findIndex(x=>x.id===editId);
      if(i>=0){reverseTxAssetEffect(data.transactions[i]); data.transactions[i]=row; applyTxAssetEffect(row)}
    }else{data.transactions.push(row);applyTxAssetEffect(row)}
    audit(modal==='editTx'?'แก้ไขรายการ':'เพิ่มรายการ',`${typeLabel(row.type)} ${THB(row.amount)}`); snapshotCurrentMonth(); save(); modal=null; editId=null; render();
  });
  $('#deleteTx')?.addEventListener('click',()=>{if(confirm('ลบรายการนี้ใช่หรือไม่?')){const old=data.transactions.find(x=>x.id===editId);reverseTxAssetEffect(old);audit('ลบรายการ',`${typeLabel(old?.type)} ${THB(old?.amount)}`);data.transactions=data.transactions.filter(x=>x.id!==editId);snapshotCurrentMonth();save();modal=null;editId=null;render()}});

  $('#assetKind')?.addEventListener('change',e=>{const isStock=e.target.value==='stock';const sf=$('#stockFields'),nf=$('#normalValueField');if(sf)sf.style.display=isStock?'block':'none';if(nf)nf.style.display=isStock?'none':'block'});
  $('#assetForm')?.addEventListener('submit',e=>{
    e.preventDefault(); const oldAsset=editId?findAsset(editId):null; const kind=$('#assetKind').value; const valueEl=kind==='stock'?$('#assetValue'):$('#assetValueNormal'); const row={id:editId||uid(),name:$('#assetName').value.trim(),kind,value:parseMoney(valueEl?.value),cost:kind==='stock'?parseMoney($('#assetCost')?.value||$('#assetValue').value):Number(oldAsset?.cost||0),units:kind==='stock'?parseMoney($('#assetUnits')?.value||0):0,price:kind==='stock'?parseMoney($('#assetPrice')?.value||0):0,liquid:oldAsset?.liquid!==false,liquidity:$('#assetLiquidity')?.value||oldAsset?.liquidity||'ready'};
    if(!row.name)return alert('กรุณาใส่ชื่อทรัพย์สิน'); if(!Number.isFinite(row.value)||row.value<0)return alert('กรุณาใส่มูลค่าที่ถูกต้อง');
    if(modal==='editAsset'){const i=data.assets.findIndex(x=>x.id===editId);if(i>=0)data.assets[i]=row}else data.assets.push(row);
    audit(modal==='editAsset'?'แก้ไขทรัพย์สิน':'เพิ่มทรัพย์สิน',row.name); snapshotCurrentMonth(); save(); modal=null; editId=null; render();
  });
  $('#reconcileAsset')?.addEventListener('click',()=>{modal='reconcile';render()});
  $('#reconcileForm')?.addEventListener('submit',e=>{e.preventDefault();const a=findAsset(editId);if(!a)return;const actual=parseMoney($('#actualBalance').value);if(!Number.isFinite(actual)||actual<0)return alert('กรุณาใส่ยอดจริง');const before=Number(a.value||0);a.value=actual;data.reconciliations=Array.isArray(data.reconciliations)?data.reconciliations:[];audit('Reconcile',`${a.name}: ${THB(before)} → ${THB(actual)}`);data.reconciliations.push({id:uid(),assetId:a.id,date:new Date().toISOString(),before,after:actual,difference:round2(actual-before),note:$('#reconcileNote').value.trim()});snapshotCurrentMonth();save();modal=null;editId=null;render()});
  $('#deleteAsset')?.addEventListener('click',()=>{if(confirm('ลบทรัพย์สินนี้ใช่หรือไม่?')){data.assets=data.assets.filter(x=>x.id!==editId);snapshotCurrentMonth();save();modal=null;editId=null;render()}});

  $('#goalForm')?.addEventListener('submit',e=>{
    e.preventDefault(); const row={id:editId||uid(),name:$('#goalName').value.trim(),target:parseMoney($('#goalTarget').value)||0,current:parseMoney($('#goalCurrent').value)||0};
    if(!Number.isFinite(row.target)||!Number.isFinite(row.current)||row.target<0||row.current<0)return alert('กรุณาใส่จำนวนเงินที่ถูกต้อง');
    if(modal==='editGoal'){const i=data.goals.findIndex(x=>x.id===editId);if(i>=0)data.goals[i]=row}else data.goals.push(row);
    save(); modal=null; editId=null; render();
  });
  $('#deleteGoal')?.addEventListener('click',()=>{if(data.goals.length<=1)return alert('ต้องมีอย่างน้อย 1 เป้าหมาย');if(confirm('ลบเป้าหมายนี้ใช่หรือไม่?')){data.goals=data.goals.filter(x=>x.id!==editId);save();modal=null;editId=null;render()}});

  $('#budgetForm')?.addEventListener('submit',e=>{e.preventDefault();const key=monthKey();if(!data.budgets[key])data.budgets[key]={};data.budgets[key][editId]=parseMoney($('#budgetAmount').value)||0;save();modal=null;editId=null;render()});
  $('#clearBudget')?.addEventListener('click',()=>{const key=monthKey();if(data.budgets[key])delete data.budgets[key][editId];save();modal=null;editId=null;render()});
  $('#projectBudgetForm')?.addEventListener('submit',e=>{e.preventDefault();const key=monthKey();if(!data.projectBudgets[key])data.projectBudgets[key]={};data.projectBudgets[key][editId]=parseMoney($('#projectBudgetAmount').value)||0;save();modal=null;editId=null;render()});
  $('#clearProjectBudget')?.addEventListener('click',()=>{const key=monthKey();if(data.projectBudgets[key])delete data.projectBudgets[key][editId];save();modal=null;editId=null;render()});

  $('#setPin')?.addEventListener('click',()=>{modal='pin';render()});
  $('#changePin')?.addEventListener('click',()=>{modal='pin';render()});
  $('#pinForm')?.addEventListener('submit',async e=>{e.preventDefault();const a=$('#newPin1').value,b=$('#newPin2').value;if(!/^\d{6}$/.test(a))return alert('เพื่อความปลอดภัย V1.2.2 กำหนด PIN 6 หลัก');if(a!==b)return alert('PIN ไม่ตรงกัน');currentPin=a;legacyPin=null;data.pin=null;data.autoLock=true;save();await saveSeq;localStorage.removeItem(DB_KEY);modal=null;render();alert('เปิดการเข้ารหัสข้อมูลในเครื่องแล้ว')});
  $('#autoLock')?.addEventListener('change',e=>{data.autoLock=e.target.checked;save()});
  $('#lockMinutes')?.addEventListener('change',e=>{data.autoLockMinutes=Number(e.target.value)||1;save()});
  $('#lockNow')?.addEventListener('click',async()=>{data.lastActive=Date.now();save();await saveSeq;currentPin=null;unlocked=false;render()});
  $('#snapshotBtn')?.addEventListener('click',()=>{snapshotCurrentMonth();save();alert('บันทึก Snapshot เดือนนี้แล้ว');render()});
  $('#exportBtn')?.addEventListener('click',async()=>{const pass=prompt('ตั้งรหัสผ่านสำหรับไฟล์ Backup (อย่างน้อย 8 ตัวอักษร)');if(!pass)return;if(pass.length<8)return alert('รหัสผ่าน Backup ต้องอย่างน้อย 8 ตัวอักษร');snapshotCurrentMonth();save();await saveSeq;const snap=clone(data);delete snap.pin;const box=await encryptObject(snap,pass);const blob=new Blob([JSON.stringify(box,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`MY-FINANCE-ENCRYPTED-${new Date().toISOString().slice(0,10)}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)});
  $('#importBtn')?.addEventListener('click',()=>document.getElementById('importFile').click());
}

document.getElementById('importFile').addEventListener('change',async e=>{
  const f=e.target.files[0]; if(!f)return;
  try{
    let obj=JSON.parse(await f.text());
    if(obj?.format==='MYFINANCE-ENC-1'){const pass=prompt('รหัสผ่านของไฟล์ Backup');if(!pass)throw new Error('cancel');obj=await decryptObject(obj,pass)}
    if(!obj||!Array.isArray(obj.transactions)||!Array.isArray(obj.assets))throw new Error('invalid');
    if(confirm('Restore จะทับข้อมูลปัจจุบันทั้งหมด ต้องการดำเนินการหรือไม่?')){data=migrate(obj);data.pin=null;save();await saveSeq;page='dashboard';render()}
  }catch{alert('ไฟล์ Backup หรือรหัสผ่านไม่ถูกต้อง')}
  e.target.value='';
});

document.addEventListener('visibilitychange',()=>{
  if(document.hidden){data.lastActive=Date.now();save()}
  else if(data.autoLock&&(hasSecureVault||legacyPin||currentPin)){const ms=(Number(data.autoLockMinutes)||1)*60000;if(Date.now()-Number(data.lastActive||0)>ms){currentPin=null;unlocked=false;render()}}
});

window.addEventListener('beforeunload',()=>{data.lastActive=Date.now();save()});
if('serviceWorker' in navigator)navigator.serviceWorker.register('./sw.js').catch(()=>{});
render();
