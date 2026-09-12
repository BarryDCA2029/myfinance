const DB_KEY='myfinance_v1';
const VAULT_KEY='myfinance_secure_v122';
const APP_VERSION='1.6';
const expenseCats=['อาหาร','เดินทาง','ครอบครัว','สุขภาพ','การศึกษา','ท่องเที่ยว','ภาษี','ของใช้ส่วนตัว','ค่าสาธารณูปโภค','ค่าซ่อม/บำรุง','ค่าแรง','วัสดุ/อุปกรณ์','ปุ๋ย/ต้นไม้','อาหารสัตว์','อื่น ๆ'];
const projects=['ส่วนตัว/ทั่วไป','บ้าน กทม.','บ้าน เกษตรวิสัย','เลี้ยงไก่','ป่ายาง','Polar Farm','Polar Farm 1','Polar Farm 2'];
const incomeCats=['เงินเดือนรอบ 1','เงินเดือนรอบ 2','ค่าเช่า 1','ค่าเช่า 2','รายรับพิเศษ/เงินสนับสนุน','ปันผล','ดอกเบี้ย','ขายทรัพย์สิน','อื่น ๆ'];
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
  verifiedEmptyDays:[],
  settings:{currency:'THB',hideZeroDebt:true,defaultExpenseAssetId:'',emergencyAssetIds:[]}
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
let calendarMonth=monthKey();
let calendarDayDate=null;
let txDraftDate='';
let detailType='';
let detailMonth=monthKey();

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
  merged.verifiedEmptyDays=Array.isArray(raw.verifiedEmptyDays)?raw.verifiedEmptyDays:[];
  merged.assets=merged.assets.map(a=>({...a,note:String(a.note||'').slice(0,150)}));
  merged.settings={...defaultData.settings,...(raw.settings||{})};
  merged.settings.emergencyAssetIds=Array.isArray(merged.settings.emergencyAssetIds)?merged.settings.emergencyAssetIds:[];
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
function today(){const d=new Date();return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`}
function monthKey(d=new Date()){return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`}
function inCurrentMonth(t){return (t.date||'').slice(0,7)===monthKey()}
function esc(s=''){return String(s).replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function typeLabel(t){return ({income:'รายรับ',expense:'รายจ่าย',reimbursement:'คืนค่าใช้จ่าย',transfer:'โอนเงิน',investment:'ลงทุน',inKind:'ผลผลิตใช้เอง'})[t]||t}
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
function iconFor(cat){const m={'อาหาร':'🍜','เดินทาง':'🚗','ครอบครัว':'👨‍👩‍👧','สุขภาพ':'🩺','การศึกษา':'📚','ท่องเที่ยว':'✈️','ภาษี':'🧾','ของใช้ส่วนตัว':'🧴','ค่าสาธารณูปโภค':'💡','ค่าซ่อม/บำรุง':'🛠️','ค่าแรง':'👷','วัสดุ/อุปกรณ์':'🧰','ปุ๋ย/ต้นไม้':'🌱','อาหารสัตว์':'🌾','เงินเดือน':'💼','ปันผล':'💹','ดอกเบี้ย':'🏦','รายได้พิเศษ':'✨','รายรับพิเศษ/เงินสนับสนุน':'✦','เงินเดือนรอบ 1':'💼','เงินเดือนรอบ 2':'💼','ค่าเช่า 1':'🏠','ค่าเช่า 2':'🏠','ผลผลิตใช้เอง':'◇','ค่าเช่า':'🏠','ขายทรัพย์สิน':'🏷️','ลงทุน':'📈','โอนเงิน':'🔄','อื่น ๆ':'•'};return m[cat]||'•'}
function audit(action,detail=''){data.auditLog=Array.isArray(data.auditLog)?data.auditLog:[];data.auditLog.push({id:uid(),at:new Date().toISOString(),action,detail});data.auditLog=data.auditLog.slice(-500)}
function liquidityLabel(v){return ({ready:'พร้อมใช้',limited:'มีข้อจำกัด',low:'สภาพคล่องต่ำ'})[v]||'พร้อมใช้'}
function assetKindLabel(k){return ({cash:'เงินสด/ธนาคาร',stock:'หุ้น/กองทุน',gold:'ทอง',property:'ที่ดิน/อสังหาฯ',vehicle:'รถ/ยานพาหนะ',other:'ทรัพย์สินอื่น',debt:'หนี้สิน'})[k]||k}
function emergencyValue(){const ids=data.settings?.emergencyAssetIds||[];return data.assets.filter(a=>ids.includes(a.id)).reduce((s,a)=>s+Number(a.value||0),0)}
function moneyValue(v){const n=parseMoney(v);return Number.isFinite(n)&&n!==0?num(n):''}
function orderedCashAssets(type='expense',selectedId=''){
  const list=[...cashAssets()];
  if(type!=='expense')return list;
  const def=data.settings?.defaultExpenseAssetId||list.find(a=>/ttb all free/i.test(a.name||''))?.id||'';
  const wallet=list.find(a=>/เงินสดในมือ|cash in hand/i.test(a.name||''));
  return list.sort((a,b)=>{
    const rank=x=>x.id===selectedId?0:x.id===def?1:(wallet&&x.id===wallet.id?2:3);
    return rank(a)-rank(b) || String(a.name).localeCompare(String(b.name),'th');
  });
}
function monthTotals(key){
  const m=data.transactions.filter(x=>(x.date||'').slice(0,7)===key);
  const income=m.filter(x=>x.type==='income').reduce((s,x)=>s+Number(x.amount||0),0);
  const expense=round2(m.filter(x=>x.type==='expense').reduce((s,x)=>s+Number(x.amount||0),0)-m.filter(x=>x.type==='reimbursement').reduce((s,x)=>s+Number(x.amount||0),0));
  return {income,expense,cashflow:round2(income-expense)};
}
function effectiveGoalCurrent(g){return /ฉุกเฉิน/.test(g?.name||'')&&data.settings?.emergencyAssetIds?.length?emergencyValue():Number(g?.current||0)}

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
function projectStats(name){const tx=data.transactions.filter(x=>inCurrentMonth(x)&&(x.project||'ส่วนตัว/ทั่วไป')===name);const income=tx.filter(x=>x.type==='income').reduce((s,x)=>s+Number(x.amount||0),0);const grossExpense=tx.filter(x=>x.type==='expense').reduce((s,x)=>s+Number(x.amount||0),0);const reimbursements=tx.filter(x=>x.type==='reimbursement').reduce((s,x)=>s+Number(x.amount||0),0);const inKind=tx.filter(x=>x.type==='inKind').reduce((s,x)=>s+Number(x.amount||0),0);const expense=round2(grossExpense-reimbursements);return {income,expense,inKind,net:income-expense,economic:round2(income+inKind-expense)}}
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
  return `${header()}<section class="hero"><div class="label">◆ NET WORTH</div><div class="value">${THB(t.netWorth)}</div><div class="delta">${t.netWorth>0?'●':'○'} Current snapshot ${pct!==null?`· ${pct>=0?'+':''}${pct.toFixed(1)}% vs เดือนก่อน`:''}</div></section><div class="grid4"><button class="mini liquid kpi-card" data-kpi="liquid"><div class="t">◉ เงินพร้อมใช้</div><div class="v">${THB(t.liquidMoney)}</div><small>แตะเพื่อดูรายละเอียด</small></button><button class="mini income kpi-card" data-kpi="income"><div class="t">↑ รายรับ</div><div class="v">${THB(t.income)}</div><small>แตะเพื่อดูรายละเอียด</small></button><button class="mini expense kpi-card" data-kpi="expense"><div class="t">↓ รายจ่าย</div><div class="v">${THB(t.expense)}</div><small>แตะเพื่อดูรายละเอียด</small></button><button class="mini cashflow kpi-card" data-kpi="cashflow"><div class="t">↕ Cash Flow</div><div class="v">${THB(t.cashflow)}</div><small>แตะเพื่อดูรายละเอียด</small></button></div>${financialPulse()}${moneyCalendar()}${spendingCard()}${budgetSummary()}${projectDashboard()}${healthCard()}${goalsSummary()}${recentTx()}`
}

function financialPulse(){
  const t=totals();
  const status=t.cashflow>=0?'เดือนนี้ยังเป็นบวก':'เดือนนี้ใช้มากกว่ารายรับ';
  return `<section class="section"><div class="section-title"><h2>Financial Pulse</h2><span>เงินจริงเดือนนี้</span></div><div class="card pulse"><b>${t.cashflow>=0?'✓':'!'} ${status}</b><p>↑ รับจริง ${THB(t.income)} · ↓ จ่ายจริงสุทธิ ${THB(t.expense)} · ↕ Cash Flow <strong class="${t.cashflow>=0?'pos':'neg'}">${t.cashflow>=0?'+':''}${THB(t.cashflow)}</strong></p><small class="pulse-note">Budget เป็นวงเงินวางแผนและไม่ถูกรวมในตัวเลขนี้</small></div></section>`
}
function moneyCalendar(){
  const [yy,mm]=calendarMonth.split('-').map(Number);
  const first=new Date(yy,mm-1,1), days=new Date(yy,mm,0).getDate();
  const offset=(first.getDay()+6)%7; // จันทร์เป็นวันแรก
  const labels=['จ','อ','พ','พฤ','ศ','ส','อา'];
  const monthTx=data.transactions.filter(x=>(x.date||'').startsWith(calendarMonth));
  const cells=[];
  for(let i=0;i<offset;i++)cells.push('<div class="cal-cell cal-empty"></div>');
  for(let d=1;d<=days;d++){
    const date=`${calendarMonth}-${String(d).padStart(2,'0')}`;
    const tx=monthTx.filter(x=>x.date===date);
    const inc=tx.filter(x=>x.type==='income').reduce((a,x)=>a+Number(x.amount||0),0);
    const exp=tx.filter(x=>x.type==='expense').reduce((a,x)=>a+Number(x.amount||0),0)-tx.filter(x=>x.type==='reimbursement').reduce((a,x)=>a+Number(x.amount||0),0);
    const checked=(data.verifiedEmptyDays||[]).includes(date);
    const todayClass=date===today()?' today':'';
    const active=tx.length?' has-tx':checked?' checked':'';
    cells.push(`<button class="cal-cell${todayClass}${active}" data-cal-date="${date}"><span class="cal-day">${d}</span>${inc?`<i class="cal-in">+${num(inc)}</i>`:''}${exp>0?`<i class="cal-out">-${num(exp)}</i>`:exp<0?`<i class="cal-in">+${num(Math.abs(exp))}</i>`:''}${!tx.length&&checked?'<i class="cal-ok">✓</i>':''}</button>`);
  }
  const label=new Date(yy,mm-1,1).toLocaleDateString('th-TH',{month:'long',year:'numeric'});
  return `<section class="section"><div class="section-title"><h2>📅 Money Calendar</h2><span>แตะวันเพื่อดู/เพิ่มรายการ</span></div><div class="card calendar-card"><div class="cal-head"><button class="cal-nav" id="calPrev" aria-label="เดือนก่อน">‹</button><b>${label}</b><button class="cal-nav" id="calNext" aria-label="เดือนถัดไป">›</button></div><div class="cal-week">${labels.map(x=>`<span>${x}</span>`).join('')}</div><div class="cal-grid">${cells.join('')}</div><div class="cal-legend"><span><i class="legend-dot in"></i>รับ</span><span><i class="legend-dot out"></i>จ่ายสุทธิ</span><span>✓ ตรวจแล้วไม่มีรายการ</span></div></div></section>`;
}
function calendarDaySheet(){
  const date=calendarDayDate||today();
  const tx=[...data.transactions].filter(x=>x.date===date).sort((a,b)=>String(b.id).localeCompare(String(a.id)));
  const inc=tx.filter(x=>x.type==='income').reduce((s,x)=>s+Number(x.amount||0),0);
  const exp=tx.filter(x=>x.type==='expense').reduce((s,x)=>s+Number(x.amount||0),0)-tx.filter(x=>x.type==='reimbursement').reduce((s,x)=>s+Number(x.amount||0),0);
  const checked=(data.verifiedEmptyDays||[]).includes(date);
  const title=new Date(date+'T12:00:00').toLocaleDateString('th-TH',{weekday:'short',day:'numeric',month:'short',year:'numeric'});
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>📅 ${title}</h3><div class="day-kpis"><div><small>รับ</small><b class="pos">${THB(inc)}</b></div><div><small>จ่ายสุทธิ</small><b class="neg">${THB(exp)}</b></div><div><small>สุทธิ</small><b class="${inc-exp>=0?'pos':'neg'}">${inc-exp>=0?'+':''}${THB(inc-exp)}</b></div></div><button class="primary" id="addOnCalendarDay">+ เพิ่มรายการในวันนี้</button>${tx.length?`<div class="card tx-list day-list">${tx.map(txRow).join('')}</div>`:`<div class="empty compact">ยังไม่มีรายการในวันนี้</div><button class="secondary" id="toggleEmptyDay">${checked?'ยกเลิก ✓ ตรวจแล้วไม่มีรายการ':'✓ ยืนยันว่าไม่มีรายการวันนี้'}</button>`}</div></div>`;
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
  const active=projects.map(name=>({name,...projectStats(name)})).filter(x=>x.income||x.expense||x.inKind);
  if(!active.length)return `<section class="section"><div class="section-title"><h2>Projects & Properties</h2><span>เดือนนี้</span></div><div class="card budget-empty"><b>ยังไม่มีรายการแยกโครงการ</b><p>เวลาบันทึกรายรับ/รายจ่าย เลือก บ้าน กทม., บ้าน เกษตรวิสัย, เลี้ยงไก่, ป่ายาง หรือ Polar Farm ได้</p></div></section>`;
  return `<section class="section"><div class="section-title"><h2>Projects & Properties</h2><span>เดือนนี้</span></div><div class="card tx-list">${active.map(x=>`<div class="tx"><div class="tx-ico">${projectIcon(x.name)}</div><div class="tx-main"><b>${esc(x.name)}</b><small>รับเงินจริง ${THB(x.income)} · จ่าย ${THB(x.expense)}${x.inKind?` · ใช้เอง ${THB(x.inKind)}`:''}</small></div><div class="amt ${x.net>=0?'pos':'neg'}">${x.net>=0?'+':''}${THB(x.net)}</div></div>`).join('')}</div></section>`
}
function projectIcon(n){return ({'บ้าน กทม.':'🏙️','บ้าน เกษตรวิสัย':'🏡','เลี้ยงไก่':'🐓','ป่ายาง':'🌳','Polar Farm':'🌾','Polar Farm 1':'🌾','Polar Farm 2':'🌾','ส่วนตัว/ทั่วไป':'👤'})[n]||'◆'}
function budgetSummary(){
  const t=totals();
  const pb=currentProjectBudgetMap();
  const pnames=Object.keys(pb).filter(k=>Number(pb[k])>0);
  if(pnames.length){
    const budgetTotal=pnames.reduce((s,k)=>s+Number(pb[k]||0),0);
    const actual=pnames.reduce((s,k)=>s+Number(projectStats(k).expense||0),0);
    const p=budgetTotal?Math.round(actual/budgetTotal*100):0;
    const remain=round2(budgetTotal-actual);
    const gap=budgetTotal-t.income;
    const warning=t.income>0&&gap>0?`<div class="budget-warning">⚠ ถ้าใช้เต็มวงเงินทุกโครงการ จะสูงกว่ารายรับเดือนนี้ ${THB(gap)} — แต่ยังไม่ใช่เงินที่ถูกใช้จริง</div>`:'';
    return `<section class="section"><div class="section-title"><h2>◎ วงเงินโครงการเดือนนี้</h2><span>${p}% ใช้แล้ว</span></div><div class="card"><div class="budget-kpis"><div><small>วงเงินที่ตั้ง</small><b>${THB(budgetTotal)}</b></div><div><small>ใช้จริง</small><b>${THB(actual)}</b></div><div><small>${remain>=0?'เหลือ':'เกินวงเงิน'}</small><b class="${remain<0?'neg':''}">${THB(Math.abs(remain))}</b></div></div><div class="bar budget ${p>100?'over':p>=80?'warn':''}"><i style="width:${Math.min(100,p)}%"></i></div>${warning}<small class="budget-note">วงเงินเป็นเพียงเพดานวางแผน ไม่ดึงเงินจาก TTB หรือบัญชีใดจนกว่าจะมีรายจ่ายจริง</small></div></section>`;
  }
  const budgets=currentBudgetMap(); const sums=monthlyExpenseByCategory();
  const cats=Object.keys(budgets).filter(k=>Number(budgets[k])>0);
  if(!cats.length)return `<section class="section"><div class="section-title"><h2>◎ วงเงินวางแผน</h2><span>เดือนนี้</span></div><div class="card budget-empty"><b>ยังไม่ได้ตั้งวงเงิน</b><p>วงเงินเป็นเพียงตัวเลขเพดาน ไม่หักเงินจริงจากบัญชี</p><button class="secondary goPlan">ไปหน้า Plan</button></div></section>`;
  const budgetTotal=cats.reduce((s,k)=>s+Number(budgets[k]||0),0); const actual=cats.reduce((s,k)=>s+Number(sums[k]||0),0); const p=budgetTotal?Math.round(actual/budgetTotal*100):0;
  const gap=budgetTotal-t.income; const warning=t.income>0&&gap>0?`<div class="budget-warning">⚠ ถ้าใช้เต็มวงเงิน จะสูงกว่ารายรับเดือนนี้ ${THB(gap)} — ยังไม่ใช่เงินที่ใช้จริง</div>`:'';
  return `<section class="section"><div class="section-title"><h2>◎ วงเงินตามหมวดเดือนนี้</h2><span>${p}% ใช้แล้ว</span></div><div class="card"><div class="budget-kpis"><div><small>วงเงินที่ตั้ง</small><b>${THB(budgetTotal)}</b></div><div><small>ใช้จริง</small><b>${THB(actual)}</b></div><div><small>เหลือ</small><b>${THB(budgetTotal-actual)}</b></div></div><div class="bar budget ${p>100?'over':p>=80?'warn':''}"><i style="width:${Math.min(100,p)}%"></i></div>${warning}<small class="budget-note">วงเงินคือเพดานการใช้ ไม่หักเงินเก็บจนกว่าจะมีรายจ่ายจริง</small></div></section>`;
}
function healthCard(){
  const t=totals(); const txMonths=new Set(data.transactions.filter(x=>x.date).map(x=>x.date.slice(0,7))).size;
  const enough=t.income>0 && data.transactions.filter(x=>x.type==='expense').length>=3;
  const g=data.goals.find(x=>x.name.includes('ฉุกเฉิน'))||data.goals[0]||{target:1,current:0};
  const gp=Math.min(100,Math.round(effectiveGoalCurrent(g)/(Number(g.target)||1)*100));
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
  return `<section class="section"><div class="section-title"><h2>Financial Goals</h2><span class="goPlan">ดูทั้งหมด</span></div><div class="card goal-list">${list.map(g=>{const p=Math.min(100,Math.round(effectiveGoalCurrent(g)/(Number(g.target)||1)*100));return `<div class="goal-mini"><div><b>${esc(g.name)}</b><small>${THB(effectiveGoalCurrent(g))} / ${THB(g.target)}</small></div><strong>${p}%</strong></div>`}).join('')}</div></section>`
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
function assetBrand(a){
  const n=(a?.name||'').toLowerCase();
  if(/ttb|ทหารไทย/.test(n))return {key:'ttb',label:'ttb'};
  if(/bofa|bank of america|boa/.test(n))return {key:'bofa',label:'BofA'};
  if(/kbank|กสิกร/.test(n))return {key:'kbank',label:'K'};
  if(/ktb|กรุงไทย/.test(n))return {key:'ktb',label:'KTB'};
  if(/scb|ไทยพาณิชย์/.test(n))return {key:'scb',label:'SCB'};
  if(/สหกรณ์|coop/.test(n))return {key:a.kind==='stock'?'coop-stock':'coop',label:a.kind==='stock'?'↗':'◇'};
  if(a?.kind==='cash'&&/เงินสด|cash/.test(n))return {key:'wallet',label:'฿'};
  if(a?.kind==='stock')return {key:'stock',label:'↗'};
  if(a?.kind==='gold')return {key:'gold',label:'Au'};
  if(a?.kind==='property')return {key:'property',label:'⌂'};
  if(a?.kind==='vehicle')return {key:'vehicle',label:'◒'};
  if(a?.kind==='debt')return {key:'debt',label:'−'};
  return {key:'default',label:'◆'};
}
function assetIcon(a){const b=assetBrand(a);return `<span class="asset-brand ${b.key}">${esc(b.label)}</span>`}
function assets(){
  const t=totals(); const kinds=[['cash','เงินสด/ธนาคาร','💵'],['stock','หุ้น/กองทุน','📈'],['gold','ทอง','🌑'],['property','ที่ดิน/อสังหาฯ','🏡'],['vehicle','รถ/ยานพาหนะ','🚙'],['other','ทรัพย์สินอื่น','◆']];
  const filtered=assetFilter==='all'?data.assets:data.assets.filter(a=>a.kind===assetFilter);
  const title=assetFilter==='all'?'รายการทรัพย์สิน':assetKindLabel(assetFilter);
  const inv=investmentSummary();
  const investBox=assetFilter==='stock'?`<section class="section"><div class="card invest-summary"><small>Investment Portfolio</small><div class="invest-grid"><div><span>ต้นทุนรวม</span><b>${THB(inv.cost)}</b></div><div><span>มูลค่าปัจจุบัน</span><b>${THB(inv.value)}</b></div><div><span>Unrealized P/L</span><b class="${inv.pl>=0?'pos':'neg'}">${inv.pl>=0?'+':''}${THB(inv.pl)} (${inv.pct>=0?'+':''}${inv.pct.toFixed(2)}%)</b></div></div></div></section>`:'';
  return `${header('Assets','ทรัพย์สินและฐานะสุทธิ')}<div class="title-row"><h2 class="page-title">My Wealth</h2><small>Net Worth ${THB(t.netWorth)}</small></div><div class="asset-grid">${kinds.map(([k,n,ic])=>{const list=data.assets.filter(a=>a.kind===k);const v=list.reduce((s,a)=>s+Number(a.value||0),0);return `<button class="asset-card asset-card-btn ${assetFilter===k?'selected':''}" data-asset-kind="${k}"><div class="a-label">${ic} ${n}</div><div class="a-value">${THB(v)}</div><div class="a-sub">${list.length} รายการ · แตะเพื่อดู</div></button>`}).join('')}</div>${assetFilter!=='all'?`<button class="secondary asset-back" id="assetBack">← ดูทรัพย์สินทั้งหมด</button>`:''}${investBox}${t.debtTotal>0?`<section class="section"><div class="card debt-card"><small>หนี้สินรวม</small><b>${THB(t.debtTotal)}</b></div></section>`:''}<section class="section"><div class="section-title"><h2>${esc(title)}</h2><span id="addAsset">+ เพิ่ม</span></div><div class="card tx-list">${filtered.length?filtered.map(a=>{const pl=a.kind==='stock'?Number(a.value||0)-Number(a.cost??a.value??0):0;return `<button class="tx tx-button asset-row" data-asset-id="${a.id}"><div class="tx-ico premium-asset-ico">${assetIcon(a)}</div><div class="tx-main"><b>${esc(a.name)}</b><small>${esc(assetKindLabel(a.kind))}${a.kind==='stock'?` · P/L <span class="${pl>=0?'pos':'neg'}">${pl>=0?'+':''}${THB(pl)}</span>`:''}</small></div><div class="amt ${a.kind==='debt'?'neg':''}">${THB(a.value)}</div></button>`}).join(''):'<div class="empty">ยังไม่มีรายการในหมวดนี้</div>'}</div></section>`
}
function plan(){
  const budgets=currentBudgetMap(); const sums=monthlyExpenseByCategory();
  const budgetRows=expenseCats.map(cat=>{const b=Number(budgets[cat]||0);const a=Number(sums[cat]||0);const p=b?Math.round(a/b*100):(a>0?999:0);return `<div class="budget-row"><div class="budget-head"><div><b>${esc(cat)}</b><small>ใช้จริง ${THB(a)}</small></div><button class="budget-edit" data-budget-cat="${esc(cat)}">${b?THB(b):'ตั้งวงเงิน'}</button></div>${b?`<div class="bar budget ${p>100?'over':p>=80?'warn':''}"><i style="width:${Math.min(100,p)}%"></i></div><small class="budget-note">${p>100?`ใช้แล้ว ${THB(a)} (${p}%) · เกินวงเงิน ${THB(a-b)}`:`ใช้แล้ว ${THB(a)} (${p}%) · เหลือ ${THB(b-a)} (${Math.max(0,100-p)}%)`}</small>`:''}</div>`}).join('');
  return `${header('Plan','Budget & Goals')}<div class="title-row"><h2 class="page-title">Financial Goals</h2><button class="mini-add" id="addGoal">+ เพิ่ม</button></div><div class="goal-cards">${data.goals.length?data.goals.map(g=>{const p=Math.min(100,Math.round(effectiveGoalCurrent(g)/(Number(g.target)||1)*100));return `<button class="card goal-card" data-goal-id="${g.id}"><div><div class="label goal-label">${esc(g.name)}</div><div class="goal-value">${THB(effectiveGoalCurrent(g))}</div><small>เป้าหมาย ${THB(g.target)} · ${p}%</small><div class="bar"><i style="width:${p}%"></i></div></div><span>›</span></button>`}).join(''):'<div class="card empty">ยังไม่มีเป้าหมาย</div>'}</div>${emergencyFundPlan()}${projectPlan()}<div class="notice plan-notice"><b>วงเงินวางแผน ≠ เงินที่ถูกหัก</b><br>ใส่เป็นตัวเลขเพดานเท่านั้น เงินยังอยู่ในบัญชีเดิม จนกว่าจะบันทึกรายจ่ายจริง</div><section class="section"><div class="section-title"><h2>วงเงินวางแผนตามหมวด</h2><span>${new Date().toLocaleDateString('th-TH',{month:'long'})}</span></div><div class="card budget-list">${budgetRows}</div></section>`
}
function emergencyFundPlan(){
  const ids=data.settings?.emergencyAssetIds||[];
  const eligible=data.assets.filter(a=>a.kind==='cash');
  return `<section class="section"><div class="section-title"><h2>🛡️ เงินสำรองฉุกเฉิน</h2><span>${THB(emergencyValue())}</span></div><div class="card emergency-card"><p>เลือกจากเงินที่มีอยู่แล้ว ไม่สร้างเงินก้อนซ้ำและไม่หักออกจากบัญชี</p>${eligible.length?eligible.map(a=>`<label class="emergency-row"><input type="checkbox" data-emergency-asset="${a.id}" ${ids.includes(a.id)?'checked':''}><span>${esc(a.name)}</span><b>${THB(a.value)}</b></label>`).join(''):'<div class="empty compact">ยังไม่มีบัญชีเงินสด/ธนาคาร</div>'}</div></section>`
}
function projectPlan(){
  const pb=currentProjectBudgetMap();
  const rows=projects.filter(x=>x!=='ส่วนตัว/ทั่วไป').map(name=>{const st=projectStats(name),b=Number(pb[name]||0),p=b?Math.round(st.expense/b*100):0;return `<div class="budget-row"><div class="budget-head"><div><b>${projectIcon(name)} ${esc(name)}</b><small>รับเงินจริง ${THB(st.income)} · ใช้ ${THB(st.expense)}${st.inKind?` · ผลผลิตใช้เอง ${THB(st.inKind)}`:''} · สุทธิเงินสด ${THB(st.net)}</small></div><button class="budget-edit" data-project-budget="${esc(name)}">${b?THB(b):'ตั้งวงเงิน'}</button></div>${b?`<div class="bar budget ${p>100?'over':p>=80?'warn':''}"><i style="width:${Math.min(100,p)}%"></i></div><small class="budget-note">${p>100?`ใช้แล้ว ${THB(st.expense)} (${p}%) · เกินวงเงิน ${THB(st.expense-b)}`:`ใช้แล้ว ${THB(st.expense)} (${p}%) · เหลือ ${THB(b-st.expense)} (${Math.max(0,100-p)}%)`}</small>`:''}</div>`}).join('');
  return `<section class="section"><div class="section-title"><h2>Projects & Properties</h2><span>วงเงินวางแผน · ไม่หักเงินจริง</span></div><div class="card budget-list">${rows}</div></section>`
}
function settings(){
  const hasPin=!!(hasSecureVault||legacyPin||currentPin);
  return `${header('Settings','Privacy, Backup & App Lock')}<h2 class="page-title">ความเป็นส่วนตัวและข้อมูล</h2><div class="settings-list"><div class="setting"><div><b>App Lock</b><small>${hasPin?'เข้ารหัสข้อมูลแล้ว':'ยังไม่ได้ตั้ง PIN / Encryption'}</small></div><button id="${hasPin?'changePin':'setPin'}">${hasPin?'Change':'Set PIN'}</button></div><div class="setting"><div><b>Auto Lock</b><small>${hasPin?'ล็อกเมื่อออกจากแอปเกินเวลาที่กำหนด':'เปิดใช้ได้หลังตั้ง PIN'}</small></div><input class="toggle" id="autoLock" type="checkbox" ${data.autoLock?'checked':''} ${hasPin?'':'disabled'}></div><div class="setting"><div><b>เวลาล็อกอัตโนมัติ</b><small>หลังออกจากแอป</small></div><select id="lockMinutes" ${hasPin?'':'disabled'}><option value="1" ${data.autoLockMinutes==1?'selected':''}>1 นาที</option><option value="5" ${data.autoLockMinutes==5?'selected':''}>5 นาที</option><option value="15" ${data.autoLockMinutes==15?'selected':''}>15 นาที</option></select></div><div class="setting"><div><b>Encrypted Backup</b><small>ไฟล์สำรองเข้ารหัส AES-256-GCM และต้องใช้รหัสผ่านเพื่อเปิด</small></div><button id="exportBtn">Export</button></div><div class="setting"><div><b>Restore Encrypted Backup</b><small>นำไฟล์สำรองที่เข้ารหัสกลับเข้าแอป</small></div><button id="importBtn">Import</button></div><div class="setting"><div><b>บันทึก Snapshot เดือนนี้</b><small>เก็บ Net Worth เพื่อเทียบเดือนถัดไป</small></div><button id="snapshotBtn">Save</button></div><div class="setting"><div><b>บัญชีจ่ายหลัก</b><small>ใช้เป็นค่าเริ่มต้นเฉพาะรายการรายจ่าย</small></div><select id="defaultExpenseAsset"><option value="">อัตโนมัติ: TTB ALL FREE</option>${cashAssets().map(a=>`<option value="${a.id}" ${data.settings?.defaultExpenseAssetId===a.id?'selected':''}>${esc(a.name)}</option>`).join('')}</select></div>${hasPin?`<div class="setting"><div><b>ล็อกทันที</b><small>กลับไปหน้า PIN</small></div><button id="lockNow">Lock</button></div>`:''}</div><div class="notice"><b>Security Core · AES-256</b><br>เมื่อเปิด App Lock ข้อมูลหลักในเครื่องถูกเข้ารหัสด้วย AES-256-GCM โดยคีย์ที่ derive จาก PIN ด้วย PBKDF2-SHA-256 (210,000 iterations) แอปนี้ไม่มี Cloud Sync/Analytics/API ส่งข้อมูลการเงินออกไป ควรเก็บ Encrypted Backup ไว้ในเครื่องอย่างปลอดภัย</div><div class="setting"><div><b>Audit Trail</b><small>เก็บประวัติการเพิ่ม แก้ไข ลบ และ Reconcile ล่าสุด</small></div><span>${(data.auditLog||[]).length} รายการ</span></div><div class="version">MY FINANCE v${APP_VERSION}</div>`
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
  if(modal==='calendarDay')return calendarDaySheet();
  if(modal==='kpiDetail')return kpiDetailSheet();
  return '';
}
function kpiDetailSheet(){
  const key=detailMonth||monthKey(); const mt=monthTotals(key); const [y,m]=key.split('-').map(Number); const label=new Date(y,m-1,1).toLocaleDateString('th-TH',{month:'long',year:'numeric'});
  let title='',body='',total=0;
  if(detailType==='liquid'){
    title='◉ เงินพร้อมใช้'; const list=data.assets.filter(a=>a.kind==='cash'&&(a.liquidity||'ready')==='ready'); total=list.reduce((s,a)=>s+Number(a.value||0),0); body=list.map(a=>`<div class="detail-row"><span>${esc(a.name)}</span><b>${THB(a.value)}</b></div>`).join('')||'<div class="empty compact">ไม่มีรายการ</div>';
  }else{
    const list=data.transactions.filter(x=>(x.date||'').slice(0,7)===key);
    if(detailType==='income'){title='↑ รายรับจริง';total=mt.income;const inc=list.filter(x=>x.type==='income');const recurring=['เงินเดือนรอบ 1','เงินเดือนรอบ 2','ค่าเช่า 1','ค่าเช่า 2','รายรับพิเศษ/เงินสนับสนุน','อื่น ๆ'];const status=`<div class="income-status"><b>สถานะรายรับเดือนนี้</b>${recurring.map(c=>{const v=inc.filter(x=>x.category===c).reduce((s,x)=>s+Number(x.amount||0),0);return `<div class="detail-row"><span>${v?'✓':'○'} ${c}</span><b>${v?THB(v):'ยังไม่รับ'}</b></div>`}).join('')}</div>`;body=status+(inc.map(txRow).join('')||'<div class="empty compact">ยังไม่มีรายรับจริงเดือนนี้</div>')}
    if(detailType==='expense'){title='↓ รายจ่ายสุทธิ';total=mt.expense;body=list.filter(x=>x.type==='expense'||x.type==='reimbursement').map(txRow).join('')||'<div class="empty compact">ไม่มีรายจ่ายเดือนนี้</div>'}
    if(detailType==='cashflow'){title='↕ Cash Flow';total=mt.cashflow;body=`<div class="cashflow-equation"><b>${THB(mt.income)}</b><span>รายรับจริง</span><strong>−</strong><b>${THB(mt.expense)}</b><span>รายจ่ายสุทธิ</span><strong>=</strong><b class="${mt.cashflow>=0?'pos':'neg'}">${THB(mt.cashflow)}</b><span>Cash Flow</span></div><small class="field-hint">Transfer ระหว่างบัญชีของตัวเองไม่ถูกนับเป็นรายรับหรือรายจ่าย</small>`}
  }
  const monthNav=detailType==='liquid'?'':`<div class="detail-month"><button id="detailPrev">‹</button><b>${label}</b><button id="detailNext">›</button></div>`;
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${title}</h3>${monthNav}<div class="detail-total ${total<0?'neg':''}">${total>=0&&detailType==='cashflow'?'+':''}${THB(total)}</div><div class="card detail-list">${body}</div></div></div>`
}
function txSheet(){
  const editing=modal==='editTx';
  const x=editing?data.transactions.find(t=>t.id===editId):null;
  const type=x?.type||txDraftType||'expense';
  const cats=type==='income'?incomeCats:type==='investment'?['ลงทุน','อื่น ๆ']:type==='transfer'?['โอนเงิน']:type==='inKind'?['ผลผลิตใช้เอง']:expenseCats;
  const accountFields=type==='inKind'?`<div class="notice">มูลค่าผลผลิตที่ใช้เอง เช่น ไข่ที่กินเอง ไม่เพิ่มรายรับและไม่เพิ่มยอดเงินใน Assets</div><div class="field"><label>หมวด</label><select id="category"><option>ผลผลิตใช้เอง</option></select></div>`:type==='transfer'?`<div class="row2"><div class="field"><label>จากบัญชี</label><select id="sourceAsset" required><option value="">เลือกต้นทาง</option>${cashAssets().map(a=>`<option value="${esc(a.id)}" ${x?.sourceAssetId===a.id?'selected':''}>${esc(a.name)} · ${THB(a.value)}</option>`).join('')}</select></div><div class="field"><label>ไปบัญชี</label><select id="destinationAsset" required><option value="">เลือกปลายทาง</option>${cashAssets().map(a=>`<option value="${esc(a.id)}" ${x?.destinationAssetId===a.id?'selected':''}>${esc(a.name)} · ${THB(a.value)}</option>`).join('')}</select></div></div><small class="field-hint">โอนเงินจะลดต้นทาง เพิ่มปลายทาง และไม่ถูกนับเป็นรายรับ/รายจ่าย</small>`:`<div class="row2"><div class="field"><label>หมวด</label><select id="category">${cats.map(c=>`<option ${x?.category===c?'selected':''}>${esc(c)}</option>`).join('')}</select></div><div class="field"><label>แหล่งเงิน / บัญชี</label><select id="sourceAsset"><option value="">ไม่ผูกบัญชี</option>${orderedCashAssets(type,x?.sourceAssetId||'').map(a=>{const auto=!editing&&type==='expense'&&!x?.sourceAssetId&&a.id===(data.settings?.defaultExpenseAssetId||cashAssets().find(z=>/ttb all free/i.test(z.name||''))?.id);return `<option value="${esc(a.id)}" ${(x?.sourceAssetId===a.id||(!x?.sourceAssetId&&x?.account===a.name)||auto)?'selected':''}>${esc(a.name)} · ${THB(a.value)}</option>`}).join('')}</select><small class="field-hint">${type==='reimbursement'?'เงินคืนจะเพิ่มยอดบัญชี และหักออกจากรายจ่ายสุทธิ':'รายจ่ายหักยอด · รายรับเพิ่มยอดอัตโนมัติ'}</small></div></div>`;
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${editing?'แก้ไขรายการ':'เพิ่มรายการ'}</h3><div class="type-grid">${[['income','↑','รายรับ'],['expense','↓','รายจ่าย'],['reimbursement','↩','คืนค่าใช้จ่าย'],['transfer','⇄','โอนเงิน'],['inKind','◇','ผลผลิตใช้เอง'],['investment','↗','ลงทุน']].map(([t,i,n])=>`<button class="type ${type===t?'sel':''}" data-txtype="${t}"><strong>${i}</strong>${n}</button>`).join('')}</div><form id="txForm"><input type="hidden" id="txType" value="${type}"><div class="field"><label>จำนวนเงิน</label><input id="amount" class="amount-input money-input" inputmode="decimal" type="text" autocomplete="off" placeholder="0.00" value="${x?num(x.amount):''}" required></div>${accountFields}<div class="field"><label>โครงการ / สถานที่</label><select id="project">${projects.map(c=>`<option ${((x?.project||'ส่วนตัว/ทั่วไป')===c)?'selected':''}>${esc(c)}</option>`).join('')}</select></div><div class="field"><label>วันที่</label><input id="date" type="date" value="${x?.date||txDraftDate||today()}"></div><div class="field"><label>หมายเหตุ</label><input id="note" placeholder="ไม่บังคับ" value="${esc(x?.note||'')}"></div><button class="primary">${editing?'บันทึกการแก้ไข':'บันทึก'}</button>${editing?`<button type="button" class="danger" id="deleteTx">ลบรายการนี้</button>`:''}</form></div></div>`
}
function assetSheet(){
  const editing=modal==='editAsset'; const a=editing?data.assets.find(x=>x.id===editId):null;
  const stock=a?.kind==='stock'; const cost=Number(a?.cost??a?.value??0), value=Number(a?.value||0), pl=value-cost;
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${editing?'แก้ไขทรัพย์สิน':'เพิ่มทรัพย์สิน'}</h3><form id="assetForm"><div class="field"><label>ชื่อ</label><input id="assetName" required placeholder="เช่น TISCO หรือ KBank" value="${esc(a?.name||'')}"></div><div class="field"><label>ประเภท</label><select id="assetKind">${[['cash','เงินสด/ธนาคาร'],['stock','หุ้น/กองทุน'],['gold','ทอง'],['property','ที่ดิน/อสังหาฯ'],['vehicle','รถ/ยานพาหนะ'],['other','ทรัพย์สินอื่น'],['debt','หนี้สิน']].map(([v,n])=>`<option value="${v}" ${a?.kind===v?'selected':''}>${n}</option>`).join('')}</select></div><div id="stockFields" style="display:${stock?'block':'none'}">${`<div class="row2"><div class="field"><label>ต้นทุนรวม</label><input id="assetCost" class="money-input" type="text" inputmode="decimal" value="${num(cost)}"></div><div class="field"><label>มูลค่าปัจจุบัน / NAV วันนี้</label><input id="assetValue" class="money-input" type="text" inputmode="decimal" value="${num(value)}"></div></div><div class="row2"><div class="field"><label>จำนวนหุ้น/หน่วย (ถ้ามี)</label><input id="assetUnits" type="text" inputmode="decimal" value="${Number(a?.units||0)||''}"></div><div class="field"><label>ราคา/NAV ต่อหน่วย (ถ้ามี)</label><input id="assetPrice" type="text" inputmode="decimal" value="${Number(a?.price||0)||''}"></div></div><div class="notice"><b>Unrealized P/L:</b> <span class="${pl>=0?'pos':'neg'}">${pl>=0?'+':''}${THB(pl)}${cost?` (${pl/cost*100>=0?'+':''}${(pl/cost*100).toFixed(2)}%)`:''}</span></div>`}</div><div id="normalValueField" style="display:${stock?'none':'block'}"><div class="field"><label>มูลค่าปัจจุบัน</label><input id="assetValueNormal" class="amount-input money-input" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${a?num(a.value):''}"></div></div><div class="field"><label>สภาพคล่อง</label><select id="assetLiquidity"><option value="ready" ${(a?.liquidity||'ready')==='ready'?'selected':''}>◉ พร้อมใช้</option><option value="limited" ${a?.liquidity==='limited'?'selected':''}>◐ มีข้อจำกัด</option><option value="low" ${a?.liquidity==='low'?'selected':''}>◇ สภาพคล่องต่ำ</option></select></div><div class="field"><label>บันทึก / หมายเหตุ <span id="assetNoteCount">${String(a?.note||'').length}/150</span></label><textarea id="assetNote" maxlength="150" rows="3" placeholder="เช่น บัญชีสำรองฉุกเฉิน, ราคาประเมินล่าสุด, เงื่อนไขถอนเงิน">${esc(a?.note||'')}</textarea></div>${editing&&a?.kind==='cash'?`<button type="button" class="secondary" id="reconcileAsset">Reconcile / ปรับยอดตามเงินจริง</button>`:''}<button class="primary">${editing?'บันทึกการแก้ไข':'บันทึก'}</button>${editing?`<button type="button" class="danger" id="deleteAsset">ลบรายการนี้</button>`:''}</form></div></div>`
}
function goalSheet(){
  const editing=modal==='editGoal'; const g=editing?data.goals.find(x=>x.id===editId):null;
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${editing?'แก้ไขเป้าหมาย':'เพิ่มเป้าหมาย'}</h3><form id="goalForm"><div class="field"><label>ชื่อเป้าหมาย</label><input id="goalName" value="${esc(g?.name||'')}" placeholder="เช่น เงินเที่ยวต่างประเทศ" required></div><div class="field"><label>เป้าหมาย</label><input id="goalTarget" class="money-input" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${g?num(g.target):''}" required></div><div class="field"><label>ปัจจุบัน</label><input id="goalCurrent" class="money-input" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${g?num(g.current):''}" required></div><button class="primary">บันทึก</button>${editing?`<button type="button" class="danger" id="deleteGoal">ลบเป้าหมายนี้</button>`:''}</form></div></div>`
}
function budgetSheet(){
  const cat=editId; const current=Number(currentBudgetMap()[cat]||0);
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>ตั้งวงเงิน: ${esc(cat)}</h3><form id="budgetForm"><div class="field"><label>วงเงินวางแผนเดือนนี้</label><input id="budgetAmount" class="amount-input money-input" type="text" inputmode="decimal" autocomplete="off" value="${current?num(current):''}" placeholder="0.00" required></div><button class="primary">บันทึกวงเงิน</button>${current?`<button type="button" class="danger" id="clearBudget">ล้างวงเงินหมวดนี้</button>`:''}</form></div></div>`
}
function projectBudgetSheet(){
  const name=editId,current=Number(currentProjectBudgetMap()[name]||0);
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>ตั้งวงเงิน: ${projectIcon(name)} ${esc(name)}</h3><form id="projectBudgetForm"><div class="field"><label>วงเงินรายจ่ายเดือนนี้</label><input id="projectBudgetAmount" class="amount-input money-input" type="text" inputmode="decimal" autocomplete="off" value="${current?num(current):''}" placeholder="0.00" required></div><button class="primary">บันทึกวงเงิน</button>${current?`<button type="button" class="danger" id="clearProjectBudget">ล้างวงเงินโครงการนี้</button>`:''}</form></div></div>`
}
function reconcileSheet(){
  const a=findAsset(editId); if(!a)return '';
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>Reconcile · ${esc(a.name)}</h3><p class="field-hint">ใส่ยอดที่มีอยู่จริงตอนนี้ ระบบจะปรับ Asset โดยไม่สร้างรายรับ/รายจ่ายปลอม และเก็บบันทึกส่วนต่างไว้</p><form id="reconcileForm"><div class="field"><label>ยอดในแอป</label><input value="${num(a.value)}" disabled></div><div class="field"><label>ยอดจริงตอนนี้</label><input id="actualBalance" class="money-input" type="text" inputmode="decimal" required></div><div class="field"><label>หมายเหตุ</label><input id="reconcileNote" value="ตรวจยอดตามเงินจริง"></div><button class="primary">ปรับยอด</button></form></div></div>`
}

function pinSheet(){
  return `<div class="sheet-back" id="sheetBack"><div class="sheet"><div class="grab"></div><h3>${(hasSecureVault||legacyPin||currentPin)?'เปลี่ยน PIN / Encryption':'ตั้ง PIN / Encryption'}</h3><form id="pinForm"><div class="field"><label>PIN ใหม่ 4–6 หลัก</label><input id="newPin1" class="pin" type="password" inputmode="numeric" maxlength="6" required></div><div class="field"><label>ยืนยัน PIN</label><input id="newPin2" class="pin" type="password" inputmode="numeric" maxlength="6" required></div><button class="primary">บันทึก PIN</button></form></div></div>`
}
function updateCategoryOptions(type,selected=''){
  const c=$('#category'); if(!c)return;
  const cats=type==='income'?incomeCats:type==='investment'?['ลงทุน','อื่น ๆ']:type==='transfer'?['โอนเงิน','อื่น ๆ']:type==='inKind'?['ผลผลิตใช้เอง']:expenseCats;
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

  $$('[data-kpi]').forEach(b=>b.addEventListener('click',()=>{detailType=b.dataset.kpi;detailMonth=monthKey();modal='kpiDetail';render()}));
  $('#detailPrev')?.addEventListener('click',()=>{const [y,m]=detailMonth.split('-').map(Number);detailMonth=monthKey(new Date(y,m-2,1));render()});
  $('#detailNext')?.addEventListener('click',()=>{const [y,m]=detailMonth.split('-').map(Number);detailMonth=monthKey(new Date(y,m,1));render()});
  $$('[data-emergency-asset]').forEach(c=>c.addEventListener('change',()=>{const ids=$$('[data-emergency-asset]:checked').map(x=>x.dataset.emergencyAsset);data.settings.emergencyAssetIds=ids;save();render()}));
  $('#defaultExpenseAsset')?.addEventListener('change',e=>{data.settings.defaultExpenseAssetId=e.target.value;save()});
  $$('.money-input').forEach(el=>{el.addEventListener('blur',()=>{const v=parseMoney(el.value);if(Number.isFinite(v)&&el.value.trim()!=='')el.value=num(v)});});

  $('#openSettings')?.addEventListener('click',()=>{page='settings';render()});
  $('#quickAdd')?.addEventListener('click',()=>{txDraftDate='';txDraftType='expense';modal='tx';editId=null;render()});
  $('#seeAll')?.addEventListener('click',()=>{page='transactions';render()});
  $('#calPrev')?.addEventListener('click',()=>{const [y,m]=calendarMonth.split('-').map(Number);const d=new Date(y,m-2,1);calendarMonth=monthKey(d);render()});
  $('#calNext')?.addEventListener('click',()=>{const [y,m]=calendarMonth.split('-').map(Number);const d=new Date(y,m,1);calendarMonth=monthKey(d);render()});
  $$('[data-cal-date]').forEach(b=>b.addEventListener('click',()=>{calendarDayDate=b.dataset.calDate;modal='calendarDay';editId=null;render()}));
  $('#addOnCalendarDay')?.addEventListener('click',()=>{txDraftDate=calendarDayDate||today();txDraftType='expense';modal='tx';editId=null;render()});
  $('#toggleEmptyDay')?.addEventListener('click',()=>{const d=calendarDayDate||today();data.verifiedEmptyDays=Array.isArray(data.verifiedEmptyDays)?data.verifiedEmptyDays:[];if(data.verifiedEmptyDays.includes(d))data.verifiedEmptyDays=data.verifiedEmptyDays.filter(x=>x!==d);else data.verifiedEmptyDays.push(d);save();render()});
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
  $('#sheetBack')?.addEventListener('click',e=>{if(e.target.id==='sheetBack'){if(modal==='tx')txDraftDate='';modal=null;editId=null;render()}});
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
    data.verifiedEmptyDays=(data.verifiedEmptyDays||[]).filter(d=>d!==row.date);
    if(modal==='editTx'){
      const i=data.transactions.findIndex(x=>x.id===editId);
      if(i>=0){reverseTxAssetEffect(data.transactions[i]); data.transactions[i]=row; applyTxAssetEffect(row)}
    }else{data.transactions.push(row);applyTxAssetEffect(row)}
    audit(modal==='editTx'?'แก้ไขรายการ':'เพิ่มรายการ',`${typeLabel(row.type)} ${THB(row.amount)}`); snapshotCurrentMonth(); save(); txDraftDate=''; modal=null; editId=null; render();
  });
  $('#deleteTx')?.addEventListener('click',()=>{if(confirm('ลบรายการนี้ใช่หรือไม่?')){const old=data.transactions.find(x=>x.id===editId);reverseTxAssetEffect(old);audit('ลบรายการ',`${typeLabel(old?.type)} ${THB(old?.amount)}`);data.transactions=data.transactions.filter(x=>x.id!==editId);snapshotCurrentMonth();save();modal=null;editId=null;render()}});

  $('#assetKind')?.addEventListener('change',e=>{const isStock=e.target.value==='stock';const sf=$('#stockFields'),nf=$('#normalValueField');if(sf)sf.style.display=isStock?'block':'none';if(nf)nf.style.display=isStock?'none':'block'});
  $('#assetNote')?.addEventListener('input',e=>{const c=$('#assetNoteCount');if(c)c.textContent=`${e.target.value.length}/150`});
  $('#assetForm')?.addEventListener('submit',e=>{
    e.preventDefault(); const oldAsset=editId?findAsset(editId):null; const kind=$('#assetKind').value; const valueEl=kind==='stock'?$('#assetValue'):$('#assetValueNormal'); const row={id:editId||uid(),name:$('#assetName').value.trim(),kind,value:parseMoney(valueEl?.value),cost:kind==='stock'?parseMoney($('#assetCost')?.value||$('#assetValue').value):Number(oldAsset?.cost||0),units:kind==='stock'?parseMoney($('#assetUnits')?.value||0):0,price:kind==='stock'?parseMoney($('#assetPrice')?.value||0):0,liquid:oldAsset?.liquid!==false,liquidity:$('#assetLiquidity')?.value||oldAsset?.liquidity||'ready',note:($('#assetNote')?.value||'').trim().slice(0,150)};
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
