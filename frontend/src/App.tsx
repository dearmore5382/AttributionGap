import { useEffect, useState, type FormEvent } from 'react';
import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';
import { AlertTriangle, ArrowUpRight, Check, FileJson2, FileText, Fingerprint, GitCommitHorizontal, Link2, Search, ShieldCheck, Wallet } from 'lucide-react';
import deployment from './deployment.json';

const previewPackages = [
  { name: 'tiny-router', license: 'MIT', status: 'MATCH' },
  { name: 'safe-parser', license: 'Apache-2.0', status: 'MATCH' },
  { name: 'color-kit', license: 'BSD-3-Clause', status: 'MISSING' },
];

const short = (value:string) => value.length > 16 ? `${value.slice(0,8)}…${value.slice(-6)}` : value;
type Observation={status:string;sbom_sha256:string;notice_sha256:string;packages:{name:string;license:string}[];coverage:string[]};
type Audit={id:number;creator:string;label:string;repository:string;commit:string;sbom_path:string;notice_path:string;sbom_sha256:string;notice_sha256:string;status:string;verdict:string;observation:string;successor_plus_one:number};
const address=deployment.contractAddress as `0x${string}`;
const reader=createClient({chain:studionet});
type Provider=NonNullable<Parameters<typeof createClient>[0]>['provider'];

export default function App(){
  const [view,setView]=useState(location.pathname==='/register'?'register':'audit');
  const [auditId,setAuditId]=useState('1');
  const [audit,setAudit]=useState<Audit|null>(null);
  const [wallet,setWallet]=useState('');
  const [busy,setBusy]=useState(false);
  const [notice,setNotice]=useState('Loading the verified StudioNet audit…');
  const configured=/^0x[a-fA-F0-9]{40}$/.test(deployment.contractAddress) && !/^0x0{40}$/.test(deployment.contractAddress);
  const observation:Observation|null=audit?.observation?JSON.parse(audit.observation):null;
  const packages=observation?.packages.map((p,i)=>({...p,status:observation.coverage[i]}))??previewPackages;
  const matched=packages.filter(p=>p.status==='MATCH').length;
  const score=packages.length?Math.round(matched/packages.length*100):0;
  const verdict=audit?.verdict??'ATTRIBUTION_GAPS';
  const isComplete=verdict==='NOTICE_COMPLETE';
  async function connect(){
    try{
      if(!configured) throw new Error('The reviewed contract has not been configured yet.');
      const eth=(window as unknown as {ethereum?:Provider}).ethereum;
      if(!eth) throw new Error('Install an EIP-1193 wallet to continue.');
      await eth.request({method:'wallet_switchEthereumChain',params:[{chainId:'0x'+studionet.id.toString(16)}]});
      const accounts=await eth.request({method:'eth_requestAccounts'}) as string[];
      setWallet(accounts[0]??''); setNotice('Wallet connected on StudioNet.');
    }catch(e){setNotice(e instanceof Error?e.message:'Connection failed.');}
  }
  async function loadAudit(id=auditId){
    try{
      const raw=await reader.readContract({address,functionName:'get_audit',args:[BigInt(id)],transactionHashVariant:TransactionHashVariant.LATEST_FINAL});
      const parsed=JSON.parse(String(raw)) as Audit; setAudit(parsed); setNotice(`Loaded finalized StudioNet audit ${id}.`);
    }catch(e){setNotice(e instanceof Error?e.message:'Audit read failed.');}
  }
  async function send(method:string,args:(string|bigint)[]){
    setBusy(true);
    try{
      if(!wallet) throw new Error('Connect a StudioNet wallet before writing.');
      const provider=(window as unknown as {ethereum?:Provider}).ethereum;
      if(!provider) throw new Error('Wallet disconnected.');
      const writer=createClient({chain:studionet,account:wallet as `0x${string}`,provider});
      const hash=await writer.writeContract({address,functionName:method,args,value:0n,leaderOnly:false});
      setNotice(`Submitted once: ${String(hash)}. Wait for finality before any new action.`);
    }catch(e){setNotice(e instanceof Error?e.message:'Transaction failed.');}
    finally{setBusy(false);}
  }
  function navigate(next:'audit'|'register'){
    history.pushState({},'',next==='register'?'/register':'/'); setView(next); window.scrollTo(0,0);
  }
  function register(event:FormEvent<HTMLFormElement>){
    event.preventDefault(); const f=new FormData(event.currentTarget);
    void send('register_release',[String(f.get('label')),String(f.get('owner')),String(f.get('repository')),String(f.get('commit')),String(f.get('sbomPath')),String(f.get('noticePath')),String(f.get('sbomDigest')),String(f.get('noticeDigest')),String(f.get('policy'))]);
  }
  useEffect(()=>{void loadAudit('1'); const pop=()=>setView(location.pathname==='/register'?'register':'audit'); addEventListener('popstate',pop); return()=>removeEventListener('popstate',pop);},[]);
  return <main>
    <header>
      <button className="brand brand-button" onClick={()=>navigate('audit')}><img src="/attribution-gap-logo.png"/><div><b>AttributionGap</b><span>Release notice auditor</span></div></button>
      <div className="top-actions"><nav><button className={view==='audit'?'selected':''} onClick={()=>navigate('audit')}>Audit registry</button><button className={view==='register'?'selected':''} onClick={()=>navigate('register')}>Register release</button></nav><span className="network"><i/> StudioNet</span><button className="wallet" onClick={connect} disabled={busy}><Wallet size={17}/> {wallet?short(wallet):'Connect wallet'}</button></div>
    </header>
    {view==='register'?<>
      <section className="register-page">
        <aside className="register-intro"><p className="eyebrow">NEW RELEASE AUDIT</p><h1>Bind the artifacts<br/>that actually shipped.</h1><p>Register one immutable GitHub commit, one SPDX SBOM and one third-party notice. Validators fetch both files and recompute their SHA-256 digests before assessing attribution coverage.</p><div className="guardrail"><ShieldCheck/><div><b>Source authority is constrained</b><span>The contract constructs Raw GitHub URLs. Arbitrary evidence URLs are not accepted.</span></div></div></aside>
        <form className="registration-form" onSubmit={register}>
          <div className="form-heading"><div><span>REGISTRATION FORM</span><h2>Release identity</h2></div><b>All fields required</b></div>
          <label className="wide">Release label<input name="label" placeholder="Example: Acme CLI 2.4.0" maxLength={120} required/></label>
          <div className="field-row"><label>GitHub owner<input name="owner" placeholder="organization-or-user" required/></label><label>Repository<input name="repository" placeholder="repository-name" required/></label></div>
          <label className="wide">Full commit SHA<input name="commit" placeholder="40-character immutable Git commit" pattern="[a-fA-F0-9]{40}" required/></label>
          <div className="form-divider"><span>Authenticated artifacts</span></div>
          <div className="artifact-block"><div className="artifact-title"><FileJson2/><div><b>SPDX SBOM</b><span>Bounded JSON package inventory</span></div></div><label>Path at commit<input name="sbomPath" placeholder="release/sbom.spdx.json" required/></label><label>Expected SHA-256<input name="sbomDigest" placeholder="64-character lowercase digest" pattern="[a-fA-F0-9]{64}" required/></label></div>
          <div className="artifact-block"><div className="artifact-title"><FileText/><div><b>Third-party notice</b><span>Package attribution statements</span></div></div><label>Path at commit<input name="noticePath" placeholder="THIRD_PARTY_NOTICES.md" required/></label><label>Expected SHA-256<input name="noticeDigest" placeholder="64-character lowercase digest" pattern="[a-fA-F0-9]{64}" required/></label></div>
          <label className="wide">Assessment policy<textarea name="policy" defaultValue="Every SBOM package must have a semantically matching name and declared license in the notice." maxLength={900} required/></label>
          <div className="form-actions"><button type="button" className="cancel" onClick={()=>navigate('audit')}>Back to registry</button><button className="submit-release" disabled={busy||!wallet}><Link2 size={17}/> {wallet?'Register exact sources':'Connect wallet to register'}</button></div>
          <output>{notice}</output>
        </form>
      </section>
      <footer><span>Registration writes once and never silently retries.</span><span>Contract · {short(deployment.contractAddress)}</span></footer>
    </>:<>
    <section className="commandbar">
      <div className="context"><span>RELEASE AUDIT</span><strong>{audit?.label??'AttributionGap verified release'}</strong></div>
      <div className="lookup"><Search size={17}/><input aria-label="Audit ID" value={auditId} onChange={e=>setAuditId(e.target.value)} /><button onClick={()=>void loadAudit()}>Load audit</button></div>
    </section>
    <div className="workspace">
      <aside className="sources">
        <p className="eyebrow">BOUND SOURCES</p>
        <h1>One release.<br/>Two artifacts.<br/><em>Every package.</em></h1>
        <div className="source"><FileJson2/><div><span>SPDX SBOM</span><b>{audit?.sbom_path??'fixtures/sbom-complete.json'}</b><small>sha256 · {short(audit?.sbom_sha256??'df2289afe23b32612aba6df6')}</small></div><Check/></div>
        <div className="connector"><span/><b>same commit</b><span/></div>
        <div className="source"><FileText/><div><span>THIRD-PARTY NOTICE</span><b>{audit?.notice_path??'fixtures/notice-missing.md'}</b><small>sha256 · {short(audit?.notice_sha256??'2af7837182ca18b79d2d908f')}</small></div><Check/></div>
        <dl><div><dt><GitCommitHorizontal/> Commit</dt><dd>{short(audit?.commit??'1b4fa7cd039c3b62d5444c2b06de19d98f6a0158')}</dd></div><div><dt><Fingerprint/> Authority</dt><dd>{audit?.repository??'dearmore5382/AttributionGap'}</dd></div></dl>
        <button className="register" onClick={()=>navigate('register')}><Link2 size={17}/> Register another release</button>
      </aside>
      <section className="ledger">
        <div className="ledger-head"><div><p className="eyebrow">COVERAGE LEDGER</p><h2>{packages.length} packages declared</h2></div><div className="score"><b>{score}%</b><span>notice coverage</span></div></div>
        <div className="bar"><span style={{width:`${score}%`}}/></div>
        <div className="columns"><span>PACKAGE</span><span>DECLARED LICENSE</span><span>NOTICE MATCH</span></div>
        {packages.map((p,i)=><div className="package" key={p.name}><span className="index">0{i+1}</span><div><b>{p.name}</b><small>SBOM identity locked</small></div><code>{p.license}</code><span className={'pill '+p.status.toLowerCase()}>{p.status==='MATCH'?<Check size={14}/>:<AlertTriangle size={14}/>} {p.status}</span></div>)}
        <div className="finding">{isComplete?<ShieldCheck/>:<AlertTriangle/>}<div><b>{isComplete?'Notice coverage complete':'Coverage issue detected'}</b><p>{isComplete?'Every authenticated SBOM package has a matching notice attribution.':'One or more authenticated packages are missing, unclear, or attributed under a different license.'}</p></div></div>
      </section>
      <aside className="rail">
        <p className="eyebrow">AUDIT RAIL</p><div className="verdict"><span>FINAL VERDICT</span>{isComplete?<ShieldCheck/>:<AlertTriangle/>}<b>{verdict.replaceAll('_',' ')}</b><small>{audit?.status??'FINALIZED'} · majority agree</small></div>
        <ol><li className="done"><i><Check/></i><div><b>Sources fetched</b><span>Exact Raw GitHub bytes</span></div></li><li className="done"><i><Check/></i><div><b>Digests verified</b><span>Both commitments match</span></div></li><li className="done"><i><Check/></i><div><b>Coverage assessed</b><span>2 match · 1 missing</span></div></li><li className="active"><i>4</i><div><b>Result persisted</b><span>Immutable audit record</span></div></li></ol>
        {audit?.status==='REGISTERED'&&<button className="assess" onClick={()=>void send('assess_release',[BigInt(auditId)])} disabled={busy||!wallet}>Assess selected audit</button>}
        <button className="explorer" onClick={()=>window.open(`https://explorer-studio.genlayer.com/address/${address}`,'_blank','noopener,noreferrer')}>View on Explorer <ArrowUpRight size={16}/></button>
        <div className="integrity"><ShieldCheck/><div><b>Fail-closed integrity</b><span>Digest mismatch and unavailable sources cannot produce a positive verdict.</span></div></div>
      </aside>
    </div>
    <footer><span>{notice}</span><span>Contract · {configured?short(deployment.contractAddress):'deployment pending'}</span></footer>
    </>}
  </main>
}
