import { useState } from 'react';
import { AlertTriangle, ArrowUpRight, Check, FileJson2, FileText, Fingerprint, GitCommitHorizontal, Link2, Search, ShieldCheck, Wallet } from 'lucide-react';
import deployment from './deployment.json';

const packages = [
  { name: 'tiny-router', license: 'MIT', status: 'MATCH' },
  { name: 'safe-parser', license: 'Apache-2.0', status: 'MATCH' },
  { name: 'color-kit', license: 'BSD-3-Clause', status: 'MISSING' },
];

const short = (value:string) => value.length > 16 ? `${value.slice(0,8)}…${value.slice(-6)}` : value;

export default function App(){
  const [auditId,setAuditId]=useState('0');
  const [notice,setNotice]=useState('Preview uses a representative audit. Live writes unlock after verified deployment.');
  const configured=/^0x[a-fA-F0-9]{40}$/.test(deployment.contractAddress) && !/^0x0{40}$/.test(deployment.contractAddress);
  async function connect(){
    try{
      if(!configured) throw new Error('The reviewed contract has not been configured yet.');
      const eth=(window as unknown as {ethereum?:{request:(x:unknown)=>Promise<unknown>}}).ethereum;
      if(!eth) throw new Error('Install an EIP-1193 wallet to continue.');
      await eth.request({method:'eth_requestAccounts'}); setNotice('Wallet connected.');
    }catch(e){setNotice(e instanceof Error?e.message:'Connection failed.');}
  }
  return <main>
    <header>
      <div className="brand"><img src="/attribution-gap-logo.png"/><div><b>AttributionGap</b><span>Release notice auditor</span></div></div>
      <div className="top-actions"><span className="network"><i/> StudioNet</span><button className="wallet" onClick={connect}><Wallet size={17}/> Connect wallet</button></div>
    </header>
    <section className="commandbar">
      <div className="context"><span>RELEASE AUDIT</span><strong>northstar-web / v2.4.0</strong></div>
      <div className="lookup"><Search size={17}/><input aria-label="Audit ID" value={auditId} onChange={e=>setAuditId(e.target.value)} /><button onClick={()=>setNotice(`Audit ${auditId} is shown in preview mode.`)}>Load audit</button></div>
    </section>
    <div className="workspace">
      <aside className="sources">
        <p className="eyebrow">BOUND SOURCES</p>
        <h1>One release.<br/>Two artifacts.<br/><em>Every package.</em></h1>
        <div className="source"><FileJson2/><div><span>SPDX SBOM</span><b>release/sbom.spdx.json</b><small>sha256 · {short('42fe117ac0a290ff3ff67dcb')}</small></div><Check/></div>
        <div className="connector"><span/><b>same commit</b><span/></div>
        <div className="source"><FileText/><div><span>THIRD-PARTY NOTICE</span><b>THIRD_PARTY_NOTICES.md</b><small>sha256 · {short('8ad6fe312be90de09f877fcc')}</small></div><Check/></div>
        <dl><div><dt><GitCommitHorizontal/> Commit</dt><dd>53c6627…fec4ba9</dd></div><div><dt><Fingerprint/> Authority</dt><dd>acme/northstar-web</dd></div></dl>
        <button className="register"><Link2 size={17}/> Register another release</button>
      </aside>
      <section className="ledger">
        <div className="ledger-head"><div><p className="eyebrow">COVERAGE LEDGER</p><h2>3 packages declared</h2></div><div className="score"><b>67%</b><span>notice coverage</span></div></div>
        <div className="bar"><span style={{width:'67%'}}/></div>
        <div className="columns"><span>PACKAGE</span><span>DECLARED LICENSE</span><span>NOTICE MATCH</span></div>
        {packages.map((p,i)=><div className="package" key={p.name}><span className="index">0{i+1}</span><div><b>{p.name}</b><small>SBOM identity locked</small></div><code>{p.license}</code><span className={'pill '+p.status.toLowerCase()}>{p.status==='MATCH'?<Check size={14}/>:<AlertTriangle size={14}/>} {p.status}</span></div>)}
        <div className="finding"><AlertTriangle/><div><b>Attribution gap detected</b><p><strong>color-kit</strong> is present in the authenticated SBOM but no matching BSD-3-Clause attribution appears in the notice.</p></div></div>
      </section>
      <aside className="rail">
        <p className="eyebrow">AUDIT RAIL</p><div className="verdict"><span>FINAL VERDICT</span><AlertTriangle/><b>ATTRIBUTION<br/>GAPS</b><small>Finalized · majority agree</small></div>
        <ol><li className="done"><i><Check/></i><div><b>Sources fetched</b><span>Exact Raw GitHub bytes</span></div></li><li className="done"><i><Check/></i><div><b>Digests verified</b><span>Both commitments match</span></div></li><li className="done"><i><Check/></i><div><b>Coverage assessed</b><span>2 match · 1 missing</span></div></li><li className="active"><i>4</i><div><b>Result persisted</b><span>Immutable audit record</span></div></li></ol>
        <button className="explorer">View on Explorer <ArrowUpRight size={16}/></button>
        <div className="integrity"><ShieldCheck/><div><b>Fail-closed integrity</b><span>Digest mismatch and unavailable sources cannot produce a positive verdict.</span></div></div>
      </aside>
    </div>
    <footer><span>{notice}</span><span>Contract · {configured?short(deployment.contractAddress):'deployment pending'}</span></footer>
  </main>
}
