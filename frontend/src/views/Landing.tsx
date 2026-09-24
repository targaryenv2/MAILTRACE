import { useState, useEffect } from "react";
// MailTrace Landing Page v2 -- Claude artifact design
import type { Route } from "../components/Shell";
const T={bg:"#FAFAFA",surf:"#FFFFFF",bdr:"#E5E7EB",text:"#0F172A",sub:"#64748B",mute:"#94A3B8",blue:"#2563EB",blueL:"#EFF6FF",red:"#DC2626",redL:"#FEF2F2",amb:"#D97706",ambL:"#FEF3C7",grn:"#16A34A",grnL:"#F0FDF4",ind:"#4F46E5",indL:"#EEF2FF",con:"#0B0D10",conS:"#111419",conB:"#242932",conT:"#F5F7FA",conSub:"#9CA3AF"};
const rc=(r:string)=>({high:{c:T.red,b:T.redL},medium:{c:T.amb,b:T.ambL},low:{c:T.mute,b:"#F8FAFC"}}[r]??{c:T.mute,b:"#F8FAFC"});
const lc=(id:string)=>({headers:T.blue,auth:T.red,urls:T.amb,attach:T.red,ml:T.ind,relay:T.blue,graph:T.ind,chain:T.grn}[id]??T.blue);
const STEPS=[{t:"09:42:01",msg:"Parsing MIME tree & QR payloads",l:"L1"},{t:"09:42:01",msg:"Evidence preserved - SHA-256 locked",l:"L1"},{t:"09:42:02",msg:"Authentication alignment evaluated",l:"L4"},{t:"09:42:02",msg:"ML classified - PHISHING (p=0.962)",l:"L2"},{t:"09:42:03",msg:"Threat intel queried - 2 blocklist hits",l:"L6"},{t:"09:42:04",msg:"Relay reconstructed - origin: Singapore",l:"L5"},{t:"09:42:05",msg:"Campaign identified - 14 related cases",l:"L7"},{t:"09:42:05",msg:"MITRE ATT&CK mapped - T1566.002",l:"L7"},{t:"09:42:06",msg:"Verdict generated - investigation complete",l:"L9"}];
const LAYER_TABS=[{id:"headers",label:"Headers"},{id:"auth",label:"Auth"},{id:"urls",label:"URLs"},{id:"attach",label:"Files"},{id:"ml",label:"ML"},{id:"relay",label:"Relay"},{id:"graph",label:"Graph"},{id:"chain",label:"Chain"}];
const LAYER_DATA:Record<string,{title:string;rows:{k:string;v:string;risk:string;n:string}[]}>={
headers:{title:"MIME Header Extraction",rows:[{k:"From",v:"ceo@company.com",risk:"high",n:"display name spoofed"},{k:"Reply-To",v:"ceo@random-server.net",risk:"high",n:"different domain"},{k:"Subject",v:"Urgent payment request",risk:"medium",n:"urgency keyword"},{k:"Message-ID",v:"<2026082700421@random-server.net>",risk:"low",n:""},{k:"X-Mailer",v:"Sendmail 8.15.2",risk:"low",n:""}]},
auth:{title:"SPF / DKIM / DMARC",rows:[{k:"SPF",v:"FAIL",risk:"high",n:"unauthorized server"},{k:"DKIM",v:"NONE",risk:"high",n:"no signature"},{k:"DMARC",v:"FAIL",risk:"high",n:"display spoofing"},{k:"FCrDNS",v:"FAIL",risk:"medium",n:"no PTR match"},{k:"Alignment",v:"MISALIGNED",risk:"high",n:"from != envelope"}]},
urls:{title:"URL Extraction & Sandbox",rows:[{k:"Extracted",v:"3 URLs",risk:"low",n:""},{k:"URL 1",v:"bit.ly/a9x2f -> login-verify-portal.net",risk:"high",n:"redirect chain"},{k:"Punycode",v:"xn--pple-43d.com -> apple lookalike",risk:"high",n:"decoded"},{k:"Landing",v:"Credential harvesting form",risk:"high",n:"sandbox detonation"},{k:"Domain age",v:"3 days - NRD",risk:"high",n:"newly registered"}]},
attach:{title:"Attachment Forensics",rows:[{k:"Filename",v:"Invoice_Q3.pdf.exe",risk:"high",n:"double extension"},{k:"Magic bytes",v:"MZ - PE32 executable",risk:"high",n:"not a PDF"},{k:"MD5",v:"d41d8cd98f00b204e980",risk:"low",n:""},{k:"SHA-256",v:"e3b0c44298fc1c149afb",risk:"low",n:""},{k:"VirusTotal",v:"34/72 engines flagged",risk:"high",n:"malware confirmed"}]},
ml:{title:"5-Class ML Prediction",rows:[{k:"Verdict",v:"PHISHING",risk:"high",n:"p = 0.962"},{k:"Phishing",v:"96.2%",risk:"high",n:""},{k:"Malware",v:"2.1%",risk:"low",n:""},{k:"BEC",v:"1.4%",risk:"low",n:""},{k:"Suspicious",v:"0.2%",risk:"low",n:""},{k:"Benign",v:"0.1%",risk:"low",n:""}]},
relay:{title:"Relay Path Reconstruction",rows:[{k:"Origin",v:"Singapore - AS138097",risk:"high",n:"bulletproof hosting"},{k:"Transit",v:"Amsterdam - Tor exit node",risk:"high",n:"anonymizer"},{k:"Inbound",v:"Google MX - AS15169",risk:"low",n:"legitimate"},{k:"Clock skew",v:"Header timestamp forged",risk:"high",n:"tampered"},{k:"Confidence",v:"High - city precision",risk:"low",n:"94%"}]},
graph:{title:"Campaign Correlation",rows:[{k:"Campaign",v:"MT-CAMP-2026-0042",risk:"medium",n:""},{k:"Related",v:"14 incidents",risk:"high",n:"same IP infrastructure"},{k:"Targeted",v:"17 mailboxes",risk:"high",n:""},{k:"MITRE",v:"T1566.002, T1090.003, T1204.002",risk:"medium",n:""},{k:"Actor type",v:"Phishing-kit - 89.4% confidence",risk:"medium",n:""}]},
chain:{title:"Chain of Custody",rows:[{k:"Case ID",v:"MT-2026-0007",risk:"low",n:""},{k:"SHA-256",v:"7c8e4f91...a91f",risk:"low",n:"raw email fingerprint"},{k:"Merkle Root",v:"91af3e82...82bc",risk:"low",n:""},{k:"TX Hash",v:"0x1df99b15ea07dc9...",risk:"low",n:"EVM blockchain"},{k:"Timestamp",v:"2026-08-27T09:42:06Z",risk:"low",n:"immutable"}]},
};
const SHAP=[{tok:"verify",s:4.09,pos:true},{tok:"password",s:3.21,pos:true},{tok:"urgent",s:2.87,pos:true},{tok:"attachment",s:2.14,pos:true},{tok:"CEO",s:1.98,pos:true},{tok:"DMARC pass",s:1.60,pos:false},{tok:"SPF pass",s:0.92,pos:false}];
const HOPS=[{n:0,label:"Attacker Origin",place:"Singapore",ip:"103.82.44.21",asn:"AS138097",anom:"Bulletproof hosting"},{n:1,label:"Outbound Relay",place:"Amsterdam, Netherlands",ip:"185.220.101.47",asn:"AS204900",anom:"Tor exit node"},{n:2,label:"Inbound MX",place:"Google Infrastructure",ip:"209.85.128.81",asn:"AS15169",anom:null},{n:3,label:"Target Mailbox",place:"Recipient Inbox",ip:null,asn:null,anom:null}];
const PLANS=[{name:"Free",price:"",per:"/mo",desc:"For individuals",cta:"Start free",hi:false,f:["50 analyses / month","Browser extension","Basic investigation","5-class ML verdict","Community support"]},{name:"Pro",price:"",per:"/mo",desc:"For security researchers",cta:"Start free trial",hi:true,f:["500 analyses / month","Campaign correlation","API access - 10k calls","SHAP explainability","Evidence PDF export","Email support"]},{name:"Business",price:"",per:"/mo",desc:"For security teams",cta:"Talk to sales",hi:false,f:["Unlimited analyses","Team workspace & RBAC","SSO / SCIM","SIEM integrations","Audit logs","SLA guarantee"]},{name:"Enterprise",price:"Custom",per:"",desc:"For large organizations",cta:"Contact us",hi:false,f:["Private deployment","Custom data retention","Dedicated SOC support","Custom SLA","Compliance reports","On-premise option"]}];
const API_RESP={
  "verdict": "phishing",
  "risk_score": 91,
  "confidence": 0.962,
  "origin": { "place": "Singapore", "asn": "AS138097" },
  "campaign": { "id": "MT-CAMP-2026-0042", "related_cases": 14 },
  "mitre": ["T1566.002","T1090.003"]
};
const Wrap=({children,style={}}:{children:React.ReactNode;style?:React.CSSProperties})=>(
  <div style={{maxWidth:1160,margin:"0 auto",padding:"0 28px",...style}}>{children}</div>);
const EyeBrow=({children}:{children:React.ReactNode})=>(
  <p style={{fontSize:12,fontWeight:600,letterSpacing:"0.1em",textTransform:"uppercase",color:T.blue,margin:"0 0 12px"}}>{children}</p>);
const BigH=({children,center}:{children:React.ReactNode;center?:boolean})=>(
  <h2 style={{fontSize:"clamp(30px,3.5vw,46px)",fontWeight:900,letterSpacing:"-0.035em",color:T.text,lineHeight:1.08,margin:"0 0 16px",textAlign:center?"center":"left"}}>{children}</h2>);
const SubP=({children,center,mw=520}:{children:React.ReactNode;center?:boolean;mw?:number})=>(
  <p style={{fontSize:16,color:T.sub,lineHeight:1.7,maxWidth:mw,margin:center?"0 auto":"0"}}>{children}</p>);
const Spacer=({h}:{h:number})=><div style={{height:h}}/>;

function Widget({onAnalyze}:{onAnalyze:()=>void}){
  const [step,setStep]=useState(-1);
  const [done,setDone]=useState(false);
  const [runKey,setRunKey]=useState(0);
  useEffect(()=>{
    setStep(-1);setDone(false);
    const d=[500,1000,1600,2200,2900,3500,4200,4800,5500];
    const ts=d.map((t,i)=>setTimeout(()=>setStep(i),t));
    const dt=setTimeout(()=>setDone(true),6300);
    return()=>{ts.forEach(clearTimeout);clearTimeout(dt);};
  },[runKey]);
  const sc=(l:string)=>({L1:"#60A5FA",L2:"#818CF8",L4:"#FBBF24",L5:"#34D399",L6:"#4ADE80",L7:"#A78BFA",L9:"#22C55E"}[l]??"#9CA3AF");
  return(
    <div style={{background:T.con,borderRadius:16,overflow:"hidden",border:`1px solid ${T.conB}`,fontFamily:"monospace"}}>
      <div style={{background:T.conS,padding:"10px 16px",borderBottom:`1px solid ${T.conB}`,display:"flex",alignItems:"center",gap:6}}>
        {["#EF4444","#F59E0B","#22C55E"].map(c=><div key={c} style={{width:10,height:10,borderRadius:"50%",background:c}}/>)}
        <span style={{fontSize:11,color:T.conSub,marginLeft:8}}>MailTrace · Autonomous Investigation</span>
      </div>
      <div style={{margin:"14px 16px 0",background:"rgba(255,255,255,0.04)",borderRadius:8,padding:"10px 14px",border:`1px solid ${T.conB}`}}>
        <div style={{fontSize:10,color:T.conSub,marginBottom:3}}>ANALYZING</div>
        <div style={{fontSize:13,color:T.conT,fontWeight:600}}>From: ceo@company.com</div>
        <div style={{fontSize:12,color:T.conSub}}>Subject: Urgent payment request</div>
        <div style={{fontSize:11,color:"#F87171",marginTop:2}}>Attachment: Invoice_Q3.pdf.exe</div>
      </div>
      <div style={{padding:"12px 16px",minHeight:220}}>
        {STEPS.map((s,i)=>i<=step?(<div key={i} style={{display:"flex",alignItems:"flex-start",gap:8,marginBottom:6}}>
          <span style={{fontSize:10,color:T.conSub,minWidth:52}}>{s.t}</span>
          <span style={{fontSize:10,background:sc(s.l)+"22",color:sc(s.l),borderRadius:3,padding:"1px 5px",flexShrink:0}}>{s.l}</span>
          <span style={{fontSize:11,color:i===step?T.conT:T.conSub,lineHeight:1.4}}>{s.msg}</span>
        </div>):null)}
        {step>=0&&step<STEPS.length-1&&(<div style={{display:"flex",gap:6,alignItems:"center",paddingLeft:60,marginTop:2}}>
          <span style={{fontSize:18,color:"#5B8CFF",lineHeight:1}}>·</span>
          <span style={{fontSize:11,color:T.conSub}}>investigating...</span>
        </div>)}
      </div>
      {done&&(<div style={{margin:"0 16px 16px",background:"rgba(37,99,235,0.1)",border:"1px solid rgba(91,140,255,0.25)",borderRadius:10,padding:"14px 16px"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
          <div><div style={{fontSize:10,color:T.conSub,marginBottom:3}}>VERDICT</div><div style={{fontSize:20,fontWeight:800,color:"#F87171"}}>PHISHING</div></div>
          <div style={{textAlign:"right"}}><div style={{fontSize:10,color:T.conSub,marginBottom:3}}>RISK SCORE</div><div style={{fontSize:28,fontWeight:900,color:T.conT,lineHeight:1}}>91<span style={{fontSize:14,color:T.conSub,fontWeight:400}}>/100</span></div></div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"4px 16px",marginBottom:10}}>
          {[["Origin","Singapore"],["Campaign","14 cases"],["Targeted","17 mailboxes"],["MITRE","T1566.002"]].map(([k,v])=>(
            <div key={k} style={{display:"flex",justifyContent:"space-between"}}>
              <span style={{fontSize:11,color:T.conSub}}>{k}</span>
              <span style={{fontSize:11,color:T.conT,fontWeight:600}}>{v}</span>
            </div>))}
        </div>
        <div style={{background:"rgba(239,68,68,0.12)",borderRadius:6,padding:"7px 10px",fontSize:11,color:"#FCA5A5"}}>
          Quarantine estate-wide · block sender and link domains
        </div>
        <div style={{display:"flex",gap:8,marginTop:10}}>
          <button onClick={onAnalyze} style={{flex:1,background:T.blue,border:"none",borderRadius:6,padding:"7px 12px",fontSize:11,color:"#fff",cursor:"pointer",fontWeight:600}}>Analyse your email</button>
          <button onClick={()=>setRunKey(k=>k+1)} style={{background:"transparent",border:`1px solid ${T.conB}`,borderRadius:6,padding:"5px 12px",fontSize:11,color:T.conSub,cursor:"pointer"}}>Run again</button>
        </div>
      </div>)}
    </div>
  );
}
function Navbar({navigate}:{navigate:(r:Route)=>void}){
  return(<nav style={{position:"sticky",top:0,zIndex:50,background:"rgba(250,250,250,0.9)",backdropFilter:"blur(14px)",borderBottom:`1px solid ${T.conB}`}}>
    <Wrap style={{display:"flex",alignItems:"center",height:56,gap:32}}>
      <span style={{fontWeight:800,fontSize:17,letterSpacing:"-0.04em",color:T.text,marginRight:"auto"}}>Mail<span style={{color:T.blue}}>Trace</span></span>
      {([["Platform","dashboard"],["Analyse","ingest"],["Campaigns","campaigns"],["Queue","queue"],["Settings","settings"]] as [string,Route["name"]][]).map(([label,r])=>(
        <a key={label} href="#" onClick={e=>{e.preventDefault();navigate({name:r} as Route);}} style={{fontSize:14,color:T.sub,textDecoration:"none",fontWeight:500}}>{label}</a>
      ))}
      <button onClick={()=>navigate({name:"ingest"})} style={{background:T.blue,color:"#fff",border:"none",borderRadius:8,padding:"7px 18px",fontSize:14,fontWeight:600,cursor:"pointer"}}>Start free</button>
    </Wrap>
  </nav>);
}

function Hero({navigate}:{navigate:(r:Route)=>void}){
  return(<div style={{background:T.bg,padding:"80px 28px 96px"}}>
    <Wrap style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:56,alignItems:"center"}}>
      <div>
        <div style={{display:"inline-block",background:T.blueL,color:T.blue,fontSize:11,fontWeight:700,padding:"4px 12px",borderRadius:100,letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:24}}>Email Forensics Intelligence</div>
        <h1 style={{fontSize:"clamp(48px,5.5vw,68px)",fontWeight:900,letterSpacing:"-0.04em",color:T.text,lineHeight:1.0,margin:"0 0 22px"}}>Every email<br/>leaves a trail.</h1>
        <p style={{fontSize:17,color:T.sub,lineHeight:1.68,maxWidth:440,margin:"0 0 32px"}}>Analyze suspicious email. Reconstruct the infrastructure behind it. Identify connected attacks. Preserve the investigation as cryptographically verifiable evidence.</p>
        <div style={{display:"flex",gap:12,marginBottom:24,flexWrap:"wrap"}}>
          <button onClick={()=>navigate({name:"ingest"})} style={{background:T.blue,color:"#fff",border:"none",borderRadius:10,padding:"12px 24px",fontSize:15,fontWeight:600,cursor:"pointer"}}>Analyze an email</button>
          <button onClick={()=>navigate({name:"dashboard"})} style={{background:"transparent",color:T.text,border:`1.5px solid ${T.bdr}`,borderRadius:10,padding:"11px 22px",fontSize:15,fontWeight:500,cursor:"pointer"}}>Explore the platform</button>
        </div>
        <p style={{fontSize:13,color:T.mute,margin:0}}>Trained on 26,216 real emails · 10 forensic layers · 50,021 ML features</p>
      </div>
      <Widget onAnalyze={()=>navigate({name:"ingest"})}/>
    </Wrap>
  </div>);
}

function EmailUnfolds(){
  const [active,setActive]=useState("headers");
  const data=LAYER_DATA[active];
  const pc=lc(active);
  return(<div style={{background:T.surf,borderTop:`1px solid ${T.conB}`,borderBottom:`1px solid ${T.conB}`,padding:"88px 28px"}}>
    <Wrap>
      <EyeBrow>Forensic Artifact</EyeBrow>
      <BigH>Email is not just a message.</BigH>
      <SubP mw={540}>Every email is a layered forensic artifact. MailTrace dissects all 8 forensic layers simultaneously.</SubP>
      <Spacer h={32}/>
      <div style={{background:"#F8FAFC",border:`1px solid ${T.conB}`,borderRadius:10,padding:"13px 18px",marginBottom:20,maxWidth:600,fontFamily:"monospace",fontSize:13,lineHeight:1.9}}>
        <div><span style={{color:T.mute}}>From:</span> <span style={{color:T.red,fontWeight:600}}>ceo@company.com</span> <span style={{color:T.mute,fontSize:11}}>(display name spoofed)</span></div>
        <div><span style={{color:T.mute}}>Subject:</span> <span style={{color:T.text}}>Urgent payment request</span></div>
        <div><span style={{color:T.mute}}>Attach:</span> <span style={{color:T.red}}>Invoice_Q3.pdf.exe</span></div>
      </div>
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:20}}>
        {LAYER_TABS.map(tab=>{const tc=lc(tab.id);const isA=tab.id===active;return(
          <button key={tab.id} onClick={()=>setActive(tab.id)} style={{background:isA?tc:"transparent",color:isA?"#fff":T.sub,border:`1.5px solid ${T.bdr}`,borderRadius:8,padding:"6px 16px",fontSize:13,fontWeight:600,cursor:"pointer"}}>{tab.label}</button>
        );})}
      </div>
      <div style={{background:"#F8FAFC",border:`1.5px solid ${pc}28`,borderRadius:12,padding:22,maxWidth:680}}>
        <div style={{fontSize:11,fontWeight:700,letterSpacing:"0.08em",textTransform:"uppercase",color:pc,marginBottom:16}}>{data.title}</div>
        <div style={{display:"flex",flexDirection:"column",gap:6}}>
          {data.rows.map((row,i)=>{const {c,b}=rc(row.risk);return(
            <div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"8px 12px",background:T.surf,borderRadius:8,border:`1px solid ${T.conB}`}}>
              <span style={{fontSize:12,color:T.sub,minWidth:92,fontFamily:"monospace",fontWeight:500,flexShrink:0}}>{row.k}</span>
              <span style={{fontSize:12,color:T.text,fontFamily:"monospace",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{row.v}</span>
              {row.risk!=="low"&&<span style={{fontSize:11,background:b,color:c,borderRadius:4,padding:"1px 7px",fontWeight:700,flexShrink:0}}>{row.risk==="high"?"HIGH":"MED"}</span>}
              {row.n&&<span style={{fontSize:11,color:T.mute,flexShrink:0}}>{row.n}</span>}
            </div>);})}
        </div>
      </div>
    </Wrap>
  </div>);
}
function Shap(){
  const max=Math.max(...SHAP.map(s=>s.s));
  return(<div style={{padding:"88px 28px"}}>
    <Wrap style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:72,alignItems:"center"}}>
      <div>
        <EyeBrow>ML & Explainability - Layer 2</EyeBrow>
        <BigH>Understand the decision.</BigH>
        <SubP>Not just a verdict - a transparent explanation. Every classification exposes top signals via SHAP feature attribution on 50,021-feature sparse vectors.</SubP>
        <Spacer h={32}/>
        <div style={{background:T.redL,border:`1.5px solid ${T.red}22`,borderRadius:16,padding:"24px 28px",display:"inline-block"}}>
          <div style={{fontSize:11,color:T.sub,fontWeight:600,textTransform:"uppercase",marginBottom:8}}>Risk Score</div>
          <div style={{fontSize:68,fontWeight:900,color:T.red,lineHeight:1}}>91</div>
          <div style={{fontSize:14,color:T.red,fontWeight:700,marginBottom:14}}>PHISHING</div>
          {[["ML","38"],["Auth","22"],["Network","14"],["Intel","11"],["Heuristics","6"]].map(([k,v])=>(
            <div key={k} style={{display:"flex",justifyContent:"space-between",gap:24,marginBottom:4}}>
              <span style={{fontSize:13,color:T.sub}}>{k}</span>
              <span style={{fontSize:13,fontWeight:700,color:T.text}}>+{v}</span>
            </div>))}
        </div>
      </div>
      <div>
        <div style={{fontSize:14,fontWeight:700,color:T.text,marginBottom:4}}>Top contributing signals</div>
        <div style={{fontSize:13,color:T.sub,marginBottom:24}}>Logistic regression · SHAP local explanation · cosine-deduplicated corpus</div>
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          {SHAP.map((s,i)=>(<div key={i}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:5}}>
              <span style={{fontSize:13,fontFamily:"monospace",color:T.text,fontWeight:600}}>"{s.tok}"</span>
              <span style={{fontSize:14,fontWeight:800,color:s.pos?T.red:T.grn}}>{s.pos?"+":"-"}{s.s.toFixed(2)}</span>
            </div>
            <div style={{background:"#F1F5F9",borderRadius:4,height:7,overflow:"hidden"}}>
              <div style={{width:`${(s.s/max)*100}%`,height:"100%",background:s.pos?T.red:T.grn,borderRadius:4}}/>
            </div>
          </div>))}
        </div>
      </div>
    </Wrap>
  </div>);
}

function RelaySection(){
  return(<div style={{background:T.surf,borderTop:`1px solid ${T.conB}`,borderBottom:`1px solid ${T.conB}`,padding:"88px 28px"}}>
    <Wrap style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:72,alignItems:"center"}}>
      <div>
        {HOPS.map((hop,i)=>(<div key={i} style={{display:"flex",gap:18}}>
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",minWidth:26}}>
            <div style={{width:24,height:24,borderRadius:"50%",background:hop.anom?T.red:i===HOPS.length-1?T.grn:T.blue,border:"2.5px solid white",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:"white"}}>{hop.n}</div>
            {i<HOPS.length-1&&<div style={{width:2,flex:1,background:T.bdr,minHeight:40}}/>}
          </div>
          <div style={{paddingBottom:i<HOPS.length-1?28:0,flex:1}}>
            <div style={{fontSize:11,fontWeight:700,textTransform:"uppercase",color:T.mute,marginBottom:3}}>Hop {hop.n} · {hop.label}</div>
            <div style={{fontSize:15,fontWeight:700,color:T.text}}>{hop.place}</div>
            {hop.ip&&<div style={{fontSize:12,color:T.sub,fontFamily:"monospace"}}>{hop.ip} · {hop.asn}</div>}
            {hop.anom&&<div style={{display:"inline-block",fontSize:11,background:T.redL,color:T.red,borderRadius:4,padding:"2px 8px",marginTop:4,fontWeight:600}}>! {hop.anom}</div>}
          </div>
        </div>))}
      </div>
      <div>
        <EyeBrow>Layer 5 - Network Forensics</EyeBrow>
        <BigH>Follow the infrastructure.</BigH>
        <SubP>MailTrace inverts the received header chain, geolocates every relay server, and identifies the earliest reliable public origin.</SubP>
        <Spacer h={28}/>
        <div style={{background:"#F8FAFC",border:`1px solid ${T.conB}`,borderRadius:12,padding:"20px 24px"}}>
          <div style={{fontSize:11,fontWeight:700,textTransform:"uppercase",color:T.sub,marginBottom:12}}>Earliest reliable origin</div>
          <div style={{fontSize:22,fontWeight:900,color:T.text,marginBottom:10}}>Singapore, SG</div>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
            <span style={{fontSize:13,color:T.sub}}>Confidence</span><span style={{fontSize:13,fontWeight:700}}>94%</span>
          </div>
          <div style={{background:"#E2E8F0",borderRadius:4,height:6,marginBottom:14}}>
            <div style={{width:"94%",height:"100%",background:T.blue,borderRadius:4}}/>
          </div>
          {[["ASN","AS138097"],["ISP","Zenlayer"],["Anomalies","2 detected"]].map(([k,v])=>(
            <div key={k} style={{display:"flex",justifyContent:"space-between",marginBottom:5}}>
              <span style={{fontSize:13,color:T.sub}}>{k}</span>
              <span style={{fontSize:13,fontWeight:600,color:k==="Anomalies"?T.red:T.text}}>{v}</span>
            </div>))}
        </div>
      </div>
    </Wrap>
  </div>);
}
function Evidence(){
  const steps=["Evidence captured","SHA-256 hash","Merkle root","Smart contract","Verified"];
  return(<div style={{padding:"88px 28px"}}>
    <Wrap>
      <div style={{textAlign:"center",marginBottom:48}}>
        <EyeBrow>Layer 8 - Chain of Custody</EyeBrow>
        <BigH center>Evidence that holds up.</BigH>
        <Spacer h={12}/>
        <SubP center mw={500}>Every investigation is sealed with a Merkle root and anchored to an EVM-compatible blockchain - cryptographically verifiable proof for courts, regulators, and insurers.</SubP>
      </div>
      <div style={{display:"flex",justifyContent:"center",alignItems:"center",flexWrap:"wrap",marginBottom:48}}>
        {steps.map((s,i)=>(<div key={s} style={{display:"flex",alignItems:"center"}}>
          <div style={{textAlign:"center",padding:"0 6px"}}>
            <div style={{width:36,height:36,borderRadius:"50%",background:i===steps.length-1?T.grnL:T.blueL,border:`2px solid ${i===steps.length-1?T.grn:T.blue}`,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 8px",fontSize:13,fontWeight:700,color:i===steps.length-1?T.grn:T.blue}}>
              {i===steps.length-1?"v":i+1}
            </div>
            <div style={{fontSize:12,color:T.sub,maxWidth:76,textAlign:"center"}}>{s}</div>
          </div>
          {i<steps.length-1&&<div style={{width:28,height:1,background:T.bdr,flexShrink:0,margin:"0 4px 16px"}}/>}
        </div>))}
      </div>
      <div style={{maxWidth:520,margin:"0 auto",background:T.con,borderRadius:16,padding:"28px 32px",border:`1px solid ${T.conB}`,fontFamily:"monospace"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:20}}>
          <div><div style={{fontSize:10,color:T.conSub,marginBottom:4}}>CASE</div><div style={{fontSize:20,fontWeight:800,color:T.conT}}>MT-2026-0007</div></div>
          <div style={{background:"rgba(22,163,74,0.14)",border:"1px solid rgba(22,163,74,0.35)",borderRadius:8,padding:"6px 14px"}}>
            <span style={{fontSize:12,fontWeight:700,color:"#4ADE80"}}>VERIFIED</span>
          </div>
        </div>
        <div style={{borderTop:`1px solid ${T.conB}`,paddingTop:16,display:"flex",flexDirection:"column",gap:12}}>
          {[{k:"Evidence hash",v:"7c8e4f91...a91f"},{k:"Merkle root",v:"91af3e82...82bc"},{k:"TX hash",v:"0x1df99b15ea07dc9..."},{k:"Block",v:"#21,847,392 · Polygon mainnet"},{k:"Timestamp",v:"2026-08-27T09:42:06.000Z"}].map(({k,v})=>(
            <div key={k}><div style={{fontSize:10,color:T.conSub,textTransform:"uppercase",marginBottom:2}}>{k}</div><div style={{fontSize:12,color:T.conT,wordBreak:"break-all",lineHeight:1.4}}>{v}</div></div>
          ))}
        </div>
      </div>
    </Wrap>
  </div>);
}

function APISection(){
  return(<div style={{background:T.surf,borderTop:`1px solid ${T.conB}`,borderBottom:`1px solid ${T.conB}`,padding:"88px 28px"}}>
    <Wrap style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:72,alignItems:"start"}}>
      <div>
        <EyeBrow>API Platform - Layer 10</EyeBrow>
        <BigH>Build MailTrace into your security stack.</BigH>
        <SubP>One API call. Full investigation. Verdict, origin, campaign correlation, and MITRE ATT&CK mappings in a single response. 28 endpoints. Full OpenAPI spec.</SubP>
        <Spacer h={32}/>
        {[{icon:"🖥",k:"Dashboard",v:"Full investigation workspace for analysts"},{icon:"⚡",k:"API",v:"Programmatic access for developers"},{icon:"🔌",k:"Extension",v:"Inline Gmail and Outlook analysis"}].map(({icon,k,v})=>(
          <div key={k} style={{display:"flex",gap:14,alignItems:"flex-start",marginBottom:16}}>
            <div style={{width:36,height:36,borderRadius:8,background:T.blueL,display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,flexShrink:0}}>{icon}</div>
            <div><div style={{fontSize:14,fontWeight:700,color:T.text}}>{k}</div><div style={{fontSize:13,color:T.sub}}>{v}</div></div>
          </div>))}
      </div>
      <div>
        <div style={{background:T.con,borderRadius:"12px 12px 0 0",padding:"14px 20px",border:`1px solid ${T.conB}`,borderBottom:"none"}}>
          <div style={{fontSize:11,color:"#60A5FA",fontFamily:"monospace",marginBottom:8}}>POST /api/ingest</div>
          <pre style={{margin:0,fontSize:12,color:T.conSub,fontFamily:"monospace",lineHeight:1.6}}>
{`{
  "email": "<raw .eml>"
}`}
          </pre>
        </div>
        <div style={{background:"#0D1117",borderRadius:"0 0 12px 12px",padding:"14px 20px",border:`1px solid ${T.conB}`,borderTop:"1px solid rgba(255,255,255,0.05)"}}>
          <div style={{fontSize:11,color:"#4ADE80",fontFamily:"monospace",marginBottom:8}}>200 OK - ~420ms</div>
          <pre style={{margin:0,fontSize:12,color:"#E2E8F0",fontFamily:"monospace",lineHeight:1.65,overflow:"auto"}}>{API_RESP}</pre>
        </div>
      </div>
    </Wrap>
  </div>);
}
function Pricing({navigate}:{navigate:(r:Route)=>void}){
  return(<div style={{padding:"88px 28px"}}>
    <Wrap>
      <div style={{textAlign:"center",marginBottom:48}}>
        <EyeBrow>Pricing</EyeBrow>
        <BigH center>Start free. Scale when ready.</BigH>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:18,alignItems:"start"}}>
        {PLANS.map(p=>(<div key={p.name} style={{background:p.hi?T.blue:T.surf,border:`1.5px solid ${T.bdr}`,borderRadius:14,padding:"26px 22px",boxShadow:p.hi?`0 8px 40px ${T.blue}22`:"none"}}>
          {p.hi&&<div style={{fontSize:10,fontWeight:700,textTransform:"uppercase",color:"rgba(255,255,255,0.6)",marginBottom:10}}>Most popular</div>}
          <div style={{fontSize:18,fontWeight:800,color:p.hi?"#fff":T.text,marginBottom:4}}>{p.name}</div>
          <div style={{fontSize:13,color:p.hi?"rgba(255,255,255,0.6)":T.sub,marginBottom:18}}>{p.desc}</div>
          <div style={{display:"flex",alignItems:"baseline",gap:2,marginBottom:20}}>
            <span style={{fontSize:34,fontWeight:900,color:p.hi?"#fff":T.text}}>{p.price}</span>
            <span style={{fontSize:13,color:p.hi?"rgba(255,255,255,0.55)":T.sub}}>{p.per}</span>
          </div>
          <button onClick={()=>navigate({name:"ingest"})} style={{width:"100%",padding:10,borderRadius:8,fontSize:14,fontWeight:600,cursor:"pointer",background:p.hi?"#fff":"transparent",color:T.blue,border:p.hi?"none":`1.5px solid ${T.bdr}`,marginBottom:18}}>{p.cta}</button>
          <div style={{display:"flex",flexDirection:"column",gap:7}}>
            {p.f.map(feat=>(<div key={feat} style={{display:"flex",gap:8,alignItems:"flex-start"}}>
              <span style={{color:p.hi?"rgba(255,255,255,0.8)":T.grn,fontSize:13,flexShrink:0}}>&#10003;</span>
              <span style={{fontSize:13,color:p.hi?"rgba(255,255,255,0.8)":T.sub}}>{feat}</span>
            </div>))}
          </div>
        </div>))}
      </div>
    </Wrap>
  </div>);
}

function Footer({navigate}:{navigate:(r:Route)=>void}){
  const cols:Record<string,string[]>={
    Platform:["Dashboard","Cases","Investigator","Evidence","Reports","Changelog"],
    Developers:["API Reference","Quickstart","Webhooks","SDKs","Rate limits","Status"],
    Company:["About","Blog","Research","Careers","Security","Press"],
    Legal:["Terms","Privacy","Cookies","GDPR","Security Policy"],
  };
  return(<footer style={{background:"#0F172A",padding:"64px 28px 40px"}}>
    <Wrap>
      <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr",gap:40,marginBottom:48}}>
        <div>
          <div style={{fontSize:20,fontWeight:900,color:"#fff",marginBottom:12}}>Mail<span style={{color:T.blue}}>Trace</span></div>
          <p style={{fontSize:14,color:"#475569",lineHeight:1.65,maxWidth:230,margin:"0 0 20px"}}>Email forensics intelligence. Investigate, correlate, and preserve evidence automatically.</p>
          <div style={{fontSize:12,color:"#334155"}}>10 forensic layers · Blockchain custody · MITRE ATT&CK</div>
        </div>
        {Object.entries(cols).map(([h,links])=>(<div key={h}>
          <div style={{fontSize:11,fontWeight:700,letterSpacing:"0.08em",textTransform:"uppercase",color:"#475569",marginBottom:16}}>{h}</div>
          <div style={{display:"flex",flexDirection:"column",gap:9}}>
            {links.map(l=><a key={l} href="#" style={{fontSize:14,color:"#64748B",textDecoration:"none"}}>{l}</a>)}
          </div>
        </div>))}
      </div>
      <div style={{borderTop:"1px solid #1E293B",paddingTop:24,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <span style={{fontSize:13,color:"#475569"}}>2026 MailTrace. Email forensics for the intelligence age.</span>
        <button onClick={()=>navigate({name:"ingest"})} style={{fontSize:13,color:T.blue,background:"none",border:"none",cursor:"pointer",fontWeight:600}}>Start analysing</button>
      </div>
    </Wrap>
  </footer>);
}

export function Landing({navigate}:{navigate:(r:Route)=>void}){
  return(<div style={{background:T.bg,fontFamily:"-apple-system,BlinkMacSystemFont,'Inter',system-ui,sans-serif",color:T.text,margin:0,padding:0,minHeight:"100vh"}}>
    <Navbar navigate={navigate}/>
    <Hero navigate={navigate}/>
    <EmailUnfolds/>
    <Shap/>
    <RelaySection/>
    <Evidence/>
    <APISection/>
    <Pricing navigate={navigate}/>
    <Footer navigate={navigate}/>
  </div>);
}
