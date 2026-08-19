
// ---------------------------------------------------------------
// DATA — Enterprise ATT&CK, condensed high-yield set for analyst interview prep
// ---------------------------------------------------------------
const TACTICS = [
{id:"TA0043", name:"Reconnaissance", desc:"Adversary is gathering information they can use to plan future operations.",
 techniques:[
  {id:"T1595", name:"Active Scanning", desc:"Probing victim infrastructure (IP blocks, vulnerability scans) to find exploitable targets.", detect:"Flag scan-pattern traffic (many ports/hosts in short bursts) from external IPs at the perimeter."},
  {id:"T1592", name:"Gather Victim Host Information", desc:"Collecting details on hardware, software, and firmware running in the target environment.", detect:"Hard to detect directly — focus on limiting what's exposed via banners, job postings, and public DNS."},
  {id:"T1589", name:"Gather Victim Identity Information", desc:"Harvesting employee names, emails, and credentials for use in phishing or password attacks.", detect:"Monitor for credential-stuffing attempts and breach-dump exposure of your domain's emails."},
  {id:"T1598", name:"Phishing for Information", desc:"Sending deceptive messages to elicit sensitive info rather than deploy malware directly.", detect:"Email gateway analytics on reply-baiting patterns; user-reported suspicious mail."},
  {id:"T1593", name:"Search Open Websites/Domains", desc:"Using social media, code repos, and search engines to profile the organization.", detect:"Not directly detectable — reduce exposure via OSINT hygiene and employee awareness training."},
  {id:"T1591", name:"Gather Victim Org Information", desc:"Researching org structure, business relationships, and physical locations.", detect:"Same as above — a hygiene/awareness control, not a log-detection control."}
 ]},
{id:"TA0042", name:"Resource Development", desc:"Adversary is establishing resources (infrastructure, accounts, capabilities) to support operations.",
 techniques:[
  {id:"T1583", name:"Acquire Infrastructure", desc:"Buying or leasing servers, domains, and cloud services to host payloads or C2.", detect:"Threat intel feeds on newly registered domains; passive DNS correlation with known TTPs."},
  {id:"T1586", name:"Compromise Accounts", desc:"Taking over existing social media or email accounts to add legitimacy to campaigns.", detect:"Anomalous login geography/device on partner or public-facing accounts you monitor."},
  {id:"T1587", name:"Develop Capabilities", desc:"Building custom malware, exploits, or certificates in-house rather than buying them.", detect:"Primarily an intel/attribution signal seen post-incident via malware family analysis."},
  {id:"T1588", name:"Obtain Capabilities", desc:"Purchasing or downloading malware, exploits, and tools instead of building them.", detect:"Watch for known commodity-tool signatures (Cobalt Strike beacons, RAT families) on the wire."},
  {id:"T1584", name:"Compromise Infrastructure", desc:"Hijacking legitimate servers/domains (rather than buying new ones) to use as staging.", detect:"Reputation feeds flagging previously-benign infrastructure suddenly serving malicious content."},
  {id:"T1608", name:"Stage Capabilities", desc:"Uploading tools/payloads to attacker-controlled infrastructure ahead of use.", detect:"Sandboxing and threat intel on payload-hosting URLs before delivery hits your users."}
 ]},
{id:"TA0001", name:"Initial Access", desc:"The techniques adversaries use to get their first foothold in the network.",
 techniques:[
  {id:"T1566", name:"Phishing", desc:"Malicious attachments/links sent to trick a user into executing code or handing over creds.", detect:"Email gateway detonation/sandboxing, DMARC/SPF/DKIM failures, and user reports of suspicious mail."},
  {id:"T1190", name:"Exploit Public-Facing Application", desc:"Attacking an internet-facing app (web server, VPN, API) via a known or 0-day vulnerability.", detect:"WAF/IDS alerts on exploit signatures; unexpected child processes spawned by web server processes."},
  {id:"T1078", name:"Valid Accounts", desc:"Using stolen, purchased, or default credentials to log in as a legitimate user.", detect:"Impossible-travel logins, off-hours access, and logins from unfamiliar ASNs/devices."},
  {id:"T1133", name:"External Remote Services", desc:"Abusing VPNs, RDP gateways, or other remote-access services exposed to the internet.", detect:"Alert on remote-access logins without matching MFA challenge, or from disallowed geographies."},
  {id:"T1195", name:"Supply Chain Compromise", desc:"Inserting malicious code into legitimate software/hardware before it reaches the victim.", detect:"Hash/signature verification on vendor updates; anomalous outbound connections from trusted software."},
  {id:"T1091", name:"Replication Through Removable Media", desc:"Spreading via infected USB drives or other removable media, often air-gap jumping.", detect:"USB device-control logging and autorun execution alerts on removable media mount."},
  {id:"T1200", name:"Hardware Additions", desc:"Introducing rogue physical devices (USB implants, network taps) to gain access.", detect:"Physical security controls plus 802.1X port security and asset inventory reconciliation."}
 ]},
{id:"TA0002", name:"Execution", desc:"Techniques that result in adversary-controlled code running on a local or remote system.",
 techniques:[
  {id:"T1059", name:"Command and Scripting Interpreter", desc:"Abusing PowerShell, cmd, bash, Python etc. to run commands and scripts.", detect:"PowerShell script-block logging, command-line auditing (4688), flag obfuscated/encoded commands."},
  {id:"T1053", name:"Scheduled Task/Job", desc:"Using task schedulers (cron, Windows Task Scheduler) to trigger execution.", detect:"Alert on new scheduled tasks created by non-admin users or run as SYSTEM unexpectedly."},
  {id:"T1204", name:"User Execution", desc:"Relying on a user to open a file or click a link that triggers the payload.", detect:"EDR alerts on Office spawning shells; user-education metrics from phishing simulations."},
  {id:"T1569", name:"System Services", desc:"Executing code via native OS services like Windows Service Control Manager (sc.exe).", detect:"Monitor service creation events (7045) for unusual binaries or paths."},
  {id:"T1047", name:"Windows Management Instrumentation", desc:"Using WMI for local or remote code execution and reconnaissance.", detect:"Log WMI process creation (wmiprvse.exe spawning children) and remote WMI connections."},
  {id:"T1129", name:"Shared Modules", desc:"Loading malicious DLLs into a process's address space via shared module loading.", detect:"Unsigned or unusually-located DLL load events correlated with process integrity checks."}
 ]},
{id:"TA0003", name:"Persistence", desc:"Techniques that keep the adversary's access alive across reboots, credential changes, etc.",
 techniques:[
  {id:"T1547", name:"Boot or Logon Autostart Execution", desc:"Registry Run keys, startup folders, or similar to auto-launch malware at boot/logon.", detect:"Baseline and alert on new Run/RunOnce key entries or startup-folder writes."},
  {id:"T1053", name:"Scheduled Task/Job", desc:"Same mechanism as execution, but used here to survive reboot and re-trigger malware.", detect:"Same as above — alert on new/edited scheduled tasks, especially hidden or SYSTEM-run ones."},
  {id:"T1078", name:"Valid Accounts", desc:"Re-using compromised credentials so access doesn't depend on malware staying installed.", detect:"Credential-use anomalies; disable/rotate creds fast after any suspected exposure."},
  {id:"T1136", name:"Create Account", desc:"Adding a new local, domain, or cloud account for durable access.", detect:"Alert on account creation events (4720) outside change-management windows."},
  {id:"T1543", name:"Create or Modify System Process", desc:"Installing a malicious Windows service or daemon that restarts with the OS.", detect:"Service creation/modification logs; compare against a known-good service baseline."},
  {id:"T1505", name:"Server Software Component", desc:"Installing a web shell or malicious module into server software (IIS, Apache, Exchange).", detect:"File-integrity monitoring on web roots; scan for known web-shell signatures."}
 ]},
{id:"TA0004", name:"Privilege Escalation", desc:"Techniques used to gain higher-level permissions on a system or network.",
 techniques:[
  {id:"T1055", name:"Process Injection", desc:"Injecting code into a legitimate, higher-privileged process to run under its context.", detect:"EDR flags on cross-process memory writes (WriteProcessMemory, CreateRemoteThread patterns)."},
  {id:"T1548", name:"Abuse Elevation Control Mechanism", desc:"Bypassing UAC or sudo controls to run code with elevated privileges.", detect:"Monitor UAC bypass indicators (e.g., unusual use of fodhelper.exe, eventvwr.exe) and sudoers changes."},
  {id:"T1068", name:"Exploitation for Privilege Escalation", desc:"Exploiting an OS or app vulnerability to jump from user to admin/SYSTEM.", detect:"EDR/AV signatures for known local-privesc exploits; patch-compliance monitoring."},
  {id:"T1078", name:"Valid Accounts", desc:"Using an already-privileged compromised account instead of needing to escalate at all.", detect:"Track privileged-account logon patterns and flag deviation from baseline usage."},
  {id:"T1547", name:"Boot or Logon Autostart Execution", desc:"Autostart mechanisms that run in a higher-privileged context can also be an escalation vector.", detect:"Same Run-key/startup monitoring, paying attention to SYSTEM-context entries."}
 ]},
{id:"TA0005", name:"Defense Evasion", desc:"Techniques adversaries use to avoid being detected throughout their operation.",
 techniques:[
  {id:"T1027", name:"Obfuscated Files or Information", desc:"Encoding, encrypting, or packing payloads/scripts to defeat signature detection.", detect:"Flag base64/encoded PowerShell blocks; entropy analysis on files; sandbox detonation."},
  {id:"T1070", name:"Indicator Removal", desc:"Clearing event logs, deleting files, or timestomping to erase evidence of activity.", detect:"Alert on event-log-clear events (1102) and unexpected log gaps."},
  {id:"T1036", name:"Masquerading", desc:"Naming malicious files/processes to look like legitimate system files (e.g., svch0st.exe).", detect:"Compare process names/paths/hashes against known-good baselines; check digital signatures."},
  {id:"T1055", name:"Process Injection", desc:"Also used here to hide malicious code inside a trusted process's memory space.", detect:"Same as under Privilege Escalation — EDR memory-injection heuristics."},
  {id:"T1562", name:"Impair Defenses", desc:"Disabling AV/EDR, firewall rules, or logging to operate more freely.", detect:"Alert on security-tool service stops, tamper-protection triggers, and Defender exclusions added."},
  {id:"T1218", name:"System Binary Proxy Execution", desc:"Using trusted OS binaries (rundll32, regsvr32, mshta) to run malicious code — 'living off the land'.", detect:"Baseline normal use of LOLBins and flag unusual parent/child process or network activity from them."}
 ]},
{id:"TA0006", name:"Credential Access", desc:"Techniques for stealing account names, passwords, or other credentials.",
 techniques:[
  {id:"T1003", name:"OS Credential Dumping", desc:"Extracting credentials from memory (e.g., LSASS), SAM, or NTDS.dit.", detect:"Alert on LSASS process access by non-standard processes (a top SOC interview topic!)."},
  {id:"T1110", name:"Brute Force", desc:"Systematically guessing passwords, including password spraying across many accounts.", detect:"Account-lockout thresholds, spike in failed logons (4625) across many accounts from one source."},
  {id:"T1555", name:"Credentials from Password Stores", desc:"Pulling saved passwords from browsers, password managers, or the OS credential vault.", detect:"File-access monitoring on browser credential stores; EDR alerts on known dumping tool usage."},
  {id:"T1552", name:"Unsecured Credentials", desc:"Finding plaintext passwords in files, scripts, config files, or command history.", detect:"DLP scanning for credential patterns in shares/repos; secrets-scanning in code."},
  {id:"T1556", name:"Modify Authentication Process", desc:"Tampering with auth mechanisms (e.g., password filter DLLs) to capture creds or bypass MFA.", detect:"Integrity monitoring on auth-related DLLs/registry keys and MFA-policy change alerts."},
  {id:"T1040", name:"Network Sniffing", desc:"Capturing network traffic to intercept credentials sent in the clear.", detect:"Detect promiscuous-mode NIC changes and unexpected packet-capture tool execution."},
  {id:"T1558", name:"Steal or Forge Kerberos Tickets", desc:"Kerberoasting or Golden/Silver Ticket attacks to gain or forge domain access.", detect:"Alert on abnormal TGS requests for many SPNs (Kerberoasting) and unusual ticket lifetimes."}
 ]},
{id:"TA0007", name:"Discovery", desc:"Techniques adversaries use to learn about the environment they've landed in.",
 techniques:[
  {id:"T1082", name:"System Information Discovery", desc:"Running commands like systeminfo, hostname, or ver to profile the host.", detect:"Baseline normal admin recon usage; flag scripted/rapid enumeration commands."},
  {id:"T1087", name:"Account Discovery", desc:"Enumerating local, domain, or cloud accounts (net user, net group, etc.).", detect:"Alert on bulk LDAP/AD queries or net.exe enumeration from non-IT accounts."},
  {id:"T1018", name:"Remote System Discovery", desc:"Mapping other hosts on the network via ping sweeps, ARP, or AD queries.", detect:"NetFlow anomalies showing broad internal scanning behavior from a single host."},
  {id:"T1046", name:"Network Service Discovery", desc:"Port/service scanning internally to find lateral-movement targets.", detect:"IDS signatures for internal port scans; flag hosts making many distinct connection attempts."},
  {id:"T1057", name:"Process Discovery", desc:"Listing running processes to find security tools or targets for injection.", detect:"Generally low-signal alone — correlate with other discovery/execution activity."},
  {id:"T1069", name:"Permission Groups Discovery", desc:"Enumerating AD/cloud groups to identify privileged accounts to target.", detect:"Flag repeated queries against privileged groups (Domain Admins, etc.) from unusual accounts."}
 ]},
{id:"TA0008", name:"Lateral Movement", desc:"Techniques adversaries use to move through the environment from system to system.",
 techniques:[
  {id:"T1021", name:"Remote Services", desc:"Using RDP, SSH, SMB, or WinRM with valid credentials to log into other systems.", detect:"Alert on RDP/WinRM logons between hosts that don't normally communicate; new admin-share access."},
  {id:"T1550", name:"Use Alternate Authentication Material", desc:"Pass-the-hash or pass-the-ticket — authenticating without knowing the plaintext password.", detect:"Detect NTLM logons with no matching Kerberos pre-auth, or unusual token/ticket reuse patterns."},
  {id:"T1210", name:"Exploitation of Remote Services", desc:"Exploiting a vulnerability in a remote service (e.g., SMB) to move laterally.", detect:"IDS/IPS signatures for known remote exploit traffic (e.g., EternalBlue-style SMB exploitation)."},
  {id:"T1080", name:"Taint Shared Content", desc:"Planting malicious files on a network share so other users execute them.", detect:"File-integrity monitoring on shared drives; alert on newly-written executables in shares."}
 ]},
{id:"TA0009", name:"Collection", desc:"Techniques used to gather data of interest before staging it for exfiltration.",
 techniques:[
  {id:"T1560", name:"Archive Collected Data", desc:"Compressing/encrypting stolen data (zip, rar, 7z) before moving it out.", detect:"Flag creation of large archive files in staging directories, especially password-protected ones."},
  {id:"T1005", name:"Data from Local System", desc:"Searching the local filesystem for files of interest to steal.", detect:"Mass file-access patterns (many reads in short time) from a single process/user."},
  {id:"T1114", name:"Email Collection", desc:"Harvesting mailbox contents, often via compromised mail accounts or mailbox rules.", detect:"Alert on new forwarding rules or mailbox-export operations, especially to external addresses."},
  {id:"T1113", name:"Screen Capture", desc:"Taking screenshots of the victim's desktop to collect sensitive visual info.", detect:"EDR behavioral detection on screenshot APIs called by non-standard processes."},
  {id:"T1056", name:"Input Capture", desc:"Keylogging or form-grabbing to capture credentials and other typed data.", detect:"Detect low-level keyboard hook installation and unusual driver loads."}
 ]},
{id:"TA0011", name:"Command and Control", desc:"Techniques for communicating with compromised systems to control them.",
 techniques:[
  {id:"T1071", name:"Application Layer Protocol", desc:"Blending C2 traffic into normal HTTP/S, DNS, or other app-layer protocols.", detect:"Beaconing detection: regular interval/jitter outbound connections; TLS JA3 fingerprinting."},
  {id:"T1105", name:"Ingress Tool Transfer", desc:"Downloading additional tools/malware onto the compromised host post-access.", detect:"Alert on unexpected outbound downloads from endpoints, especially to raw IPs or pastebin-like sites."},
  {id:"T1573", name:"Encrypted Channel", desc:"Encrypting C2 traffic (custom or standard crypto) to prevent content inspection.", detect:"TLS inspection where possible; anomaly-based detection on encrypted-traffic metadata/volume."},
  {id:"T1090", name:"Proxy", desc:"Routing C2 through an intermediate proxy/relay to obscure the true destination.", detect:"Flag connections to known open-proxy/Tor-exit infrastructure via threat intel feeds."},
  {id:"T1568", name:"Dynamic Resolution", desc:"Using domain generation algorithms (DGA) or fast-flux DNS to hide C2 infrastructure.", detect:"DNS analytics for high-entropy/algorithmically-generated domain lookups."},
  {id:"T1102", name:"Web Service", desc:"Using legitimate services (GitHub, Twitter, cloud storage) as a C2 channel or dead-drop.", detect:"Anomalous API traffic to legit web services from endpoints that shouldn't use them."}
 ]},
{id:"TA0010", name:"Exfiltration", desc:"Techniques adversaries use to steal data out of the network.",
 techniques:[
  {id:"T1041", name:"Exfiltration Over C2 Channel", desc:"Sending stolen data out over the same channel used for command and control.", detect:"Volume/anomaly detection on outbound traffic over established beacon connections."},
  {id:"T1048", name:"Exfiltration Over Alternative Protocol", desc:"Using a separate protocol (e.g., FTP, DNS tunneling) from the main C2 channel.", detect:"Watch for large DNS TXT-record volume or unexpected outbound FTP/other protocol use."},
  {id:"T1567", name:"Exfiltration Over Web Service", desc:"Uploading stolen data to cloud storage (Dropbox, Google Drive, etc.).", detect:"CASB/proxy alerts on large uploads to unsanctioned cloud storage services."},
  {id:"T1029", name:"Scheduled Transfer", desc:"Exfiltrating data at set intervals to blend in with normal traffic patterns.", detect:"Look for consistent, low-and-slow outbound transfer patterns at regular times."}
 ]},
{id:"TA0040", name:"Impact", desc:"Techniques adversaries use to disrupt availability or compromise integrity of systems/data.",
 techniques:[
  {id:"T1486", name:"Data Encrypted for Impact", desc:"Ransomware — encrypting files/systems and demanding payment for the key.", detect:"Mass file-modification/rename alerts, shadow-copy deletion, and honeypot-file triggers."},
  {id:"T1490", name:"Inhibit System Recovery", desc:"Deleting backups, shadow copies, or disabling recovery tools ahead of a destructive attack.", detect:"Alert on vssadmin/wbadmin delete commands and backup-service tampering."},
  {id:"T1489", name:"Service Stop", desc:"Stopping critical services (backup agents, DBs, security tools) to cause disruption.", detect:"Service-stop events (7036) for critical/security services outside maintenance windows."},
  {id:"T1485", name:"Data Destruction", desc:"Wiping or corrupting data/systems irrecoverably (as opposed to ransoming it).", detect:"Mass-deletion/overwrite alerts; compare against backup integrity regularly."},
  {id:"T1498", name:"Network Denial of Service", desc:"Flooding network resources to make services unavailable to legitimate users.", detect:"NetFlow volume spikes, upstream DDoS-mitigation provider alerts."},
  {id:"T1531", name:"Account Access Removal", desc:"Locking out or deleting accounts/credentials to deny legitimate users access.", detect:"Bulk password-reset or account-disable events (4725/4726) in a short window."}
 ]}
];

const ALL_TECH = [];
TACTICS.forEach(t=>t.techniques.forEach(tech=>ALL_TECH.push({...tech, tacticId:t.id, tacticName:t.name})));
const TOTAL = ALL_TECH.length;

// ---------------------------------------------------------------
// STATE
// ---------------------------------------------------------------
let studied = new Set();
let quizStats = {correct:0, total:0};
let currentTacticFilter = null; // null = all
let showUnstudiedOnly = false;
let searchTerm = "";
let quizState = {question:null, answered:false};

function ensureStorageAdapter(){
  if (window.storage) return;

  window.storage = {
    get(key, fallback) {
      try {
        const raw = localStorage.getItem(key);
        return raw === null ? fallback : { value: raw };
      } catch (e) {
        return fallback;
      }
    },
    set(key, value) {
      try {
        localStorage.setItem(key, value);
        return true;
      } catch (e) {
        return false;
      }
    }
  };
}

async function loadState(){
  ensureStorageAdapter();
  try{
    const r = await window.storage.get('attack-studied', false);
    if(r && r.value) {
      const parsed = JSON.parse(r.value);
      if(Array.isArray(parsed)) studied = new Set(parsed);
    }
  }catch(e){}
  try{
    const r2 = await window.storage.get('attack-quizstats', false);
    if(r2 && r2.value) {
      const parsed = JSON.parse(r2.value);
      if(parsed && typeof parsed === 'object') quizStats = parsed;
    }
  }catch(e){}
  render();
}
async function saveStudied(){
  ensureStorageAdapter();
  try{ await window.storage.set('attack-studied', JSON.stringify([...studied])); }catch(e){}
}
async function saveQuizStats(){
  ensureStorageAdapter();
  try{ await window.storage.set('attack-quizstats', JSON.stringify(quizStats)); }catch(e){}
}

// ---------------------------------------------------------------
// RENDER: header stats + rail
// ---------------------------------------------------------------
function renderHeader(){
  document.getElementById('stat-studied').textContent = studied.size;
  document.getElementById('stat-total').textContent = TOTAL;
  document.getElementById('stat-quiz').textContent = quizStats.total;
  document.getElementById('stat-acc').textContent = quizStats.total ? Math.round(100*quizStats.correct/quizStats.total)+'%' : '—';
  const pct = TOTAL ? studied.size/TOTAL : 0;
  const circ = 2*Math.PI*30;
  document.getElementById('ring-fg').style.strokeDasharray = circ;
  document.getElementById('ring-fg').style.strokeDashoffset = circ*(1-pct);
  document.getElementById('ring-label').textContent = Math.round(pct*100)+'%';
}

function renderRail(){
  const rail = document.getElementById('rail');
  rail.innerHTML = '';
  TACTICS.forEach((t, i)=>{
    const total = t.techniques.length;
    const done = t.techniques.filter(tech=>studied.has(tech.id)).length;
    const pct = total? done/total : 0;
    const btn = document.createElement('button');
    btn.className = 'rail-node' + (currentTacticFilter===t.id?' active':'') + (pct===1?' complete':'');
    const circ = 2*Math.PI*16;
    btn.innerHTML = `
      <div class="trace ${done>0?'lit':''}"></div>
      <div class="node-ring">
        <svg viewBox="0 0 38 38">
          <circle class="node-ring-bg" cx="19" cy="19" r="16"></circle>
          <circle class="node-ring-fg" cx="19" cy="19" r="16" stroke-dasharray="${circ}" stroke-dashoffset="${circ*(1-pct)}"></circle>
        </svg>
        <div class="node-num">${String(i+1).padStart(2,'0')}</div>
      </div>
      <div class="node-label">${t.name}</div>
      <div class="node-count">${done}/${total}</div>
    `;
    btn.onclick = ()=>{
      currentTacticFilter = (currentTacticFilter===t.id)? null : t.id;
      document.getElementById('filter-all').classList.toggle('active', currentTacticFilter===null);
      renderRail(); renderBrowse();
    };
    rail.appendChild(btn);
  });
}

// ---------------------------------------------------------------
// RENDER: browse
// ---------------------------------------------------------------
function renderBrowse(){
  const grid = document.getElementById('grid');
  const headingBlock = document.getElementById('tactic-heading-block');
  grid.innerHTML = '';
  headingBlock.innerHTML = '';

  let pool = ALL_TECH;
  if(currentTacticFilter) pool = pool.filter(t=>t.tacticId===currentTacticFilter);
  if(showUnstudiedOnly) pool = pool.filter(t=>!studied.has(t.id));
  if(searchTerm.trim()){
    const s = searchTerm.trim().toLowerCase();
    pool = pool.filter(t=> t.id.toLowerCase().includes(s) || t.name.toLowerCase().includes(s) || t.desc.toLowerCase().includes(s));
  }

  if(currentTacticFilter){
    const t = TACTICS.find(x=>x.id===currentTacticFilter);
    headingBlock.innerHTML = `<div class="tactic-heading">${t.name} <span class="id">${t.id}</span></div><div class="tactic-desc">${t.desc}</div>`;
  }

  document.getElementById('empty-note').style.display = pool.length? 'none':'block';

  pool.forEach(tech=>{
    const card = document.createElement('div');
    card.className = 'card' + (studied.has(tech.id)?' studied':'');
    card.innerHTML = `
      <div class="card-top">
        <div class="card-id">${tech.id} · ${tech.tacticName}</div>
        <div class="check ${studied.has(tech.id)?'checked':''}" data-id="${tech.id}"></div>
      </div>
      <div class="card-name">${tech.name}</div>
      <div class="card-desc">${tech.desc}</div>
      <div class="card-detect"><b>Detection idea</b>${tech.detect}</div>
    `;
    card.querySelector('.check').onclick = ()=>{
      if(studied.has(tech.id)) studied.delete(tech.id); else studied.add(tech.id);
      saveStudied();
      renderHeader(); renderRail(); renderBrowse();
    };
    grid.appendChild(card);
  });
}

// ---------------------------------------------------------------
// QUIZ
// ---------------------------------------------------------------
function pickRandom(arr){ return arr[Math.floor(Math.random()*arr.length)]; }

function newQuestion(){
  const types = ['tactic-of-technique','desc-of-technique','id-of-name'];
  const type = pickRandom(types);
  const tech = pickRandom(ALL_TECH);
  let q = {type, tech};

  if(type==='tactic-of-technique'){
    const correct = tech.tacticName;
    let distractors = new Set();
    while(distractors.size<3){
      const d = pickRandom(TACTICS).name;
      if(d!==correct) distractors.add(d);
    }
    q.prompt = `Which tactic does <code>${tech.id} — ${tech.name}</code> belong to?`;
    q.options = shuffle([correct, ...distractors]);
    q.correct = correct;
    q.explain = `${tech.id} (${tech.name}) falls under <b>${tech.tacticName}</b>. ${tech.desc}`;
  } else if(type==='desc-of-technique'){
    const correct = tech.desc;
    let distractors = new Set();
    while(distractors.size<3){
      const d = pickRandom(ALL_TECH);
      if(d.id!==tech.id) distractors.add(d.desc);
    }
    q.prompt = `What does <code>${tech.id} — ${tech.name}</code> describe?`;
    q.options = shuffle([correct, ...[...distractors]]);
    q.correct = correct;
    q.explain = `${tech.desc} <br><br><b>Detection idea:</b> ${tech.detect}`;
  } else {
    const correct = tech.id;
    let distractors = new Set();
    while(distractors.size<3){
      const d = pickRandom(ALL_TECH);
      if(d.id!==tech.id) distractors.add(d.id);
    }
    q.prompt = `Which technique ID corresponds to <code>${tech.name}</code>?`;
    q.options = shuffle([correct, ...distractors]);
    q.correct = correct;
    q.explain = `${tech.id} — ${tech.name}. ${tech.desc}`;
  }
  return q;
}
function shuffle(arr){ return arr.map(v=>[Math.random(),v]).sort((a,b)=>a[0]-b[0]).map(v=>v[1]); }

const kickerLabel = {'tactic-of-technique':'Identify the tactic','desc-of-technique':'Identify the behavior','id-of-name':'Identify the technique ID'};

function renderQuiz(){
  const q = quizState.question;
  document.getElementById('qz-kicker').textContent = kickerLabel[q.type];
  document.getElementById('qz-prompt').innerHTML = q.prompt;
  const optsDiv = document.getElementById('qz-options');
  optsDiv.innerHTML = '';
  q.options.forEach(opt=>{
    const b = document.createElement('button');
    b.className = 'qopt';
    b.textContent = opt;
    b.onclick = ()=>answerQuiz(opt);
    optsDiv.appendChild(b);
  });
  document.getElementById('qz-explain').classList.remove('show');
  document.getElementById('qz-next').classList.remove('show');
  document.getElementById('qs-correct').textContent = quizStats.correct;
  document.getElementById('qs-total').textContent = quizStats.total;
  document.getElementById('qz-bar').style.width = quizStats.total? Math.min(100, quizStats.total*3)+'%' : '0%';
  quizState.answered = false;
}

function answerQuiz(selected){
  if(quizState.answered) return;
  quizState.answered = true;
  const q = quizState.question;
  const isCorrect = selected===q.correct;
  quizStats.total++;
  if(isCorrect) quizStats.correct++;
  saveQuizStats();
  document.querySelectorAll('.qopt').forEach(b=>{
    b.disabled = true;
    if(b.textContent===q.correct) b.classList.add('correct');
    else if(b.textContent===selected) b.classList.add('wrong');
  });
  const ex = document.getElementById('qz-explain');
  ex.innerHTML = (isCorrect? '<b style="color:var(--green)">Correct.</b> ' : '<b style="color:var(--red)">Not quite.</b> ') + q.explain;
  ex.classList.add('show');
  document.getElementById('qz-next').classList.add('show');
  document.getElementById('qs-correct').textContent = quizStats.correct;
  document.getElementById('qs-total').textContent = quizStats.total;
  document.getElementById('qz-bar').style.width = Math.min(100, quizStats.total*3)+'%';
  // count technique as studied when answered correctly
  if(isCorrect){ studied.add(q.tech.id); saveStudied(); renderHeader(); renderRail(); }
}

if(document.getElementById('qz-next')){
document.getElementById('qz-next').onclick = ()=>{
  quizState.question = newQuestion();
  renderQuiz();
};
document.getElementById('qz-reset').onclick = ()=>{
  quizStats = {correct:0, total:0};
  saveQuizStats();
  quizState.question = newQuestion();
  renderQuiz();
};

// ---------------------------------------------------------------
// TABS + CONTROLS
// ---------------------------------------------------------------
document.querySelectorAll('.tab-btn').forEach(btn=>{
  btn.onclick = ()=>{
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    document.getElementById('browse-view').style.display = tab==='browse'?'block':'none';
    document.getElementById('quiz-view').style.display = tab==='quiz'?'block':'none';
    if(tab==='quiz' && !quizState.question){
      quizState.question = newQuestion();
      renderQuiz();
    }
  };
});
document.getElementById('search').addEventListener('input', e=>{ searchTerm = e.target.value; renderBrowse(); });
document.getElementById('filter-all').onclick = ()=>{
  currentTacticFilter = null;
  document.getElementById('filter-all').classList.add('active');
  renderRail(); renderBrowse();
};
document.getElementById('filter-unstudied').onclick = ()=>{
  showUnstudiedOnly = !showUnstudiedOnly;
  document.getElementById('filter-unstudied').classList.toggle('active', showUnstudiedOnly);
  renderBrowse();
};
}

function applyTheme(theme){
  const root = document.documentElement;
  const nextTheme = theme === 'light' ? 'light' : 'dark';
  root.setAttribute('data-theme', nextTheme);
  const btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.textContent = nextTheme === 'dark' ? '☀️ Light' : '🌙 Dark';
  }
  try {
    localStorage.setItem('cybertraining-theme', nextTheme);
  } catch (e) {}
}

function initNotes(){
  document.querySelectorAll('.notes-panel').forEach(panel=>{
    const key = panel.dataset.notesKey;
    const input = panel.querySelector('.notes-input');
    const saveButton = panel.querySelector('.notes-save');
    const status = panel.querySelector('.notes-status');
    if(!key || !input || !saveButton) return;

    try {
      input.value = localStorage.getItem(`cybertraining-notes-${key}`) || '';
    } catch (e) {}

    input.addEventListener('input', ()=>{ status.textContent = ''; });
    saveButton.addEventListener('click', ()=>{
      try {
        localStorage.setItem(`cybertraining-notes-${key}`, input.value);
        status.textContent = 'Saved locally';
      } catch (e) {
        status.textContent = 'Storage unavailable';
      }
    });
  });
}

function initTheme(){
  let initialTheme;
  try {
    initialTheme = localStorage.getItem('cybertraining-theme');
  } catch (e) {}

  if (!initialTheme) {
    initialTheme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  applyTheme(initialTheme);

  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
    });
  }
}

function render(){
  renderHeader();
  renderRail();
  renderBrowse();
}

initNotes();
initTheme();
if(document.getElementById('browse-view')) loadState();
