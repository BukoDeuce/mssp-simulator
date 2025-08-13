import React, { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldAlert, Clock, Trophy, RefreshCw, FileText, ChevronRight, Zap, Users, Network, Settings, Crown, Timer, Filter } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

type Role = "Analyst" | "Manager" | "Executive";

type Action = {
  id: string;
  label: string;
  category: "Detect" | "Contain" | "Eradicate" | "Recover" | "Communicate" | "Improve" | "Compliance" | "Triage";
  hint?: string;
};

type Scenario = {
  id: string;
  title: string;
  severity: "P1" | "P2" | "P3" | "P4";
  industry: "Healthcare" | "Finance" | "Public Sector" | "Retail" | "Ecommerce" | "SaaS" | "Multiple";
  clientSize: "SMB" | "Mid" | "Enterprise" | "Platform";
  synopsis: string;
  indicators: string[];
  assets: string[];
  mitre: string[];
  goal: string;
  actions: Action[];
  correct: string[];
  ok: string[];
  bad: string[];
  prevention: { people: string[]; process: string[]; tech: string[] };
};

type Outcome = { score: number; slaImpact: number; trustImpact: number; notes: string[] };

type BoardEntry = { name: string; score: number; role: Role; scenario: string; date: string };

type TestResult = { name: string; pass: boolean; details?: string };

function sample<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }

const SCENARIOS: Scenario[] = [
  {
    id: "ransom-endpoint",
    title: "Ransomware Beacon on CFO Laptop",
    severity: "P1",
    industry: "Finance",
    clientSize: "Mid",
    synopsis: "EDR flags ransomware behavior (file renames, shadow copy deletion) on the CFO's laptop at a priority client. Beacon to known C2 domain detected.",
    indicators: ["EDR high-severity alert: ransomware behavior","DNS query to suspicious domain","SMB write spikes on user profile"],
    assets: ["VIP endpoint","File server share","M365 OneDrive"],
    mitre: ["TA0002 Execution","TA0040 Impact","TA0010 Exfiltration"],
    goal: "Minimize impact, preserve evidence, and restore business quickly while keeping exec stakeholder calm.",
    actions: [
      { id: "isolate-edr", label: "Isolate host via EDR", category: "Contain", hint: "Stops spread immediately." },
      { id: "disable-creds", label: "Disable user's tokens/sessions", category: "Contain" },
      { id: "forensics-mem", label: "Capture volatile memory & triage artifacts", category: "Triage" },
      { id: "notify-client-p1", label: "Notify client P1 bridge and set comms cadence", category: "Communicate" },
      { id: "broad-scan", label: "Threat hunt across tenant for IOCs", category: "Detect" },
      { id: "pay-ransom", label: "Advise client to pay ransom immediately", category: "Communicate" },
      { id: "wipe-now", label: "Reimage immediately without imaging disk", category: "Eradicate" },
      { id: "backup-verify", label: "Verify last clean backup & plan restore", category: "Recover" },
      { id: "law-enforcement", label: "Advise on law enforcement/insurance notification", category: "Compliance" },
      { id: "ioc-block", label: "Block C2 domain/IP at DNS/WAF/NGFW", category: "Contain" },
      { id: "postmortem", label: "Open post-incident review & playbook updates", category: "Improve" },
    ],
    correct: ["isolate-edr","disable-creds","notify-client-p1","broad-scan","ioc-block","backup-verify","forensics-mem"],
    ok: ["law-enforcement","postmortem"],
    bad: ["pay-ransom","wipe-now"],
    prevention: { people: ["VIP-specific tabletop exercises for ransomware","EDR response training for on-call pods"], process: ["Golden image & backup restore runbook tested quarterly","Crisis comms template for P1 VIP incidents"], tech: ["EDR tamper protection enforced","Immutable backups with 14-30 day retention","DNS sinkhole for known ransomware C2"] },
  },
  {
    id: "cloud-bucket",
    title: "Public Cloud Storage Bucket Exposed",
    severity: "P2",
    industry: "Retail",
    clientSize: "Enterprise",
    synopsis: "CSPM reports an object storage bucket containing PII is public. Access logs indicate downloads from unknown IPs.",
    indicators: ["CSPM misconfiguration alert","Access logs w/ anon requests","Data classification: PII"],
    assets: ["S3/GCS bucket","IAM roles","DLP"],
    mitre: ["TA0010 Exfiltration","TA0001 Initial Access"],
    goal: "Close exposure, assess data access, comply with breach-notification timelines.",
    actions: [
      { id: "make-private", label: "Immediately restrict bucket to private & block public ACLs", category: "Contain" },
      { id: "rotate-keys", label: "Rotate access keys and service credentials", category: "Contain" },
      { id: "notify-privacy", label: "Engage privacy/legal for breach assessment", category: "Compliance" },
      { id: "threat-intel", label: "Check threat intel for paste sites/marketplaces", category: "Detect" },
      { id: "delete-logs", label: "Purge access logs to reduce noise", category: "Improve" },
      { id: "client-brief", label: "Establish comms cadence with client execs", category: "Communicate" },
      { id: "dlp-scan", label: "Run DLP scan to scope data classification", category: "Detect" },
      { id: "siem-kql", label: "Pivot in SIEM to correlate other access", category: "Triage" },
      { id: "guardrails", label: "Apply org policy to block public buckets", category: "Improve" },
    ],
    correct: ["make-private","notify-privacy","client-brief","dlp-scan","siem-kql"],
    ok: ["rotate-keys","threat-intel","guardrails"],
    bad: ["delete-logs"],
    prevention: { people: ["Cloud security training for app teams"], process: ["Change control for storage policy exceptions"], tech: ["Organization-level block public access","DLP auto-tagging"] },
  },
  {
    id: "ddos",
    title: "Client Ecommerce Site Under DDoS",
    severity: "P1",
    industry: "Ecommerce",
    clientSize: "Enterprise",
    synopsis: "Traffic spikes 50x baseline; origin overwhelmed. WAF shows Layer 7 flood and botnet IPs.",
    indicators: ["WAF anomalies","High 5xx at origin","Synthetic checks failing"],
    assets: ["CDN/WAF","Origin web cluster","DNS"],
    mitre: ["TA0040 Impact"],
    goal: "Restore availability while filtering malicious traffic and communicating status.",
    actions: [
      { id: "waf-rules", label: "Enable emergency WAF rules / rate limiting", category: "Contain" },
      { id: "cdn-cache", label: "Increase CDN caching & serve stale", category: "Recover" },
      { id: "scale-out", label: "Scale out origin capacity", category: "Recover" },
      { id: "announce-down", label: "Post outage publicly without client approval", category: "Communicate" },
      { id: "scrub-center", label: "Route through DDoS scrubbing provider", category: "Contain" },
      { id: "status-bridge", label: "Open incident bridge & SLA comms cadence", category: "Communicate" },
      { id: "forensic-delay", label: "Delay actions awaiting full forensic report", category: "Triage" },
    ],
    correct: ["waf-rules","scrub-center","status-bridge","cdn-cache"],
    ok: ["scale-out"],
    bad: ["announce-down","forensic-delay"],
    prevention: { people: ["On-call readiness for traffic events"], process: ["Pre-approved WAF emergency playbook"], tech: ["Autoscaling, CDN prewarming, Anycast DDoS"] },
  },
  {
    id: "siem-outage",
    title: "SIEM Ingest Outage Threatens SLA",
    severity: "P2",
    industry: "Multiple",
    clientSize: "Platform",
    synopsis: "Multi-tenant SIEM stops ingesting logs due to license overage + parser failure, risking missed detections across 12 clients.",
    indicators: ["Ingest lag spike","License alerts","Parser errors"],
    assets: ["SIEM","Syslog relays","SOAR"],
    mitre: ["TA0002 Execution (telemetry loss)"],
    goal: "Restore coverage fast, maintain transparency, and avoid SLA penalties.",
    actions: [
      { id: "open-rca", label: "Declare internal incident and assign commander", category: "Communicate" },
      { id: "tiering", label: "Tier retention & drop noisy low-value logs", category: "Contain" },
      { id: "burst-license", label: "Request burst licensing from vendor", category: "Recover" },
      { id: "silent-mode", label: "Stay silent until fixed to limit panic", category: "Communicate" },
      { id: "manual-hunt", label: "Stand up manual hunts for high-risk clients", category: "Detect" },
      { id: "client-notify", label: "Notify impacted clients with mitigation plan", category: "Communicate" },
      { id: "parser-fix", label: "Rollback parser/update hotfix", category: "Recover" },
    ],
    correct: ["open-rca","client-notify","tiering","burst-license","parser-fix"],
    ok: ["manual-hunt"],
    bad: ["silent-mode"],
    prevention: { people: ["On-call for platform reliability"], process: ["Capacity planning & ingest SLOs"], tech: ["Multi-pipeline buffering, canary parsers"] },
  },
  {
    id: "cred-stuffing",
    title: "Credential Stuffing on Customer Portal",
    severity: "P2",
    industry: "SaaS",
    clientSize: "Mid",
    synopsis: "Spike in failed logins, many IPs, some takeovers confirmed. Fraud team nervous.",
    indicators: ["Auth 401/429 spikes","Same UA strings","Password reset volume up"],
    assets: ["WAF/Bot mgmt","IdP","App logs"],
    mitre: ["TA0006 Credential Access","TA0001 Initial Access"],
    goal: "Stop takeover, protect users, advise on hardening.",
    actions: [
      { id: "bot-mitigation", label: "Enable bot mitigation / CAPTCHA / rate limits", category: "Contain" },
      { id: "mfa-enforce", label: "Temporarily enforce step-up MFA", category: "Contain" },
      { id: "ip-block", label: "Block obvious bad IP ranges / ASN", category: "Contain" },
      { id: "force-reset", label: "Force password reset for affected users", category: "Recover" },
      { id: "notify-users", label: "Notify impacted users and monitor fraud", category: "Communicate" },
      { id: "disable-login", label: "Disable logins for entire portal", category: "Contain" },
    ],
    correct: ["bot-mitigation","mfa-enforce","ip-block","notify-users"],
    ok: ["force-reset"],
    bad: ["disable-login"],
    prevention: { people: ["Fraud & security response drills"], process: ["Compromised credential playbook w/ comms"], tech: ["MFA by default, credential stuffing protections"] },
  },
  {
    id: "insider-exfil",
    title: "Insider Exfiltration via Personal Cloud",
    severity: "P3",
    industry: "Healthcare",
    clientSize: "Enterprise",
    synopsis: "UEBA flags mass file movement to personal cloud storage by departing employee in a sensitive department.",
    indicators: ["UEBA anomaly","Proxy logs to personal cloud","Endpoint file moves"],
    assets: ["DLP","Proxy/CASB","HRIS"],
    mitre: ["TA0010 Exfiltration","TA0005 Defense Evasion"],
    goal: "Contain exfil, preserve evidence, coordinate with HR/legal.",
    actions: [
      { id: "suspend-user", label: "Suspend account & revoke tokens", category: "Contain" },
      { id: "block-cloud", label: "Block personal cloud domains at proxy/CASB", category: "Contain" },
      { id: "collect-evidence", label: "Preserve logs & image device", category: "Triage" },
      { id: "notify-hr", label: "Engage HR/legal for response", category: "Compliance" },
      { id: "public-shame", label: "Post the user's name to warn others", category: "Communicate" },
      { id: "dlp-tune", label: "Tune DLP policies to prevent similar exfil", category: "Improve" },
    ],
    correct: ["suspend-user","block-cloud","collect-evidence","notify-hr"],
    ok: ["dlp-tune"],
    bad: ["public-shame"],
    prevention: { people: ["Joiner-Mover-Leaver strict offboarding"], process: ["Insider risk playbook with HR"], tech: ["CASB block unsanctioned storage, DLP templates"] },
  },
  {
    id: "ot-ics-ransom",
    title: "Ransomware Hitting Radiology PACS",
    severity: "P1",
    industry: "Healthcare",
    clientSize: "Enterprise",
    synopsis: "PACS servers show encryption attempts; modality workstations sluggish. Elective imaging at risk of delays.",
    indicators: ["High CPU on PACS","Suspicious SMB writes","EDR tamper attempts"],
    assets: ["PACS","Modality workstations","AD"],
    mitre: ["TA0040 Impact","TA0003 Persistence"],
    goal: "Protect clinical operations while containing ransomware and maintaining evidence chain.",
    actions: [
      { id: "segment-ot", label: "Temporarily segment imaging VLANs", category: "Contain" },
      { id: "edr-isolate", label: "Isolate affected hosts via EDR", category: "Contain" },
      { id: "clin-comm", label: "Notify clinical ops & switch to downtime procedures", category: "Communicate" },
      { id: "restore-pacs", label: "Restore PACS from last clean snapshot", category: "Recover" },
      { id: "erase-pacs", label: "Wipe PACS immediately without capture", category: "Eradicate" },
    ],
    correct: ["segment-ot","edr-isolate","clin-comm","restore-pacs"],
    ok: [],
    bad: ["erase-pacs"],
    prevention: { people: ["Clinical downtime drills"], process: ["OT change mgmt + IR runbooks"], tech: ["Network segmentation, immutable snapshots"] },
  },
  {
    id: "bec-wire",
    title: "Business Email Compromise – Fraudulent Wire",
    severity: "P1",
    industry: "Finance",
    clientSize: "Mid",
    synopsis: "Finance clerk received CEO-lookalike email requesting urgent vendor wire change; one transfer executed.",
    indicators: ["Lookalike domain","MFA bypassed via app password","Mail rules"],
    assets: ["M365","Finance systems","Bank portal"],
    mitre: ["TA0006 Credential Access","TA0009 Collection"],
    goal: "Stop ongoing fraud, recover funds if possible, and harden mail.",
    actions: [
      { id: "bank-recall", label: "Contact bank to recall/suspend transfer", category: "Communicate" },
      { id: "reset-mfa", label: "Reset creds + revoke tokens + enforce MFA", category: "Contain" },
      { id: "mail-rules", label: "Purge malicious inbox rules & audit OAuth grants", category: "Eradicate" },
      { id: "legal-law", label: "Engage legal & law enforcement per policy", category: "Compliance" },
      { id: "blame-email", label: "Discipline the clerk publicly", category: "Communicate" },
    ],
    correct: ["bank-recall","reset-mfa","mail-rules","legal-law"],
    ok: [],
    bad: ["blame-email"],
    prevention: { people: ["Finance callback policy for wire changes"], process: ["BEC playbook"], tech: ["MFA, anti-spoofing (DMARC/DKIM/SPF), impossible travel"] },
  },
  {
    id: "vpn-zero",
    title: "Perimeter VPN Zero-Day Exploitation",
    severity: "P1",
    industry: "Public Sector",
    clientSize: "Enterprise",
    synopsis: "Threat intel indicates active exploitation of your VPN vendor; anomalous admin logins appear out-of-hours.",
    indicators: ["New admin accounts","Config changes","Outbound C2"],
    assets: ["VPN concentrator","IdP","SIEM"],
    mitre: ["TA0001 Initial Access","TA0003 Persistence"],
    goal: "Contain perimeter, block actor persistence, and validate access paths.",
    actions: [
      { id: "geo-block", label: "Geo-block & restrict admin access to jump hosts", category: "Contain" },
      { id: "patch-mitigate", label: "Apply vendor mitigations / interim config", category: "Eradicate" },
      { id: "rotate-secrets", label: "Rotate device certs & admin creds", category: "Recover" },
      { id: "hunt-si", label: "Hunt for IOCs in SIEM / netflow", category: "Detect" },
      { id: "announce-public", label: "Announce compromise on social media", category: "Communicate" },
    ],
    correct: ["geo-block","patch-mitigate","rotate-secrets","hunt-si"],
    ok: [],
    bad: ["announce-public"],
    prevention: { people: ["CAB fast-track for zero-day"], process: ["Perimeter hardening standards"], tech: ["Admin MFA, allowlisted management, config backups"] },
  },
  {
    id: "cert-expiry",
    title: "Expired TLS Certificate Breaks APIs",
    severity: "P2",
    industry: "Public Sector",
    clientSize: "Enterprise",
    synopsis: "Critical API endpoints failing due to expired cert; public trust and integrations impacted.",
    indicators: ["TLS errors","Failed health checks","Monitoring alerts"],
    assets: ["PKI","API gateway","DNS"],
    mitre: ["TA0040 Impact"],
    goal: "Restore service quickly and implement certificate lifecycle management.",
    actions: [
      { id: "install-renewed", label: "Install renewed cert & verify chain", category: "Recover" },
      { id: "enable-auto", label: "Enable auto-renew / ACME", category: "Improve" },
      { id: "silence-alerts", label: "Silence monitoring for 24h", category: "Improve" },
      { id: "status-update", label: "Issue status page update & comms", category: "Communicate" },
    ],
    correct: ["install-renewed","status-update"],
    ok: ["enable-auto"],
    bad: ["silence-alerts"],
    prevention: { people: ["Ownership clearly assigned"], process: ["Cert inventory & renewal SOP"], tech: ["ACME, monitoring with expiry alerts"] },
  },
];

const SIEM_TOOLS = ["Microsoft Sentinel", "Splunk Enterprise Security", "IBM QRadar", "Elastic Security", "Securonix", "Exabeam" ];
const SOAR_TOOLS = ["Cortex XSOAR", "Splunk SOAR (Phantom)", "Tines", "Microsoft Sentinel Automation", "Swimlane", "DFLabs/Exabeam Fusion" ];

function labelFor(s: Scenario, id: string) { return s.actions.find((a) => a.id === id)?.label ?? id; }

function severityColor(sev: Scenario["severity"]) {
  switch (sev) {
    case "P1": return "bg-red-600";
    case "P2": return "bg-orange-500";
    case "P3": return "bg-yellow-500";
    default: return "bg-emerald-600";
  }
}

function evaluateSelections(s: Scenario, picks: Set<string>, role: Role): Outcome {
  let score = 50;
  let notes: string[] = [];
  let trustImpact = 0;
  let slaImpact = 0;
  const roleBonus = role === "Manager" ? 1.1 : role === "Executive" ? 0.9 : 1.0;
  s.correct.forEach((id) => {
    if (picks.has(id)) { score += 8 * roleBonus; slaImpact += 6; trustImpact += 5; }
    else { score -= 10; notes.push(`Missed critical step: ${labelFor(s, id)}`); slaImpact -= 8; trustImpact -= 6; }
  });
  s.ok.forEach((id) => { if (picks.has(id)) { score += 3 * roleBonus; slaImpact += 2; trustImpact += 2; } });
  s.bad.forEach((id) => { if (picks.has(id)) { score -= 12; slaImpact -= 10; trustImpact -= 12; notes.push(`Selected harmful step: ${labelFor(s, id)}`); } });
  score = Math.max(0, Math.min(100, Math.round(score)));
  slaImpact = Math.max(-100, Math.min(100, slaImpact));
  trustImpact = Math.max(-100, Math.min(100, trustImpact));
  return { score, slaImpact, trustImpact, notes };
}

function buildReport(s: Scenario, outcome: Outcome, selected: string[], role: Role): string {
  const ts = new Date().toISOString();
  return `# MSSP Incident Report – ${s.title}\nTime: ${ts}\nRole: ${role}\nSeverity: ${s.severity}\nIndustry: ${s.industry}\n\n## Synopsis\n${s.synopsis}\n\n**Indicators:** ${s.indicators.join(", ")}\n\n**Assets:** ${s.assets.join(", ")}\n\n**ATT&CK:** ${s.mitre.join(", ")}\n\n## Actions Taken\n${selected.map((id) => `- ${labelFor(s, id)}`).join("\\n")}\n\n## Outcome\n- Score: ${outcome.score}/100\n- SLA Impact: ${outcome.slaImpact}\n- Client Trust Impact: ${outcome.trustImpact}\n${outcome.notes.length ? `\n**Notes:**\n${outcome.notes.map((n) => `- ${n}`).join("\\n")}` : ""}\n\n## Preventive Recommendations\n### People\n${s.prevention.people.map((p) => `- ${p}`).join("\\n")}\n\n### Process\n${s.prevention.process.map((p) => `- ${p}`).join("\\n")}\n\n### Technology\n${s.prevention.tech.map((p) => `- ${p}`).join("\\n")}\n`;
}

function download(text: string, filename: string) {
  const blob = new Blob([text], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

const LB_KEY = "mssp-sim-leaderboard";
function canUseStorage() { return typeof window !== "undefined" && "localStorage" in window; }
function safeGet(key: string, fallback: string) { try { return canUseStorage() ? localStorage.getItem(key) ?? fallback : fallback; } catch { return fallback; } }
function safeSet(key: string, value: string) { try { if (canUseStorage()) localStorage.setItem(key, value); } catch { /* noop */ } }
function loadBoard(): BoardEntry[] { try { return canUseStorage() ? JSON.parse(localStorage.getItem(LB_KEY) || "[]") : []; } catch { return []; } }
function saveBoard(entries: BoardEntry[]) { try { if (canUseStorage()) localStorage.setItem(LB_KEY, JSON.stringify(entries.slice(0, 20))); } catch { /* noop */ } }

export default function App() {
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [showReport, setShowReport] = useState(false);
  const [clientSatisfaction, setClientSatisfaction] = useState(75);
  const [slaHealth, setSlaHealth] = useState(80);
  const [round, setRound] = useState(0);
  const [name, setName] = useState<string>(() => safeGet("mssp-name", "You"));
  const [role, setRole] = useState<Role>(() => (safeGet("mssp-role", "Manager") as Role));
  const [board, setBoard] = useState<BoardEntry[]>(() => loadBoard());
  const [sector, setSector] = useState<"All" | "Healthcare" | "Finance" | "Public Sector">("All");
  const [timer, setTimer] = useState<number>(0);
  const [timedMode, setTimedMode] = useState<boolean>(true);

  useEffect(() => {
    if (!timedMode || !scenario || outcome) return;
    if (timer <= 0) return;
    const id = setInterval(() => setTimer((t) => t - 1), 1000);
    return () => clearInterval(id);
  }, [timer, timedMode, scenario, outcome]);

  useEffect(() => { safeSet("mssp-name", name); }, [name]);
  useEffect(() => { safeSet("mssp-role", role); }, [role]);

  function eligibleScenarios() {
    if (sector === "All") return SCENARIOS;
    return SCENARIOS.filter((s) => s.industry === sector);
  }

  function newScenario() {
    const pool = eligibleScenarios();
    if (pool.length === 0) { setScenario(null); setPicked(new Set()); setOutcome(null); setTimer(0); return; }
    const s = sample(pool);
    setScenario(s);
    setPicked(new Set());
    setOutcome(null);
    setRound((r) => r + 1);
    if (timedMode) setTimer(90);
  }

  function togglePick(id: string) {
    if (outcome) return;
    const next = new Set(picked);
    if (next.has(id)) next.delete(id); else next.add(id);
    setPicked(next);
  }

  function resolve(force = false) {
    if (!scenario) return;
    if (timedMode && timer <= 0 && !force) return;
    const o = evaluateSelections(scenario, picked, role);
    setOutcome(o);
    setClientSatisfaction((c) => Math.max(0, Math.min(100, c + o.trustImpact)));
    setSlaHealth((s) => Math.max(0, Math.min(100, s + o.slaImpact)));
    const entry: BoardEntry = { name, score: o.score, role, scenario: scenario.title, date: new Date().toLocaleString() };
    const next = [entry, ...board].sort((a,b) => b.score - a.score).slice(0, 20);
    setBoard(next); saveBoard(next);
  }

  useEffect(() => {
    if (timedMode && scenario && !outcome && timer === 0) {
      resolve(true);
    }
  }, [timer, timedMode, scenario, outcome]);

  const chosenLabels = useMemo(() => {
    if (!scenario) return [] as string[];
    return [...picked].map((id) => labelFor(scenario, id));
  }, [picked, scenario]);

  return (
    <div className="min-h-screen w-full bg-slate-50 p-6">
      <div className="mx-auto max-w-6xl space-y-6">
        <header className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-8 w-8" />
            <h1 className="text-2xl font-bold">MSSP Manager Simulator</h1>
            <Badge variant="outline" className="ml-2">Round {round}</Badge>
          </div>
          <div className="flex flex-wrap gap-2 items-center">
            <div className="flex items-center gap-2">
              <Users className="h-4 w-4"/>
              <Input value={name} onChange={(e) => setName(e.target.value)} className="w-36" placeholder="Your name" />
            </div>
            <div className="flex items-center gap-2">
              <Crown className="h-4 w-4"/>
              <Select value={role} onValueChange={(v) => setRole(v as Role)}>
                <SelectTrigger className="w-36"><SelectValue placeholder="Role"/></SelectTrigger>
                <SelectContent>
                  <SelectItem value="Analyst">Analyst</SelectItem>
                  <SelectItem value="Manager">Manager</SelectItem>
                  <SelectItem value="Executive">Executive</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4"/>
              <Select value={sector} onValueChange={(v: "All" | "Healthcare" | "Finance" | "Public Sector") => setSector(v)}>
                <SelectTrigger className="w-40"><SelectValue placeholder="Sector"/></SelectTrigger>
                <SelectContent>
                  <SelectItem value="All">All Sectors</SelectItem>
                  <SelectItem value="Healthcare">Healthcare</SelectItem>
                  <SelectItem value="Finance">Finance</SelectItem>
                  <SelectItem value="Public Sector">Public Sector</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Settings className="h-4 w-4"/>
              <Button variant={timedMode ? "default" : "secondary"} onClick={() => setTimedMode((t) => !t)} className="rounded-2xl">
                {timedMode ? "Timed: ON" : "Timed: OFF"}
              </Button>
            </div>
            <Button onClick={newScenario} className="rounded-2xl"><RefreshCw className="mr-2 h-4 w-4"/>New Scenario</Button>
            <Button variant="secondary" onClick={() => setShowReport(true)} disabled={!scenario || !outcome} className="rounded-2xl"><FileText className="mr-2 h-4 w-4"/>Report</Button>
          </div>
        </header>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <Card className="rounded-2xl">
            <CardHeader className="pb-2"><CardTitle className="text-base flex items-center gap-2"><Clock className="h-4 w-4"/>SLA Health</CardTitle></CardHeader>
            <CardContent><Progress value={slaHealth} /><div className="mt-2 text-sm">{slaHealth}%</div></CardContent>
          </Card>
          <Card className="rounded-2xl">
            <CardHeader className="pb-2"><CardTitle className="text-base flex items-center gap-2"><Users className="h-4 w-4"/>Client Satisfaction</CardTitle></CardHeader>
            <CardContent><Progress value={clientSatisfaction} /><div className="mt-2 text-sm">{clientSatisfaction}%</div></CardContent>
          </Card>
          <Card className="rounded-2xl">
            <CardHeader className="pb-2"><CardTitle className="text-base flex items-center gap-2"><Trophy className="h-4 w-4"/>Manager Score</CardTitle></CardHeader>
            <CardContent><Progress value={outcome?.score ?? 0} /><div className="mt-2 text-sm">{outcome ? `${outcome.score}/100` : "—"}</div></CardContent>
          </Card>
          <Card className="rounded-2xl">
            <CardHeader className="pb-2"><CardTitle className="text-base flex items-center gap-2"><Timer className="h-4 w-4"/>Round Timer</CardTitle></CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold">{timedMode && scenario && !outcome ? `${timer}s` : "—"}</div>
              <div className="text-xs text-slate-500">90s per round when Timed is ON</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <Card className="lg:col-span-2 rounded-2xl">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Network className="h-5 w-5"/>
                  <CardTitle>{scenario ? scenario.title : "Click New Scenario to start"}</CardTitle>
                </div>
                {scenario && (<Badge className={`${severityColor(scenario.severity)} text-white`}>{scenario.severity}</Badge>)}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {scenario ? (
                <>
                  <p className="text-sm text-slate-700">{scenario.synopsis}</p>
                  <Separator/>
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide mb-1">Indicators</div>
                      <ul className="list-disc pl-5 text-sm">{scenario.indicators.map((i) => (<li key={i}>{i}</li>))}</ul>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide mb-1">Assets</div>
                      <ul className="list-disc pl-5 text-sm">{scenario.assets.map((i) => (<li key={i}>{i}</li>))}</ul>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide mb-1">ATT&CK</div>
                      <ul className="list-disc pl-5 text-sm">{scenario.mitre.map((i) => (<li key={i}>{i}</li>))}</ul>
                    </div>
                  </div>
                </>
              ) : (<div className="text-slate-500">No active scenario.</div>)}
            </CardContent>
            <CardFooter className="flex gap-3">
              <Button onClick={newScenario} className="rounded-2xl"><Zap className="mr-2 h-4 w-4"/>Deal Scenario</Button>
              <Button onClick={() => resolve()} disabled={!scenario || !!outcome || (timedMode && timer <= 0)} className="rounded-2xl"><ChevronRight className="mr-2 h-4 w-4"/>Resolve</Button>
            </CardFooter>
          </Card>

          <Card className="rounded-2xl">
            <CardHeader>
              <CardTitle>Select Your Actions ({role})</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {scenario ? (
                <div className="space-y-2">
                  {scenario.actions.map((a) => {
                    const active = picked.has(a.id);
                    return (
                      <motion.button key={a.id} whileTap={{ scale: 0.98 }} onClick={() => togglePick(a.id)} className={`w-full text-left px-3 py-2 rounded-xl border ${active ? "bg-slate-900 text-white" : "bg-white"}`} title={a.hint || a.category}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{a.category}</Badge>
                            <span className="text-sm">{a.label}</span>
                          </div>
                          {active && <span className="text-xs opacity-80">Selected</span>}
                        </div>
                      </motion.button>
                    );
                  })}
                </div>
              ) : (<div className="text-sm text-slate-500">Deal a scenario first.</div>)}
            </CardContent>
            <CardFooter>
              <div className="text-xs text-slate-500">
                {role === "Analyst" && "Tip: Prioritize containment and evidence preservation before eradication."}
                {role === "Manager" && "Tip: Balance decisive containment with clear bridge comms and SLA awareness."}
                {role === "Executive" && "Tip: Focus on business impact, stakeholder comms, and regulatory exposure."}
              </div>
            </CardFooter>
          </Card>
        </div>

        <AnimatePresence>
          {outcome && scenario && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 10 }} className="grid grid-cols-1 gap-6 md:grid-cols-2">
              <Card className="rounded-2xl">
                <CardHeader><CardTitle>Resolution Outcome</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <div className="text-sm">Score: <strong>{outcome.score}/100</strong></div>
                  <div className="text-sm">SLA Impact: <strong>{outcome.slaImpact >= 0 ? "+" : ""}{outcome.slaImpact}</strong></div>
                  <div className="text-sm">Client Trust: <strong>{outcome.trustImpact >= 0 ? "+" : ""}{outcome.trustImpact}</strong></div>
                  {outcome.notes.length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide mb-1">Coaching Notes</div>
                      <ul className="list-disc pl-5 text-sm">{outcome.notes.map((n) => (<li key={n}>{n}</li>))}</ul>
                    </div>
                  )}
                  <Separator/>
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide mb-1">You chose</div>
                    <ul className="list-disc pl-5 text-sm">{chosenLabels.length ? chosenLabels.map((c) => <li key={c}>{c}</li>) : <li>—</li>}</ul>
                  </div>
                </CardContent>
              </Card>

              <Card className="rounded-2xl">
                <CardHeader><CardTitle>Manager Playbook (Best Practice)</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <ol className="list-decimal pl-5 text-sm space-y-1">{scenario.correct.map((id) => (<li key={id}>{labelFor(scenario, id)}</li>))}</ol>
                  {scenario.ok.length > 0 && (<div className="text-sm"><span className="font-semibold">Nice-to-haves:</span> {scenario.ok.map((id) => labelFor(scenario, id)).join(", ")}</div>)}
                  {scenario.bad.length > 0 && (<div className="text-sm"><span className="font-semibold">Avoid:</span> {scenario.bad.map((id) => labelFor(scenario, id)).join(", ")}</div>)}
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {scenario && (
          <Card className="rounded-2xl">
            <CardHeader><CardTitle>How to Prevent This (People • Process • Tech)</CardTitle></CardHeader>
            <CardContent className="grid grid-cols-1 gap-6 md:grid-cols-3">
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide mb-1">People</div>
                <ul className="list-disc pl-5 text-sm">{scenario.prevention.people.map((p) => (<li key={p}>{p}</li>))}</ul>
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide mb-1">Process</div>
                <ul className="list-disc pl-5 text-sm">{scenario.prevention.process.map((p) => (<li key={p}>{p}</li>))}</ul>
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide mb-1">Technology</div>
                <ul className="list-disc pl-5 text-sm">{scenario.prevention.tech.map((p) => (<li key={p}>{p}</li>))}</ul>
              </div>
            </CardContent>
          </Card>
        )}

        <Card className="rounded-2xl">
          <CardHeader><CardTitle>Tools Catalog – SIEM & SOAR</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide mb-1">SIEM</div>
              <ul className="list-disc pl-5 text-sm">{SIEM_TOOLS.map((t) => (<li key={t}>{t}</li>))}</ul>
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide mb-1">SOAR</div>
              <ul className="list-disc pl-5 text-sm">{SOAR_TOOLS.map((t) => (<li key={t}>{t}</li>))}</ul>
            </div>
          </CardContent>
        </Card>

        <Card className="rounded-2xl">
          <CardHeader><CardTitle className="flex items-center gap-2"><Trophy className="h-5 w-5"/>Leaderboard (Top 20)</CardTitle></CardHeader>
          <CardContent>
            {board.length === 0 ? (
              <div className="text-sm text-slate-500">Play a round to populate the leaderboard.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left">
                      <th className="py-2">#</th>
                      <th className="py-2">Name</th>
                      <th className="py-2">Role</th>
                      <th className="py-2">Scenario</th>
                      <th className="py-2">Score</th>
                      <th className="py-2">Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {board.map((e, i) => (
                      <tr key={`${e.name}-${e.date}-${i}`} className="border-t">
                        <td className="py-2">{i + 1}</td>
                        <td className="py-2">{e.name}</td>
                        <td className="py-2">{e.role}</td>
                        <td className="py-2">{e.scenario}</td>
                        <td className="py-2 font-semibold">{e.score}</td>
                        <td className="py-2">{e.date}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
          <CardFooter className="flex gap-2">
            <Button variant="secondary" onClick={() => { setBoard([]); saveBoard([]); }} className="rounded-2xl">Clear Leaderboard</Button>
          </CardFooter>
        </Card>

        <footer className="pt-4 text-center text-xs text-slate-500">© MSSP Manager Simulator • Timed rounds • Leaderboard • Role-based practice • Sector tailoring.</footer>

        <Dialog open={showReport} onOpenChange={setShowReport}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Generate Client-Facing Report</DialogTitle>
              <DialogDescription>Download a lightweight incident summary after resolution.</DialogDescription>
            </DialogHeader>
            {scenario && outcome ? (
              <div className="space-y-3">
                <Textarea className="min-h-[240px]" readOnly value={buildReport(scenario, outcome, [...picked], role)} />
                <div className="flex justify-end">
                  <Button onClick={() => download(buildReport(scenario, outcome, [...picked], role), `${scenario.id}-report.md`)} className="rounded-2xl"><FileText className="mr-2 h-4 w-4"/>Download .md</Button>
                </div>
              </div>
            ) : (<div className="text-sm text-slate-500">Resolve a scenario first.</div>)}
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}

export function runSelfTests(): TestResult[] {
  const results: TestResult[] = [];
  const ddos = SCENARIOS.find((s) => s.id === "ddos");
  if (!ddos) {
    results.push({ name: "fixture: ddos scenario exists", pass: false, details: "Missing ddos scenario" });
    return results;
  }

  const picksAllCorrect = new Set<string>(ddos.correct);
  const out1 = evaluateSelections(ddos, picksAllCorrect, "Analyst");
  results.push({ name: "evaluateSelections – all correct", pass: out1.score === 82, details: `score=${out1.score} expected=82` });

  const picksBadOnly = new Set<string>(["announce-down"]);
  const out2 = evaluateSelections(ddos, picksBadOnly, "Analyst");
  results.push({ name: "evaluateSelections – bad only clamps to 0", pass: out2.score === 0, details: `score=${out2.score} expected=0` });

  const rep = buildReport(ddos, out1, Array.from(picksAllCorrect), "Analyst");
  results.push({ name: "buildReport – lists actions as bullet lines", pass: rep.includes("\n- Enable emergency WAF rules / rate limiting"), details: rep.slice(0, 120) + "..." });

  results.push({ name: "labelFor – finds label", pass: labelFor(ddos, "waf-rules") === "Enable emergency WAF rules / rate limiting" });

  return results;
}
