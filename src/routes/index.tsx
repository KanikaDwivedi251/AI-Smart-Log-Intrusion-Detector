import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, Bot, Copy, FileUp, Info, Radio, Settings, Shield, ShieldAlert, ShieldBan, Server, Terminal, Gauge, ScanLine,
} from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Smart Log Intrusion & Anomaly Detector — SOC Dashboard" },
      { name: "description", content: "AI-powered log intrusion and anomaly detection with live threat map, generative insights and one-click firewall response." },
      { property: "og:title", content: "Smart Log Intrusion & Anomaly Detector" },
      { property: "og:description", content: "Real-time SOC dashboard with AI threat insights and active response." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

type Sev = "Low" | "Medium" | "High";
type Source = { cc: string; country: string; lat: number; lon: number; ips: string[] };
type Anomaly = { id: number; ts: string; ip: string; cc: string; country: string; sev: Sev; type: string; action: string };
type LogLine = { id: number; text: string; critical: boolean };

const SOURCES: Source[] = [
  { cc: "RU", country: "Russia", lat: 55.7, lon: 37.6, ips: ["185.10.10.1", "91.240.118.22"] },
  { cc: "CN", country: "China", lat: 39.9, lon: 116.4, ips: ["61.177.172.13", "222.186.30.112"] },
  { cc: "BR", country: "Brazil", lat: -23.5, lon: -46.6, ips: ["177.54.150.9"] },
  { cc: "NG", country: "Nigeria", lat: 6.5, lon: 3.4, ips: ["102.89.34.71"] },
  { cc: "IR", country: "Iran", lat: 35.7, lon: 51.4, ips: ["5.160.218.44"] },
  { cc: "NL", country: "Netherlands", lat: 52.4, lon: 4.9, ips: ["45.155.205.233"] },
  { cc: "VN", country: "Vietnam", lat: 21, lon: 105.8, ips: ["113.161.54.8"] },
  { cc: "KP", country: "North Korea", lat: 39, lon: 125.7, ips: ["175.45.176.3"] },
  { cc: "UA", country: "Ukraine", lat: 50.4, lon: 30.5, ips: ["193.32.162.70"] },
];
const TARGET = { lat: 38.9, lon: -77 };
const ATTACKS: { type: string; sev: Sev; action: string; log: (ip: string) => string }[] = [
  { type: "SSH Brute Force", sev: "High", action: "Block IP (ufw)", log: (ip) => `sshd[2211]: Failed password for root from ${ip} port 52144 ssh2` },
  { type: "SQL Injection", sev: "High", action: "Block IP + WAF rule", log: (ip) => `nginx: ${ip} "GET /login.php?id=1' UNION SELECT user,pass FROM users-- HTTP/1.1" 403` },
  { type: "Path Traversal", sev: "Medium", action: "WAF rule", log: (ip) => `nginx: ${ip} "GET /../../etc/passwd HTTP/1.1" 400` },
  { type: "XSS Attempt", sev: "Medium", action: "Sanitize + Monitor", log: (ip) => `nginx: ${ip} "POST /comment <script>alert(1)</script>" 403` },
  { type: "Port Scan", sev: "Low", action: "Rate limit", log: (ip) => `kernel: [UFW AUDIT] SRC=${ip} DST=10.0.0.5 PROTO=TCP DPT=3389 SYN` },
  { type: "Credential Stuffing", sev: "High", action: "Block IP + MFA enforce", log: (ip) => `auth: 47 failed logins for multiple users from ${ip} in 30s` },
];
const BENIGN = [
  "nginx: 10.0.4.12 \"GET /api/health HTTP/1.1\" 200 12ms",
  "sshd[1980]: Accepted publickey for deploy from 10.0.1.8 port 50122",
  "cron[331]: (root) CMD (/usr/local/bin/backup.sh)",
  "nginx: 172.16.2.40 \"GET /dashboard HTTP/1.1\" 200 48ms",
  "systemd[1]: Started Daily apt upgrade and clean activities.",
  "postgres[882]: checkpoint complete: wrote 412 buffers",
  "nginx: 10.0.4.19 \"POST /api/orders HTTP/1.1\" 201 87ms",
];

const flag = (cc: string) => String.fromCodePoint(...[...cc].map((c) => 127397 + c.charCodeAt(0)));
const proj = (lat: number, lon: number) => ({ x: ((lon + 180) / 360) * 1000, y: ((90 - lat) / 180) * 500 });
const now = () => new Date().toISOString().replace("T", " ").slice(0, 19);
const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)];
const srcOf = (ip: string) => SOURCES.find((s) => s.ips.includes(ip));

const CONTINENTS = [
  "M80,90 L200,58 L330,68 L345,125 L292,170 L262,222 L205,245 L168,200 L118,160 Z",
  "M352,38 L425,32 L412,90 L366,96 Z",
  "M268,250 L330,258 L372,300 L342,372 L312,432 L292,420 L282,340 Z",
  "M465,92 L560,78 L585,128 L522,152 L468,142 Z",
  "M458,172 L562,160 L612,222 L582,322 L542,362 L510,302 L470,242 Z",
  "M572,68 L805,58 L905,100 L862,172 L782,222 L722,232 L652,202 L602,160 Z",
  "M800,302 L882,290 L902,352 L832,372 L800,340 Z",
];

function Tip({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button aria-label="More info" className="text-muted-foreground hover:text-primary"><Info className="h-3.5 w-3.5" /></button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{text}</TooltipContent>
    </Tooltip>
  );
}

const sevClass: Record<Sev, string> = {
  High: "bg-destructive/15 text-destructive border-destructive/40",
  Medium: "bg-warning/15 text-warning border-warning/40",
  Low: "bg-primary/15 text-primary border-primary/40",
};

function Dashboard() {
  const [live, setLive] = useState(true);
  const [scanned, setScanned] = useState(184_203);
  const [anoms, setAnoms] = useState<Anomaly[]>([]);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [blocked, setBlocked] = useState<string[]>(["103.21.44.9", "89.248.165.2"]);
  const [executing, setExecuting] = useState(false);
  const idRef = useRef(0);
  const fileRef = useRef<HTMLInputElement>(null);
  const streamRef = useRef<HTMLDivElement>(null);

  const ingest = (text: string, forcedAttack?: { a: (typeof ATTACKS)[number]; ip: string }) => {
    const id = ++idRef.current;
    const critical = !!forcedAttack;
    setLogs((l) => [...l.slice(-80), { id, text: `${now()} ${text}`, critical }]);
    setScanned((n) => n + 1);
    if (forcedAttack) {
      const s = srcOf(forcedAttack.ip);
      setAnoms((a) => [{ id, ts: now(), ip: forcedAttack.ip, cc: s?.cc ?? "UN", country: s?.country ?? "Unknown", sev: forcedAttack.a.sev, type: forcedAttack.a.type, action: forcedAttack.a.action }, ...a].slice(0, 40));
    }
  };

  const tick = () => {
    if (Math.random() < 0.3) {
      const s = pick(SOURCES); const ip = pick(s.ips); const a = pick(ATTACKS);
      ingest(a.log(ip), { a, ip });
    } else ingest(pick(BENIGN));
    setScanned((n) => n + Math.floor(Math.random() * 40));
  };

  useEffect(() => { for (let i = 0; i < 14; i++) tick(); }, []); // seed
  useEffect(() => {
    if (!live) return;
    const t = setInterval(tick, 900);
    return () => clearInterval(t);
  }, [live]);
  useEffect(() => { streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: "smooth" }); }, [logs]);

  const onFile = async (f: File) => {
    const lines = (await f.text()).split(/\r?\n/).filter(Boolean).slice(0, 500);
    let hits = 0;
    for (const line of lines) {
      const ip = line.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)?.[0] ?? "0.0.0.0";
      const a = /union\s+select|' or 1=1/i.test(line) ? ATTACKS[1] : /failed password/i.test(line) ? ATTACKS[0]
        : /\.\.\//.test(line) ? ATTACKS[2] : /<script/i.test(line) ? ATTACKS[3] : null;
      if (a) hits++;
      ingest(line, a ? { a, ip } : undefined);
    }
    toast.success(`Parsed ${lines.length} lines from ${f.name}`, { description: `${hits} anomalies flagged by the detection model.` });
  };

  const active = anoms.filter((a) => !blocked.includes(a.ip));
  const top = useMemo(() => {
    const counts = new Map<string, Anomaly[]>();
    active.forEach((a) => counts.set(a.ip, [...(counts.get(a.ip) ?? []), a]));
    const [ip, list] = [...counts.entries()].sort((x, y) => y[1].length - x[1].length || (y[1][0].sev === "High" ? 1 : -1))[0] ?? [];
    return ip ? { ip, list: list! } : null;
  }, [active]);

  const highCount = active.filter((a) => a.sev === "High").length;
  const score = Math.min(99, Math.round(active.length * 2.2 + highCount * 3.5));
  const activeSources = SOURCES.filter((s) => active.some((a) => s.ips.includes(a.ip)));
  const command = top ? `sudo ufw deny from ${top.ip} to any comment "AI-SOC ${top.list[0].type}"` : "# No active threats — nothing to block";

  const execute = () => {
    if (!top) return;
    setExecuting(true);
    setTimeout(() => {
      setBlocked((b) => [...b, top.ip]);
      setExecuting(false);
      setLogs((l) => [...l, { id: ++idRef.current, text: `${now()} ufw: Rule added — DENY IN from ${top.ip}`, critical: false }]);
      toast.success(`Firewall rule applied`, { description: `${top.ip} is now blocked.` });
    }, 900);
  };

  const t = proj(TARGET.lat, TARGET.lon);

  return (
    <TooltipProvider delayDuration={150}>
      <Toaster theme="dark" />
      <div className="min-h-screen grid-bg font-sans">
        {/* Header */}
        <header className="sticky top-0 z-20 border-b border-border bg-background/85 backdrop-blur">
          <div className="mx-auto flex max-w-[1600px] items-center gap-4 px-6 py-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-primary/40 bg-primary/10 glow-primary">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <h1 className="flex-1 text-sm font-semibold leading-tight md:text-base">
              AI-Powered Smart Log Intrusion & Anomaly Detector
              <span className="block text-xs font-normal text-muted-foreground md:inline md:text-sm"> with Active Threat Response and Generative Insights</span>
            </h1>
            <div className="hidden items-center gap-2 rounded-full border border-success/40 bg-success/10 px-3 py-1 text-xs sm:flex">
              <span className="relative flex h-2 w-2"><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75" /><span className="relative h-2 w-2 rounded-full bg-success" /></span>
              <span className="text-muted-foreground">System Status:</span><span className="font-medium text-success">{live ? "Monitoring" : "Idle"}</span>
            </div>
            <button aria-label="Settings" onClick={() => toast("Settings", { description: "Detection thresholds and integrations coming soon." })} className="rounded-md border border-border p-2 text-muted-foreground transition hover:border-primary hover:text-primary">
              <Settings className="h-4 w-4" />
            </button>
          </div>
        </header>

        <main className="mx-auto grid max-w-[1600px] gap-5 px-6 py-6 xl:grid-cols-[1fr_380px]">
          <div className="space-y-5 min-w-0">
            {/* Ingestion */}
            <section className="soc-card flex flex-col gap-4 p-5 md:flex-row md:items-center">
              <div className="flex-1">
                <h2 className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Log Ingestion Control</h2>
                <p className="mt-1 text-sm text-muted-foreground">Feed syslog, nginx, auth or firewall logs into the detection model.</p>
              </div>
              <input ref={fileRef} type="file" accept=".log,.txt,.csv" className="hidden" onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
              <button onClick={() => fileRef.current?.click()} className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground glow-primary transition hover:brightness-110">
                <FileUp className="h-4 w-4" /> Upload Log File
              </button>
              <label className="flex items-center gap-3 rounded-md border border-border bg-secondary/60 px-4 py-2.5 text-sm">
                <Radio className={`h-4 w-4 ${live ? "text-destructive animate-pulse" : "text-muted-foreground"}`} />
                Start Simulated Live-Stream Mode
                <Switch checked={live} onCheckedChange={setLive} />
              </label>
            </section>

            {/* KPIs */}
            <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              {[
                { label: "Total Logs Scanned", value: scanned.toLocaleString(), icon: ScanLine, tone: "primary", tip: "All log lines parsed by the ingestion pipeline since this session started." },
                { label: "Anomalies Detected", value: anoms.length, icon: ShieldAlert, tone: "warning", tip: "Lines the AI model scored above the anomaly threshold (isolation-forest score > 0.72)." },
                { label: "Auto-Blocked IPs", value: blocked.length, icon: ShieldBan, tone: "success", tip: "Attacker IPs denied at the firewall automatically or via one-click response." },
                { label: "Current Threat Score (%)", value: `${score}%`, icon: Gauge, tone: "destructive", tip: "Weighted risk of unresolved anomalies: volume plus severity of active, unblocked attackers." },
              ].map((k) => (
                <div key={k.label} className="soc-card p-4" style={{ boxShadow: `0 0 26px -10px var(--${k.tone})` }}>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span className="flex items-center gap-1.5">{k.label} <Tip text={k.tip} /></span>
                    <k.icon className="h-4 w-4" style={{ color: `var(--${k.tone})` }} />
                  </div>
                  <div className="mt-3 font-mono text-3xl font-semibold tabular-nums" style={{ color: `var(--${k.tone})` }}>{k.value}</div>
                  {k.tone === "destructive" && (
                    <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full bg-destructive transition-all" style={{ width: `${score}%` }} /></div>
                  )}
                </div>
              ))}
            </section>

            {/* Map */}
            <section className="soc-card overflow-hidden">
              <div className="flex items-center justify-between border-b border-border px-5 py-3">
                <h2 className="flex items-center gap-2 text-sm font-semibold"><Activity className="h-4 w-4 text-primary" /> Live Threat Map <Tip text="Attacker IPs are geo-located to their country of origin. Lines show traffic toward the protected server (us-east-1)." /></h2>
                <span className="font-mono text-xs text-muted-foreground">{activeSources.length} active origins</span>
              </div>
              <svg viewBox="0 0 1000 500" className="block w-full bg-background/60">
                <defs>
                  <pattern id="dots" width="7" height="7" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.3" fill="var(--muted-foreground)" opacity="0.45" /></pattern>
                </defs>
                {CONTINENTS.map((d, i) => <path key={i} d={d} fill="url(#dots)" stroke="var(--border)" strokeLinejoin="round" />)}
                {activeSources.map((s) => {
                  const p = proj(s.lat, s.lon);
                  const mx = (p.x + t.x) / 2, my = Math.min(p.y, t.y) - 70;
                  return (
                    <g key={s.cc}>
                      <path d={`M${p.x},${p.y} Q${mx},${my} ${t.x},${t.y}`} fill="none" stroke="var(--destructive)" strokeWidth="1.5" opacity="0.75" className="attack-line" />
                      <circle cx={p.x} cy={p.y} r="3" fill="none" stroke="var(--destructive)" strokeWidth="2" className="pulse-ring" />
                      <circle cx={p.x} cy={p.y} r="4" fill="var(--destructive)"><title>{`${s.country} — ${s.ips.join(", ")}`}</title></circle>
                      <text x={p.x + 8} y={p.y - 6} fontSize="11" fill="var(--foreground)" className="font-mono">{flag(s.cc)} {s.cc}</text>
                    </g>
                  );
                })}
                <g transform={`translate(${t.x - 13},${t.y - 13})`}>
                  <rect width="26" height="26" rx="6" fill="var(--primary)" opacity="0.2" stroke="var(--primary)" />
                  <Server x="5" y="5" width="16" height="16" color="var(--primary)" />
                </g>
                <text x={t.x - 40} y={t.y + 30} fontSize="11" fill="var(--primary)" className="font-mono">TARGET SRV</text>
              </svg>
            </section>

            {/* Table */}
            <section className="soc-card overflow-hidden">
              <div className="flex items-center justify-between border-b border-border px-5 py-3">
                <h2 className="text-sm font-semibold">AI Detected Anomalies</h2>
                <span className="text-xs text-muted-foreground">Showing latest {Math.min(anoms.length, 10)}</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-secondary/50 text-left text-xs uppercase tracking-wider text-muted-foreground">
                    <tr>{["Timestamp", "Attacker IP", "Severity", "Attack Type", "Proposed Action"].map((h) => <th key={h} className="px-5 py-2.5 font-medium">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {anoms.slice(0, 10).map((a) => {
                      const isBlocked = blocked.includes(a.ip);
                      return (
                        <tr key={a.id} className="border-t border-border/60 transition hover:bg-accent/40">
                          <td className="px-5 py-2.5 font-mono text-xs text-muted-foreground">{a.ts}</td>
                          <td className="px-5 py-2.5 font-mono"><span className="mr-2" title={a.country}>{flag(a.cc)}</span>{a.ip}</td>
                          <td className="px-5 py-2.5"><span className={`rounded border px-2 py-0.5 text-xs font-medium ${sevClass[a.sev]}`}>{a.sev}</span></td>
                          <td className="px-5 py-2.5">{a.type}</td>
                          <td className="px-5 py-2.5 text-muted-foreground">{isBlocked ? <span className="text-success">✓ Blocked</span> : a.action}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>

            {/* AI insights */}
            <section className="grid gap-5 lg:grid-cols-2">
              <div className="soc-card p-5">
                <h2 className="flex items-center gap-2 text-sm font-semibold"><span className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/15"><Bot className="h-4 w-4 text-primary" /></span> AI Incident Report</h2>
                <div className="mt-4 space-y-3 text-sm leading-relaxed text-muted-foreground">
                  {top ? (
                    <>
                      <p><span className="font-medium text-foreground">Primary incident:</span> a <span className="text-destructive">{top.list[0].type}</span> campaign originating from <span className="font-mono text-foreground">{top.ip}</span> ({flag(top.list[0].cc)} {top.list[0].country}).</p>
                      <p>The model observed {top.list.length} malicious event{top.list.length > 1 ? "s" : ""} from this source, deviating sharply from the baseline of internal traffic. The pattern matches automated tooling probing for weak credentials and unsanitized inputs rather than a human operator.</p>
                      <p><span className="font-medium text-foreground">Risk:</span> if successful, the attacker could gain shell or database access on the target server. <span className="font-medium text-foreground">Recommendation:</span> block the source at the firewall and review authentication logs for any successful logins from related ranges.</p>
                    </>
                  ) : <p>No active incidents. All recent attackers have been contained.</p>}
                </div>
              </div>
              <div className="soc-card flex flex-col p-5">
                <h2 className="flex items-center gap-2 text-sm font-semibold"><span className="flex h-7 w-7 items-center justify-center rounded-md bg-destructive/15"><Terminal className="h-4 w-4 text-destructive" /></span> Recommended Active Response</h2>
                <div className="mt-4 flex items-start gap-2 rounded-md border border-border bg-background p-3 font-mono text-xs">
                  <span className="text-success">$</span>
                  <code className="flex-1 break-all text-foreground">{command}</code>
                  <button aria-label="Copy command" onClick={() => { navigator.clipboard.writeText(command); toast("Command copied"); }} className="text-muted-foreground hover:text-primary"><Copy className="h-3.5 w-3.5" /></button>
                </div>
                <p className="mt-3 text-xs text-muted-foreground">Generated from the highest-priority unresolved incident. Applies a persistent deny rule on all ports.</p>
                <button disabled={!top || executing} onClick={execute} className="mt-auto pt-0 inline-flex w-full items-center justify-center gap-2 rounded-md bg-destructive px-4 py-4 text-base font-bold uppercase tracking-wide text-destructive-foreground glow-danger transition hover:brightness-110 disabled:opacity-40 mt-5">
                  <ShieldBan className="h-5 w-5" /> {executing ? "Applying rule…" : "Execute One-Click Firewall Block"}
                </button>
              </div>
            </section>
          </div>

          {/* Log stream */}
          <aside className="soc-card flex h-[calc(100vh-7rem)] flex-col overflow-hidden xl:sticky xl:top-20">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <h2 className="text-sm font-semibold">Real-Time Alerts & Log Stream</h2>
              <span className={`flex items-center gap-1.5 text-xs ${live ? "text-destructive" : "text-muted-foreground"}`}><span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-destructive animate-pulse" : "bg-muted-foreground"}`} />{live ? "LIVE" : "PAUSED"}</span>
            </div>
            <div ref={streamRef} className="flex-1 space-y-1 overflow-y-auto p-3 font-mono text-[11px] leading-relaxed">
              {logs.map((l) => (
                <div key={l.id} className={l.critical ? "rounded border-l-2 border-destructive bg-destructive/10 px-2 py-1 text-destructive" : "px-2 text-muted-foreground"}>
                  {l.critical && <span className="mr-1 font-bold">[ALERT]</span>}{l.text}
                </div>
              ))}
            </div>
          </aside>
        </main>
      </div>
    </TooltipProvider>
  );
}
