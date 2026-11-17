import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { fmtBytes, fmtDuration, fmtRate, t } from "../lib";
import { useConfig, usePoll } from "../store";
import { Chip, Icon, Ltr, PageHead, StatCard } from "../ui";

interface Sys {
  hostname: string; version: string; kernel: string; uptime_seconds: number; load: number[];
  memory: { total: number; available: number }; cpu_percent: number; cores: number;
  disk?: { total: number; available: number }; services: Record<string, string>;
}

export interface LinkInfo {
  ifname: string; operstate: string; address?: string; mtu: number; flags: string[];
  linkinfo?: { info_kind?: string; info_slave_kind?: string };
  master?: string;
  stats64?: { rx: { bytes: number; packets: number }; tx: { bytes: number; packets: number } };
}
export interface AddrInfo { ifname: string; addr_info: { family: string; local: string; prefixlen: number; scope: string }[] }

/** Live link list with rx/tx rates computed between two polls. */
export function useLinks(ms = 3000) {
  const [data] = usePoll<{ links: LinkInfo[]; addresses: AddrInfo[] }>("/api/v1/interfaces", ms);
  const prev = useRef<{ at: number; bytes: Record<string, [number, number]> } | null>(null);
  const [rates, setRates] = useState<Record<string, { rx: number; tx: number }>>({});
  useEffect(() => {
    if (!data?.links) return;
    const now = Date.now();
    const bytes: Record<string, [number, number]> = {};
    for (const l of data.links) bytes[l.ifname] = [l.stats64?.rx.bytes || 0, l.stats64?.tx.bytes || 0];
    const p = prev.current;
    if (p) {
      const dt = (now - p.at) / 1000;
      const r: Record<string, { rx: number; tx: number }> = {};
      for (const [k, [rx, tx]] of Object.entries(bytes)) {
        const o = p.bytes[k];
        if (o && dt > 0) r[k] = { rx: Math.max(0, ((rx - o[0]) * 8) / dt), tx: Math.max(0, ((tx - o[1]) * 8) / dt) };
      }
      setRates(r);
    }
    prev.current = { at: now, bytes };
  }, [data]);
  const addrs: Record<string, string[]> = {};
  for (const a of data?.addresses || []) addrs[a.ifname] = a.addr_info.filter((x) => x.scope !== "link").map((x) => `${x.local}/${x.prefixlen}`);
  return { links: data?.links || [], addrs, rates };
}

const SVC: Record<string, string> = {
  "mahan-agent": "Mahan agent", "systemd-networkd": t("شبکه (networkd)", "Network (networkd)"), nftables: t("فایروال", "Firewall"),
  "kea-dhcp4-server": "DHCP (Kea)", unbound: "DNS (Unbound)", chrony: "NTP (chrony)", frr: t("مسیریابی پویا (FRR)", "Dynamic routing (FRR)"),
};

export default function Dashboard() {
  const [sys] = usePoll<Sys>("/api/v1/system", 5000);
  const [leases] = usePoll<unknown[]>("/api/v1/dhcp/leases", 15000);
  const { cfg } = useConfig();
  const { links, addrs, rates } = useLinks();
  const ifaces = (cfg?.interfaces || []).map((i) => i.name);
  const shown = links.filter((l) => ifaces.includes(l.ifname));
  const memUsed = sys ? sys.memory.total - sys.memory.available : 0;
  const memPct = sys ? Math.round((100 * memUsed) / sys.memory.total) : 0;
  const diskPct = sys?.disk ? Math.round((100 * (sys.disk.total - sys.disk.available)) / sys.disk.total) : 0;
  const wan = cfg?.interface_lists?.WAN || [];
  return (
    <div className="space-y-5">
      <PageHead title={t("داشبورد", "Dashboard")} sub={sys && <><Ltr>{sys.hostname}</Ltr> · <Ltr>{sys.version}</Ltr> · {t("کرنل", "kernel")} <Ltr>{sys.kernel}</Ltr></>} />
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard label={t("پردازنده", "CPU")} value={sys ? `${Math.round(sys.cpu_percent)}%` : "…"} sub={sys && t(`${sys.cores} هسته · بار ${sys.load.map((x) => x.toFixed(2)).join(" / ")}`, `${sys.cores} cores · load ${sys.load.map((x) => x.toFixed(2)).join(" / ")}`)} icon="cpu" tone={sys && sys.cpu_percent > 85 ? "talk" : "accent"} />
        <StatCard label={t("حافظه", "Memory")} value={sys ? `${memPct}%` : "…"} sub={sys && `${fmtBytes(memUsed)} / ${fmtBytes(sys.memory.total)}`} icon="memory" tone={memPct > 90 ? "talk" : "purple"} />
        <StatCard label={t("زمان روشن بودن", "Uptime")} value={sys ? fmtDuration(sys.uptime_seconds) : "…"} icon="clock" tone="sky" />
        <StatCard label={t("کلاینت‌های DHCP", "DHCP clients")} value={leases ? leases.length : "…"} sub={sys?.disk && t(`دیسک ${diskPct}% پر`, `disk ${diskPct}% used`)} icon="dhcp" tone="idle" />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="card overflow-hidden xl:col-span-2">
          <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
            <h2 className="card-title">{t("اینترفیس‌ها و ترافیک", "Interfaces and traffic")}</h2>
            <Link to="/interfaces" className="text-sm text-accent">{t("مدیریت", "Manage")}</Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-surface-2 text-xs text-ink-3">
                <tr><th className="px-4 py-2 text-start font-medium">{t("نام", "Name")}</th><th className="px-4 py-2 text-start font-medium">{t("وضعیت", "State")}</th><th className="px-4 py-2 text-start font-medium">{t("آدرس", "Address")}</th><th className="px-4 py-2 text-end font-medium">{t("دریافت", "RX")}</th><th className="px-4 py-2 text-end font-medium">{t("ارسال", "TX")}</th></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {shown.map((l) => {
                  const up = l.operstate === "UP" || (l.operstate === "UNKNOWN" && l.flags.includes("UP"));
                  return (
                    <tr key={l.ifname}>
                      <td className="px-4 py-2.5 font-medium"><Ltr>{l.ifname}</Ltr>{wan.includes(l.ifname) && <span className="ms-2"><Chip tone="sky">WAN</Chip></span>}{l.master && <span className="ms-2 text-xs text-ink-3">→ <Ltr>{l.master}</Ltr></span>}</td>
                      <td className="px-4 py-2.5">{up ? <Chip tone="idle">{t("فعال", "up")}</Chip> : <Chip tone="off">{t("قطع", "down")}</Chip>}</td>
                      <td className="px-4 py-2.5 text-xs"><Ltr className="mono">{(addrs[l.ifname] || []).join("  ") || "—"}</Ltr></td>
                      <td className="px-4 py-2.5 text-end"><Ltr className="mono text-xs">{fmtRate(rates[l.ifname]?.rx)}</Ltr></td>
                      <td className="px-4 py-2.5 text-end"><Ltr className="mono text-xs">{fmtRate(rates[l.ifname]?.tx)}</Ltr></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="border-b border-line px-5 py-3.5"><h2 className="card-title">{t("سرویس‌ها", "Services")}</h2></div>
          <ul className="divide-y divide-line">
            {sys && Object.entries(sys.services).map(([k, v]) => {
              const optional = k === "frr" || (k === "kea-dhcp4-server" && !(cfg?.dhcp_servers || []).length);
              const tone = v === "active" ? "idle" : optional && v === "inactive" ? "off" : "talk";
              return (
                <li key={k} className="flex items-center gap-3 px-5 py-2.5 text-sm">
                  <span className={`size-2 rounded-full bg-${tone}`} />
                  <span className="flex-1">{SVC[k] || k}</span>
                  <span className={`text-xs text-${tone}`}>{v === "active" ? t("فعال", "running") : optional && v === "inactive" ? t("استفاده نشده", "not used") : v === "inactive" ? t("خاموش", "stopped") : v === "failed" ? t("خطا", "failed") : v}</span>
                </li>
              );
            })}
          </ul>
          <div className="border-t border-line px-5 py-3 text-xs text-ink-3"><Icon name="shield" className="me-1 inline size-3.5" />{t(`${cfg?.firewall?.filter?.length || 0} قانون فایروال، ${cfg?.firewall?.nat?.length || 0} قانون NAT`, `${cfg?.firewall?.filter?.length || 0} firewall rules, ${cfg?.firewall?.nat?.length || 0} NAT rules`)}</div>
        </div>
      </div>
    </div>
  );
}
