import { useEffect, useMemo, useState } from "react";
import qrcode from "qrcode-generator";
import { api, fmtBytes, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Config, Iface, Rule, WGPeer } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, ListInput, Ltr, Modal, PageHead, Select, Tabs, TextInput, useToast } from "../ui";
import { useLinks } from "./Dashboard";
import RozanehTab from "./VpnRozaneh";
import V2RayTab from "./VpnV2Ray";
import PPPTab from "./VpnPPP";
import L2TPv3Tab from "./VpnL2TPv3";
import TunnelsTab from "./VpnTunnels";

// VPN page: WireGuard here, Rozaneh in VpnRozaneh.tsx, V2Ray in VpnV2Ray.tsx.

interface PeerState { public_key: string; endpoint?: string; allowed_ips: string[]; last_handshake: number; rx_bytes: number; tx_bytes: number }
interface IfState { name: string; public_key: string; listen_port: number; peers: PeerState[] }
interface Keypair { private_key: string; public_key: string; preshared_key?: string }

// ---- small IPv4 helpers -------------------------------------------------
export const ip2n = (ip: string) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
export const n2ip = (n: number) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".");
export function parseCidr(c: string): { ip: string; len: number; net: number; size: number } | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(c.trim());
  if (!m) return null;
  const len = Number(m[2]);
  if (len > 32 || m[1].split(".").some((x) => Number(x) > 255)) return null;
  const size = 2 ** (32 - len);
  return { ip: m[1], len, net: Math.floor(ip2n(m[1]) / size) * size, size };
}
const network = (c: string) => { const p = parseCidr(c); return p ? `${n2ip(p.net)}/${p.len}` : ""; };
export function nextFree(serverCidr: string, used: string[]): string {
  const p = parseCidr(serverCidr);
  if (!p) return "";
  const taken = new Set([ip2n(p.ip), ...used.map((u) => ip2n(u.split("/")[0]))]);
  for (let n = p.net + 1; n < p.net + p.size - 1; n++) if (!taken.has(n)) return n2ip(n);
  return "";
}
const fwComment = (name: string) => `WireGuard ${name}`;
export const ago = (now: number, ts: number) => {
  if (!ts) return t("هرگز", "never");
  const s = Math.max(0, now - ts);
  if (s < 60) return t(`${s} ثانیه پیش`, `${s}s ago`);
  if (s < 3600) return t(`${Math.floor(s / 60)} دقیقه پیش`, `${Math.floor(s / 60)} min ago`);
  if (s < 86400) return t(`${Math.floor(s / 3600)} ساعت پیش`, `${Math.floor(s / 3600)} h ago`);
  return t(`${Math.floor(s / 86400)} روز پیش`, `${Math.floor(s / 86400)} d ago`);
};
export const keygen = (psk = false) => api<Keypair>(`/api/v1/wireguard/keypair${psk ? "?psk=1" : ""}`, { method: "POST" });

export default function Vpn() {
  const [tab, setTab] = useState("wireguard");
  return (
    <div className="space-y-4">
      <PageHead title="VPN" sub={t("سرور و کلاینت VPN روی روتر", "VPN servers and clients on the router")} />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "wireguard", label: "WireGuard", icon: "lock" }, { id: "rozaneh", label: t("روزنه", "Rozaneh"), icon: "shield" }, { id: "v2ray", label: "V2Ray", icon: "globe" }, { id: "ppp", label: "SSTP / L2TP / PPTP", icon: "link" }, { id: "l2tpv3", label: "L2TPv3", icon: "link" }, { id: "tunnels", label: "GRE / IPIP / EoIP", icon: "link" }]} />
      {tab === "wireguard" && <WireGuardTab />}
      {tab === "rozaneh" && <RozanehTab />}
      {tab === "v2ray" && <V2RayTab />}
      {tab === "ppp" && <PPPTab />}
      {tab === "l2tpv3" && <L2TPv3Tab />}
      {tab === "tunnels" && <TunnelsTab />}
    </div>
  );
}

function WireGuardTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ interfaces: IfState[]; now: number }>("/api/v1/wireguard/status", 5000);
  const [creating, setCreating] = useState(false);
  if (!cfg) return null;
  const servers = cfg.interfaces.filter((i) => i.type === "wireguard");
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-ink-3">{t("هر اینترفیس WireGuard می‌تواند هم سرور برای گوشی و لپ‌تاپ باشد و هم تونل سایت‌به‌سایت به روتر دیگر.", "Each WireGuard interface can serve phones and laptops and also hold site-to-site tunnels to other routers.")}</p>
        <button className="btn btn-primary btn-sm" onClick={() => setCreating(true)}><Icon name="plus" className="size-4" />{t("سرور WireGuard جدید", "New WireGuard server")}</button>
      </div>
      {!servers.length && <div className="card"><Empty icon="lock" title={t("هنوز WireGuard ساخته نشده", "No WireGuard interface yet")}>{t("یک سرور بسازید، بعد برای هر گوشی یا لپ‌تاپ یک کلاینت اضافه کنید و QR آن را اسکن کنید.", "Create a server, then add a client per phone or laptop and scan its QR code.")}</Empty></div>}
      {servers.map((s) => <ServerCard key={s.name} ifc={s} live={(live?.interfaces || []).find((x) => x.name === s.name)} now={live?.now || 0} />)}
      {creating && <NewServer onClose={() => setCreating(false)} />}
    </div>
  );
}

/** Public WAN address, used as the default endpoint for client configs. */
export function useWanIP(cfg: Config | null) {
  const { addrs } = useLinks(0);
  const wan = cfg?.interface_lists?.WAN || [];
  for (const w of wan) for (const a of addrs[w] || []) if (!a.includes(":")) return a.split("/")[0];
  return "";
}

function NewServer({ onClose }: { onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const existing = (cfg?.interfaces || []).filter((i) => i.type === "wireguard").length;
  const [name, setName] = useState(`wg${existing}`);
  const [port, setPort] = useState(51820 + existing);
  const [addr, setAddr] = useState(`10.${100 + existing}.0.1/24`);
  const [endpoint, setEndpoint] = useState("");
  const [openFw, setOpenFw] = useState(true);
  const [asLan, setAsLan] = useState(true);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (!endpoint && wanIP) setEndpoint(wanIP); }, [wanIP]); // eslint-disable-line react-hooks/exhaustive-deps
  const taken = (cfg?.interfaces || []).some((i) => i.name === name);
  const valid = /^[a-z][a-z0-9-]{0,14}$/.test(name) && !taken && !!parseCidr(addr) && port > 0 && port < 65536;
  const save = async () => {
    setBusy(true);
    try {
      const kp = await keygen();
      const ok = await edit((c) => {
        c.interfaces.push({
          name, type: "wireguard", comment: t("سرور VPN", "VPN server"), addressing: "static", addresses: [addr],
          wireguard: { private_key: kp.private_key, listen_port: port, client_endpoint: endpoint || undefined, peers: [] },
        });
        if (asLan) {
          c.interface_lists = c.interface_lists || {};
          c.interface_lists.LAN = [...new Set([...(c.interface_lists.LAN || []), name])];
          if (c.dns?.enabled) c.dns.listen_on = [...new Set([...(c.dns.listen_on || []), name])];
        }
        if (openFw) setFwRule(c, name, port);
      }, t("سرور ساخته شد (هنوز اعمال نشده)", "Server created (not applied yet)"));
      if (ok) onClose();
    } catch (e) { alert((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} title={t("سرور WireGuard جدید", "New WireGuard server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid || busy} onClick={save}>{t("ساختن", "Create")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("نام اینترفیس", "Interface name")}><TextInput value={name} onChange={(v) => setName(v.toLowerCase())} /></Field>
        <Field label={t("پورت UDP", "UDP port")}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>
        <Field label={t("آدرس روتر در تونل", "Router address in the tunnel")} hint={t("کلاینت‌ها از همین رنج IP می‌گیرند", "Clients get addresses from this range")}><TextInput value={addr} onChange={setAddr} /></Field>
        <Field label={t("آدرس عمومی برای کلاینت‌ها", "Public address for clients")} hint={t("IP یا دامنه‌ای که از اینترنت به این روتر می‌رسد", "IP or domain that reaches this router from the internet")}><TextInput value={endpoint} placeholder="vpn.example.com" onChange={setEndpoint} /></Field>
        <div className="space-y-3 sm:col-span-2">
          <Check label={t("باز کردن پورت روی فایروال (از WAN)", "Open the port in the firewall (from WAN)")} checked={openFw} onChange={setOpenFw} />
          <Check label={t("کلاینت‌های VPN مثل LAN باشند", "Treat VPN clients like the LAN")} checked={asLan} onChange={setAsLan}
            hint={t("به شبکه‌ی داخلی، پنل و DNS روتر دسترسی دارند و از اینترنت روتر استفاده می‌کنند", "They reach the LAN, this panel and the router's DNS, and use the router's internet")} />
        </div>
        {taken && <p className="text-sm text-talk sm:col-span-2">{t("این نام قبلاً استفاده شده", "This name is already used")}</p>}
      </div>
    </Modal>
  );
}

/** Adds or updates the input rule for a WireGuard port, above the first input drop. */
function setFwRule(c: Config, name: string, port: number) {
  c.firewall = c.firewall || {};
  const filter = (c.firewall.filter = c.firewall.filter || []);
  const rule: Rule = { chain: "input", action: "accept", protocol: "udp", dst_port: String(port), in_interface_list: "WAN", comment: fwComment(name) };
  const at = filter.findIndex((r) => r.comment === fwComment(name));
  if (at >= 0) { filter[at] = rule; return; }
  let pos = filter.findIndex((r) => r.chain === "input" && (r.action === "drop" || r.action === "reject") && !r.connection_state);
  if (pos < 0) pos = filter.length;
  filter.splice(pos, 0, rule);
}

function removeServer(c: Config, name: string) {
  c.interfaces = c.interfaces.filter((i) => i.name !== name);
  for (const k of Object.keys(c.interface_lists || {})) c.interface_lists![k] = c.interface_lists![k].filter((x) => x !== name);
  if (c.dns?.listen_on) c.dns.listen_on = c.dns.listen_on.filter((x) => x !== name);
  if (c.firewall?.filter) c.firewall.filter = c.firewall.filter.filter((r) => r.comment !== fwComment(name));
}

function ServerCard({ ifc, live, now }: { ifc: Iface; live?: IfState; now: number }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const toast = useToast();
  const wg = ifc.wireguard!;
  const [pub, setPub] = useState("");
  const [dialog, setDialog] = useState<"client" | "site" | "settings" | null>(null);
  const [editPeer, setEditPeer] = useState<number | null>(null);
  useEffect(() => {
    if (live?.public_key) { setPub(live.public_key); return; }
    if (wg.private_key) api<{ public_key: string }>("/api/v1/wireguard/pubkey", { method: "POST", body: { private_key: wg.private_key } }).then((r) => setPub(r.public_key)).catch(() => setPub(""));
  }, [wg.private_key, live?.public_key]);
  const peers = wg.peers || [];
  const endpoint = wg.client_endpoint || wanIP;
  const lan = (cfg?.interface_lists?.LAN || []).includes(ifc.name);
  const fwOpen = (cfg?.firewall?.filter || []).some((r) => r.comment === fwComment(ifc.name));
  const copy = (s: string) => { navigator.clipboard?.writeText(s).then(() => toast(t("کپی شد", "Copied"))); };
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="lock" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        {live ? <Chip tone="idle">{t("فعال", "running")}</Chip> : <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>}
        {ifc.disabled && <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>}
        <div className="ms-auto flex flex-wrap gap-2">
          <button className="btn btn-primary btn-sm" onClick={() => setDialog("client")}><Icon name="plus" className="size-4" />{t("کلاینت (گوشی / لپ‌تاپ)", "Client (phone / laptop)")}</button>
          <button className="btn btn-sm" onClick={() => setDialog("site")}><Icon name="link" className="size-4" />{t("سایت‌به‌سایت", "Site-to-site")}</button>
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setDialog("settings")}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`سرور ${ifc.name} و همه‌ی کلاینت‌هایش حذف شود؟`, `Delete ${ifc.name} and all its clients?`)} onConfirm={() => edit((c) => removeServer(c, ifc.name), t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("پورت", "Port")}><Ltr className="mono">UDP {wg.listen_port || "—"}</Ltr>{!fwOpen && <span className="ms-2 text-xs text-ring">{t("روی فایروال باز نیست", "not open in firewall")}</span>}</Info>
        <Info label={t("آدرس تونل", "Tunnel address")}><Ltr className="mono">{(ifc.addresses || []).join(", ") || "—"}</Ltr></Info>
        <Info label={t("آدرس عمومی", "Public address")}><Ltr className="mono">{endpoint ? `${endpoint}${endpoint.includes(":") ? "" : ":" + (wg.listen_port || 51820)}` : "—"}</Ltr></Info>
        <Info label={t("دسترسی کلاینت‌ها", "Client access")}>{lan ? t("مثل LAN", "like the LAN") : t("فقط تونل", "tunnel only")}</Info>
        <div className="sm:col-span-2 xl:col-span-4">
          <span className="text-xs text-ink-3">{t("کلید عمومی روتر", "Router public key")}</span>
          <div className="flex items-center gap-2"><Ltr className="mono truncate text-xs">{pub || "…"}</Ltr>{pub && <button className="icon-btn" onClick={() => copy(pub)} title={t("کپی", "Copy")}><Icon name="file" className="size-4" /></button>}</div>
        </div>
      </div>
      {!peers.length ? <div className="border-t border-line"><Empty title={t("هنوز کلاینتی ندارد", "No clients yet")} /></div> : (
        <div className="overflow-x-auto border-t border-line">
          <table className="w-full text-sm">
            <thead className="bg-surface-2 text-xs text-ink-3"><tr>
              <th className="px-4 py-2 text-start font-medium">{t("نام", "Name")}</th><th className="px-4 py-2 text-start font-medium">{t("آدرس‌ها", "Addresses")}</th>
              <th className="px-4 py-2 text-start font-medium">{t("وضعیت", "State")}</th><th className="px-4 py-2 text-start font-medium">{t("از کجا", "From")}</th>
              <th className="px-4 py-2 text-end font-medium">{t("دریافت / ارسال", "RX / TX")}</th><th className="px-4 py-2" />
            </tr></thead>
            <tbody className="divide-y divide-line">
              {peers.map((p, k) => {
                const st = live?.peers.find((x) => x.public_key === p.public_key);
                const online = !!st && st.last_handshake > 0 && now - st.last_handshake < 180;
                return (
                  <tr key={p.public_key + k}>
                    <td className="px-4 py-2.5 font-medium">{p.comment || <span className="text-ink-3">{t("بی‌نام", "unnamed")}</span>}{p.endpoint && <span className="ms-2"><Chip tone="sky">{t("سایت", "site")}</Chip></span>}</td>
                    <td className="px-4 py-2.5 text-xs"><Ltr className="mono">{p.allowed_ips.join(", ")}</Ltr></td>
                    <td className="px-4 py-2.5 text-xs">{online ? <Chip tone="idle">{t("وصل", "online")}</Chip> : <Chip tone="off">{t("قطع", "offline")}</Chip>}<span className="ms-2 text-ink-3">{st ? ago(now, st.last_handshake) : ""}</span></td>
                    <td className="px-4 py-2.5 text-xs"><Ltr className="mono">{st?.endpoint || p.endpoint || "—"}</Ltr></td>
                    <td className="px-4 py-2.5 text-end text-xs"><Ltr className="mono">{st ? `${fmtBytes(st.rx_bytes)} / ${fmtBytes(st.tx_bytes)}` : "—"}</Ltr></td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-end">
                      <button className="icon-btn" onClick={() => setEditPeer(k)}><Icon name="edit" className="size-4" /></button>
                      <ConfirmButton className="icon-btn text-talk" question={t(`«${p.comment || p.public_key.slice(0, 8)}» حذف شود؟ دیگر نمی‌تواند وصل شود.`, `Delete "${p.comment || p.public_key.slice(0, 8)}"? It will no longer connect.`)}
                        onConfirm={() => edit((c) => { const w = c.interfaces.find((i) => i.name === ifc.name)!.wireguard!; w.peers = (w.peers || []).filter((_, j) => j !== k); }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {dialog === "client" && <NewClient ifc={ifc} serverPub={pub} endpoint={endpoint} onClose={() => setDialog(null)} />}
      {dialog === "site" && <SitePeer ifc={ifc} serverPub={pub} index={-1} onClose={() => setDialog(null)} />}
      {editPeer !== null && <SitePeer ifc={ifc} serverPub={pub} index={editPeer} onClose={() => setEditPeer(null)} />}
      {dialog === "settings" && <ServerSettings ifc={ifc} onClose={() => setDialog(null)} />}
    </div>
  );
}

export const Info = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div><div className="text-xs text-ink-3">{label}</div><div>{children}</div></div>
);

function ServerSettings({ ifc, onClose }: { ifc: Iface; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const wg = ifc.wireguard!;
  const [port, setPort] = useState(wg.listen_port || 51820);
  const [addr, setAddr] = useState((ifc.addresses || [])[0] || "");
  const [endpoint, setEndpoint] = useState(wg.client_endpoint || "");
  const [dns, setDns] = useState(wg.client_dns || "");
  const [disabled, setDisabled] = useState(!!ifc.disabled);
  const [asLan, setAsLan] = useState((cfg?.interface_lists?.LAN || []).includes(ifc.name));
  const [openFw, setOpenFw] = useState((cfg?.firewall?.filter || []).some((r) => r.comment === fwComment(ifc.name)));
  const save = async () => {
    const ok = await edit((c) => {
      const i = c.interfaces.find((x) => x.name === ifc.name)!;
      i.addresses = [addr];
      i.disabled = disabled || undefined;
      i.wireguard = { ...i.wireguard!, listen_port: port, client_endpoint: endpoint || undefined, client_dns: dns || undefined };
      c.interface_lists = c.interface_lists || {};
      const L = (c.interface_lists.LAN || []).filter((x) => x !== ifc.name);
      c.interface_lists.LAN = asLan ? [...L, ifc.name] : L;
      if (c.dns) {
        const D = (c.dns.listen_on || []).filter((x) => x !== ifc.name);
        c.dns.listen_on = asLan && c.dns.enabled ? [...D, ifc.name] : D;
      }
      if (openFw) setFwRule(c, ifc.name, port);
      else if (c.firewall?.filter) c.firewall.filter = c.firewall.filter.filter((r) => r.comment !== fwComment(ifc.name));
    }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open onClose={onClose} title={`${t("تنظیمات", "Settings")} ${ifc.name}`}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!parseCidr(addr)} onClick={save}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("پورت UDP", "UDP port")}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>
        <Field label={t("آدرس روتر در تونل", "Router address in the tunnel")}><TextInput value={addr} onChange={setAddr} /></Field>
        <Field label={t("آدرس عمومی برای کلاینت‌ها", "Public address for clients")} hint={t("خالی = IP فعلی WAN", "empty = current WAN IP")}><TextInput value={endpoint} onChange={setEndpoint} /></Field>
        <Field label={t("DNS برای کلاینت‌ها", "DNS for clients")} hint={t("خالی = خود روتر یا 1.1.1.1", "empty = the router, or 1.1.1.1")}><TextInput value={dns} onChange={setDns} /></Field>
        <div className="space-y-3 sm:col-span-2">
          <Check label={t("پورت روی فایروال باز باشد (از WAN)", "Port open in the firewall (from WAN)")} checked={openFw} onChange={setOpenFw} />
          <Check label={t("کلاینت‌های VPN مثل LAN باشند", "Treat VPN clients like the LAN")} checked={asLan} onChange={setAsLan} />
          <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />
        </div>
        <p className="text-xs text-ink-3 sm:col-span-2">{t("تغییر پورت یا آدرس عمومی یعنی باید کانفیگ کلاینت‌ها را هم عوض کنید.", "Changing the port or public address means the client configs must change too.")}</p>
      </div>
    </Modal>
  );
}

function NewClient({ ifc, serverPub, endpoint, onClose }: { ifc: Iface; serverPub: string; endpoint: string; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const wg = ifc.wireguard!;
  const serverCidr = (ifc.addresses || [])[0] || "";
  const used = (wg.peers || []).flatMap((p) => p.allowed_ips);
  const [name, setName] = useState("");
  const [ip, setIp] = useState(() => nextFree(serverCidr, used));
  const [mode, setMode] = useState<"full" | "split">("full");
  const lanList = cfg?.interface_lists?.LAN || [];
  const asLan = lanList.includes(ifc.name);
  const lanNets = useMemo(() => [...new Set([network(serverCidr), ...(cfg?.interfaces || []).filter((i) => lanList.includes(i.name) && i.name !== ifc.name).flatMap((i) => (i.addresses || []).map(network))].filter(Boolean))], [cfg, serverCidr]); // eslint-disable-line react-hooks/exhaustive-deps
  const [dns, setDns] = useState(wg.client_dns || (asLan && cfg?.dns?.enabled ? serverCidr.split("/")[0] : "1.1.1.1"));
  const [result, setResult] = useState<{ name: string; file: string; conf: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const p = parseCidr(serverCidr);
  const ipOk = !!p && /^\d+\.\d+\.\d+\.\d+$/.test(ip) && Math.floor(ip2n(ip) / p.size) * p.size === p.net && !used.some((u) => u.split("/")[0] === ip) && ip !== p.ip;
  const port = wg.listen_port || 51820;
  const ep = endpoint.includes(":") ? endpoint : `${endpoint}:${port}`;
  const create = async () => {
    setBusy(true);
    try {
      const kp = await keygen(true);
      const label = name.trim() || `client-${ip.split(".").pop()}`;
      const ok = await edit((c) => {
        const w = c.interfaces.find((i) => i.name === ifc.name)!.wireguard!;
        w.peers = [...(w.peers || []), { comment: label, public_key: kp.public_key, preshared_key: kp.preshared_key, allowed_ips: [`${ip}/32`] }];
      });
      if (!ok) return;
      const conf = [
        "[Interface]", `PrivateKey = ${kp.private_key}`, `Address = ${ip}/32`, dns ? `DNS = ${dns}` : "", "",
        "[Peer]", `PublicKey = ${serverPub}`, `PresharedKey = ${kp.preshared_key}`, `Endpoint = ${ep}`,
        `AllowedIPs = ${mode === "full" ? "0.0.0.0/0" : lanNets.join(", ")}`, "PersistentKeepalive = 25", "",
      ].filter((l, i, a) => l !== "" || a[i - 1] !== "").join("\n");
      // WireGuard apps take the file name as tunnel name: ASCII, max 15 chars
      const ascii = label.replace(/[^A-Za-z0-9_=+.-]+/g, "-").replace(/^-+|-+$/g, "");
      setResult({ name: label, file: (/[A-Za-z0-9]/.test(ascii) ? ascii : `${ifc.name}-${ip.split(".").pop()}`).slice(0, 15), conf });
    } catch (e) { alert((e as Error).message); } finally { setBusy(false); }
  };
  if (result) return <ClientResult name={result.name} file={`${result.file}.conf`} conf={result.conf} onClose={onClose} />;
  return (
    <Modal open onClose={onClose} title={t(`کلاینت جدید روی ${ifc.name}`, `New client on ${ifc.name}`)}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!ipOk || !serverPub || !endpoint || busy} onClick={create}>{t("ساختن و نمایش QR", "Create and show QR")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("نام", "Name")}><TextInput ltr={false} value={name} placeholder={t("مثلاً گوشی علی", "e.g. Ali's phone")} onChange={setName} /></Field>
        <Field label={t("آدرس IP کلاینت", "Client IP address")}><TextInput value={ip} onChange={setIp} /></Field>
        <Field label={t("چه ترافیکی از VPN برود", "What goes through the VPN")}>
          <Select value={mode} onChange={(v) => setMode(v as "full" | "split")} options={[
            { value: "full", label: t("همه‌ی اینترنت (از اینترنت روتر)", "All internet (via this router)") },
            { value: "split", label: t("فقط شبکه‌ی داخلی", "Only the internal network") },
          ]} />
        </Field>
        <Field label="DNS"><TextInput value={dns} onChange={setDns} /></Field>
        {mode === "split" && <p className="text-xs text-ink-3 sm:col-span-2">{t("شبکه‌ها: ", "Networks: ")}<Ltr className="mono">{lanNets.join(", ")}</Ltr></p>}
        {!endpoint && <p className="text-sm text-talk sm:col-span-2">{t("آدرس عمومی روتر معلوم نیست؛ در تنظیمات سرور واردش کنید.", "The router's public address is unknown; set it in the server settings.")}</p>}
        {!ipOk && ip && <p className="text-sm text-talk sm:col-span-2">{t("این IP در رنج تونل نیست یا قبلاً استفاده شده.", "This IP is outside the tunnel range or already used.")}</p>}
      </div>
    </Modal>
  );
}

export function ClientResult({ name, file, conf, onClose, steps }: { name: string; file: string; conf: string; onClose: () => void; steps?: React.ReactNode }) {
  const svg = useMemo(() => { const q = qrcode(0, "M"); q.addData(conf); q.make(); return q.createSvgTag({ cellSize: 4, margin: 4, scalable: true }); }, [conf]);
  const download = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([conf], { type: "text/plain" }));
    a.download = file;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <Modal open wide onClose={onClose} title={t(`کانفیگ «${name}»`, `Config for "${name}"`)}
      footer={<><button className="btn" onClick={download}><Icon name="down" className="size-4" />{t("دانلود", "Download")} <Ltr>{file}</Ltr></button><button className="btn btn-primary" onClick={onClose}>{t("تمام", "Done")}</button></>}>
      <div className="grid gap-5 md:grid-cols-[260px_1fr]">
        <div className="rounded-lg bg-white p-2" dangerouslySetInnerHTML={{ __html: svg }} />
        <div className="min-w-0 space-y-3">
          <div className="rounded-md bg-ring-soft p-3 text-sm text-ring">{t("کلید خصوصی این کلاینت فقط همین حالا نمایش داده می‌شود و روی روتر ذخیره نمی‌شود. اگر گم شد، کلاینت را حذف کنید و دوباره بسازید.", "This client's private key is shown only now and is not stored on the router. If it is lost, delete the client and create it again.")}</div>
          {steps || <ol className="list-decimal space-y-1 ps-5 text-sm text-ink-2">
            <li>{t("در گوشی برنامه‌ی WireGuard را نصب کنید و با «+» این QR را اسکن کنید (یا فایل را در ویندوز Import کنید).", "Install the WireGuard app and scan this QR with \"+\" (or import the file on Windows).")}</li>
            <li>{t("در صفحه‌ی «تغییرات» این تغییر را اعمال و تأیید کنید.", "Apply and confirm the change on the Changes page.")}</li>
          </ol>}
          <pre className="ltr mono max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-surface-2 p-3 text-left text-xs">{conf}</pre>
        </div>
      </div>
    </Modal>
  );
}

function SitePeer({ ifc, serverPub, index, onClose }: { ifc: Iface; serverPub: string; index: number; onClose: () => void }) {
  const { edit } = useConfig();
  const orig: WGPeer = index >= 0 ? ifc.wireguard!.peers![index] : { public_key: "", allowed_ips: [], persistent_keepalive: 25, route_allowed_ips: true };
  const [p, setP] = useState<WGPeer>({ ...orig });
  const set = (x: Partial<WGPeer>) => setP((o) => ({ ...o, ...x }));
  const keyOk = /^[A-Za-z0-9+/]{43}=$/.test(p.public_key.trim());
  const save = async () => {
    const clean: WGPeer = { ...p, public_key: p.public_key.trim(), allowed_ips: p.allowed_ips.filter(Boolean), endpoint: p.endpoint || undefined, preshared_key: p.preshared_key || undefined, persistent_keepalive: p.persistent_keepalive || undefined, route_allowed_ips: p.route_allowed_ips || undefined };
    const ok = await edit((c) => {
      const w = c.interfaces.find((i) => i.name === ifc.name)!.wireguard!;
      const list = [...(w.peers || [])];
      if (index >= 0) list[index] = clean; else list.push(clean);
      w.peers = list;
    }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={index >= 0 ? t("ویرایش همتا", "Edit peer") : t("تونل سایت‌به‌سایت", "Site-to-site tunnel")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!keyOk || !p.allowed_ips.length} onClick={save}>{t("ذخیره", "Save")}</button></>}>
      {index < 0 && <p className="mb-4 text-sm text-ink-3">{t("روی روتر طرف مقابل، این کلید عمومی را به عنوان همتا وارد کنید: ", "On the other router, add this public key as a peer: ")}<Ltr className="mono text-xs">{serverPub}</Ltr></p>}
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("نام", "Name")}><TextInput ltr={false} value={p.comment} onChange={(v) => set({ comment: v })} /></Field>
        <Field label={t("کلید عمومی طرف مقابل", "Remote public key")}><TextInput value={p.public_key} onChange={(v) => set({ public_key: v })} /></Field>
        <Field label="Endpoint" hint={t("آدرس طرف مقابل؛ اگر او به ما وصل می‌شود خالی بگذارید", "The other side's address; leave empty if it connects to us")}><TextInput value={p.endpoint} placeholder="203.0.113.7:51820" onChange={(v) => set({ endpoint: v })} /></Field>
        <Field label="Preshared key" hint={t("اختیاری", "optional")}><TextInput type="password" value={p.preshared_key} onChange={(v) => set({ preshared_key: v })} /></Field>
        <Field label={t("شبکه‌های پشت طرف مقابل (Allowed IPs)", "Networks behind the other side (Allowed IPs)")} hint="10.100.0.2/32, 192.168.20.0/24"><ListInput value={p.allowed_ips} onChange={(v) => set({ allowed_ips: v })} rows={3} /></Field>
        <div className="space-y-3">
          <Field label="Keepalive"><TextInput type="number" value={p.persistent_keepalive} onChange={(v) => set({ persistent_keepalive: v ? Number(v) : undefined })} /></Field>
          <Check label={t("مسیر برای این شبکه‌ها ساخته شود", "Add routes for these networks")} checked={!!p.route_allowed_ips} onChange={(v) => set({ route_allowed_ips: v })} />
        </div>
      </div>
    </Modal>
  );
}
