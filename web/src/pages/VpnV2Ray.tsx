import { useEffect, useMemo, useState } from "react";
import qrcode from "qrcode-generator";
import { api, fmtBytes, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Config, Iface, Rule, V2RayServer } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, Ltr, Modal, Select, TextInput, useToast } from "../ui";
import { Info, keygen, useWanIP } from "./Vpn";
import { LogView, RoutingFields, liveChip, removeIface, routingLabel, routingOf, setRouting } from "./VpnRozaneh";
import type { Routing, RzLive } from "./VpnRozaneh";

// V2Ray tab. sing-box runs both sides: a TUN client for share links
// (vless/vmess/trojan/ss/hysteria2) routed by policy, and a VLESS-Reality
// or Shadowsocks-2022 server for phones (v2rayNG, v2rayN, Hiddify, Streisand).

const FW = "V2Ray server";
const TARGETS = ["www.microsoft.com:443", "www.apple.com:443", "www.speedtest.net:443", "dl.google.com:443"];

/** Short description of a share link for display; null when not one. */
export function linkSummary(link: string): { proto: string; server: string } | null {
  const l = link.trim();
  const m = /^(vless|vmess|trojan|ss|hysteria2|hy2):\/\/(.+)$/i.exec(l);
  if (!m) return null;
  const proto = m[1].toLowerCase();
  if (proto === "vmess") {
    try {
      const j = JSON.parse(atob(m[2].split("#")[0].replace(/-/g, "+").replace(/_/g, "/")));
      return j.add ? { proto: "VMess", server: `${j.add}:${j.port}` } : null;
    } catch { return null; }
  }
  const body = m[2].split("#")[0].split("?")[0];
  const at = body.lastIndexOf("@");
  let hp = at >= 0 ? body.slice(at + 1) : "";
  if (!hp && proto === "ss") { try { const d = atob(body); hp = d.slice(d.lastIndexOf("@") + 1); } catch { return null; } }
  hp = hp.replace(/\/$/, "");
  if (!/:\d+$/.test(hp)) return null;
  const sec = /[?&]security=reality/.test(l) ? " + Reality" : /[?&]security=tls/.test(l) ? " + TLS" : "";
  const names: Record<string, string> = { vless: "VLESS", trojan: "Trojan", ss: "Shadowsocks", hysteria2: "Hysteria2", hy2: "Hysteria2" };
  return { proto: names[proto] + sec, server: hp };
}

const b64url = (std: string) => std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64std = (url: string) => { const s = url.replace(/-/g, "+").replace(/_/g, "/"); return s + "=".repeat((4 - (s.length % 4)) % 4); };
const randHex = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");
const randKey16 = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : (() => { const h = randHex(16); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`; })());

export default function V2RayTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ interfaces: RzLive[]; server: RzLive | null }>("/api/v1/v2ray/status", 5000);
  const [dialog, setDialog] = useState<"client" | "server" | null>(null);
  if (!cfg) return null;
  const clients = cfg.interfaces.filter((i) => i.type === "v2ray");
  return (
    <div className="space-y-6">
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("اتصال روتر به سرور V2Ray", "Connect this router to a V2Ray server")}</h2>
            <p className="text-sm text-ink-3">{t("لینک VLESS، VMess، Trojan، Shadowsocks یا Hysteria2 را وارد کنید و انتخاب کنید ترافیک کدام دستگاه‌ها از آن برود.", "Paste a VLESS, VMess, Trojan, Shadowsocks or Hysteria2 link and choose which traffic goes through it.")}</p>
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => setDialog("client")}><Icon name="plus" className="size-4" />{t("اتصال جدید", "New connection")}</button>
        </div>
        {!clients.length && <div className="card"><Empty icon="globe" title={t("هنوز اتصالی ساخته نشده", "No connection yet")}>{t("لینک را از پنل سرور V2Ray یا فروشنده‌ی سرویس بگیرید (همان لینکی که در v2rayNG وارد می‌کنید).", "Get the link from your V2Ray server panel or provider (the same link you would add to v2rayNG).")}</Empty></div>}
        {clients.map((c) => <ClientCard key={c.name} ifc={c} live={(live?.interfaces || []).find((x) => x.name === c.name)} />)}
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("سرور V2Ray روی این روتر", "V2Ray server on this router")}</h2>
            <p className="text-sm text-ink-3">{t("گوشی و لپ‌تاپ با v2rayNG، v2rayN، Hiddify یا Streisand از بیرون به این روتر وصل می‌شوند. VLESS Reality دامنه و گواهی لازم ندارد.", "Phones and laptops connect from outside with v2rayNG, v2rayN, Hiddify or Streisand. VLESS Reality needs no domain or certificate.")}</p>
          </div>
          {!cfg.v2ray_server && <button className="btn btn-primary btn-sm" onClick={() => setDialog("server")}><Icon name="plus" className="size-4" />{t("راه‌اندازی سرور", "Set up the server")}</button>}
        </div>
        {cfg.v2ray_server ? <ServerCard s={cfg.v2ray_server} live={live?.server || undefined} /> : <div className="card"><Empty icon="server" title={t("سرور V2Ray راه‌اندازی نشده", "No V2Ray server yet")} /></div>}
      </section>
      {dialog === "client" && <ClientDialog onClose={() => setDialog(null)} />}
      {dialog === "server" && <NewServer onClose={() => setDialog(null)} />}
    </div>
  );
}

// ---- client ---------------------------------------------------------------

function ClientDialog({ ifc, routing: initial, onClose }: { ifc?: Iface; routing?: Routing; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const used = new Set((cfg?.interfaces || []).map((i) => i.name));
  let n = 1;
  while (used.has(`v2r${n}`)) n++;
  const [name, setName] = useState(ifc?.name || `v2r${n}`);
  const [link, setLink] = useState(ifc?.v2ray?.link || "");
  const [disabled, setDisabled] = useState(!!ifc?.disabled);
  const [routing, setR] = useState<Routing>(initial || { mode: "except_iran", devices: [], dns: true, block: false });
  const sum = linkSummary(link);
  const valid = (!!ifc || (/^[a-z][a-z0-9-]{0,14}$/.test(name) && !used.has(name))) && !!sum && (routing.mode !== "devices" || routing.devices.length > 0);
  const save = async () => {
    const ok = await edit((c) => {
      if (ifc) {
        const i = c.interfaces.find((x) => x.name === ifc.name)!;
        i.v2ray = { link: link.trim() };
        i.disabled = disabled || undefined;
      } else {
        c.interfaces.push({ name, type: "v2ray", comment: `${sum!.proto} ${sum!.server}`, v2ray: { link: link.trim() } });
        c.interface_lists = c.interface_lists || {};
        c.interface_lists.WAN = [...new Set([...(c.interface_lists.WAN || []), name])];
      }
      setRouting(c, ifc?.name || name, routing);
    }, ifc ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("اتصال ساخته شد (هنوز اعمال نشده)", "Connection created (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={ifc ? `${t("تنظیمات", "Settings")} ${ifc.name}` : t("اتصال روتر به سرور V2Ray", "Connect the router to a V2Ray server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{ifc ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <Field label={t("لینک", "Link")} hint={sum ? <span className="text-idle">{sum.proto} — <Ltr className="mono">{sum.server}</Ltr></span> : link ? <span className="text-talk">{t("لینک شناخته نشد", "Link not recognised")}</span> : "vless:// vmess:// trojan:// ss:// hysteria2://"}>
            <textarea className="input mono ltr min-h-28 text-left text-xs" dir="ltr" spellCheck={false} value={link} placeholder="vless://…" onChange={(e) => setLink(e.target.value)} />
          </Field>
          {!ifc && <Field label={t("نام اینترفیس", "Interface name")}><TextInput value={name} onChange={(v) => setName(v.toLowerCase())} /></Field>}
          {ifc && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
          <p className="text-xs text-ink-3">{t("پشتیبانی‌شده: TCP، WebSocket، gRPC، HTTPUpgrade و HTTP/2، با TLS یا Reality. XHTTP هنوز پشتیبانی نمی‌شود.", "Supported: TCP, WebSocket, gRPC, HTTPUpgrade and HTTP/2, with TLS or Reality. XHTTP is not supported yet.")}</p>
        </div>
        <RoutingFields value={routing} onChange={setR} />
      </div>
    </Modal>
  );
}

function ClientCard({ ifc, live }: { ifc: Iface; live?: RzLive }) {
  const { cfg, edit } = useConfig();
  const [editing, setEditing] = useState(false);
  const sum = linkSummary(ifc.v2ray?.link || "");
  const routing = routingOf((cfg?.policy_routes || []).find((p) => p.interface === ifc.name));
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="globe" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        {liveChip(ifc, live)}
        <div className="ms-auto flex gap-2">
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`اتصال ${ifc.name} حذف شود؟`, `Delete connection ${ifc.name}?`)} onConfirm={() => edit((c) => removeIface(c, ifc.name), t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("پروتکل", "Protocol")}>{sum?.proto || "—"}</Info>
        <Info label={t("سرور", "Server")}><Ltr className="mono">{sum?.server || "—"}</Ltr></Info>
        <Info label={t("دانلود / آپلود", "Down / Up")}><Ltr className="mono">{live?.up ? `${fmtBytes(live.rx_bytes)} / ${fmtBytes(live.tx_bytes)}` : "—"}</Ltr></Info>
        <Info label={t("مسیریابی", "Routing")}>{routingLabel(routing)}</Info>
      </div>
      <LogView live={live} />
      {editing && <ClientDialog ifc={ifc} routing={routing} onClose={() => setEditing(false)} />}
    </div>
  );
}

// ---- server ---------------------------------------------------------------

/** Opens the server port from WAN: redirect public→listen, accept listen. */
function setServerFw(c: Config, s: V2RayServer) {
  const pub = s.public_port || 443, listen = s.listen_port || 8444;
  const protos = s.protocol === "shadowsocks" ? ["tcp", "udp"] : ["tcp"];
  c.firewall = c.firewall || {};
  const filter = (c.firewall.filter = (c.firewall.filter || []).filter((r) => r.comment !== FW));
  let pos = filter.findIndex((r) => r.chain === "input" && (r.action === "drop" || r.action === "reject") && !r.connection_state);
  if (pos < 0) pos = filter.length;
  filter.splice(pos, 0, ...protos.map((p): Rule => ({ chain: "input", action: "accept", protocol: p, dst_port: String(listen), in_interface_list: "WAN", comment: FW })));
  const nat = (c.firewall.nat = (c.firewall.nat || []).filter((r) => r.comment !== FW));
  if (pub !== listen) nat.unshift(...protos.map((p): Rule => ({ chain: "dstnat", action: "redirect", protocol: p, dst_port: String(pub), in_interface_list: "WAN", to_port: String(listen), comment: FW })));
}

function clearServerFw(c: Config) {
  if (c.firewall?.filter) c.firewall.filter = c.firewall.filter.filter((r) => r.comment !== FW);
  if (c.firewall?.nat) c.firewall.nat = c.firewall.nat.filter((r) => r.comment !== FW);
}

function NewServer({ onClose }: { onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const rz = (cfg?.interfaces || []).find((i) => i.type === "rozaneh_server");
  const rzPort = rz ? rz.rozaneh_server?.public_port || 443 : 0;
  const [proto, setProto] = useState<"vless_reality" | "shadowsocks">("vless_reality");
  const [port, setPort] = useState(rzPort === 443 ? 2053 : 443);
  const [target, setTarget] = useState(TARGETS[0]);
  const [address, setAddress] = useState("");
  const [allowLan, setAllowLan] = useState(false);
  const [busy, setBusy] = useState(false);
  const valid = port > 0 && port < 65536 && port !== rzPort && (proto !== "vless_reality" || /^[a-z0-9.-]+:\d+$/i.test(target));
  const save = async () => {
    setBusy(true);
    try {
      const s: V2RayServer = { protocol: proto === "vless_reality" ? undefined : proto, public_port: port === 443 ? undefined : port, address: address || undefined, allow_lan: allowLan || undefined, users: [] };
      if (proto === "vless_reality") {
        const kp = await keygen();
        s.reality_private_key = b64url(kp.private_key);
        s.reality_short_id = randHex(4);
        s.reality_target = target === TARGETS[0] ? undefined : target;
      } else s.ss_key = randKey16();
      const ok = await edit((c) => { c.v2ray_server = s; setServerFw(c, s); }, t("سرور ساخته شد (هنوز اعمال نشده)", "Server created (not applied yet)"));
      if (ok) onClose();
    } catch (e) { alert((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} title={t("راه‌اندازی سرور V2Ray", "Set up a V2Ray server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid || busy} onClick={save}>{t("ساختن", "Create")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("پروتکل", "Protocol")}>
          <Select value={proto} onChange={(v) => setProto(v as "vless_reality")} options={[
            { value: "vless_reality", label: t("VLESS + Reality (پیشنهادی)", "VLESS + Reality (recommended)") },
            { value: "shadowsocks", label: "Shadowsocks 2022" },
          ]} />
        </Field>
        <Field label={t("پورت عمومی", "Public port")} hint={port === rzPort ? <span className="text-talk">{t("سرور روزنه از این پورت استفاده می‌کند", "The Rozaneh server uses this port")}</span> : undefined}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>
        {proto === "vless_reality" && <Field label={t("سایت پوششی Reality", "Reality cover site")} hint={t("یک سایت خارجی واقعی با TLS 1.3؛ ترافیک شبیه اتصال به همین سایت دیده می‌شود.", "A real foreign site with TLS 1.3; the traffic looks like a connection to it.")}>
          <TextInput value={target} onChange={setTarget} />
        </Field>}
        <Field label={t("آدرس عمومی برای لینک‌ها", "Public address for links")} hint={t("خالی = IP فعلی WAN", "empty = current WAN IP")}><TextInput value={address} placeholder="vpn.example.com" onChange={setAddress} /></Field>
        <div className="space-y-3 sm:col-span-2">
          <Check label={t("دسترسی کلاینت‌ها به شبکه‌ی داخلی و روتر", "Clients may reach the LAN and this router")} checked={allowLan} onChange={setAllowLan}
            hint={t("خاموش = فقط اینترنت", "off = internet only")} />
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("پورت ", "Port ")}<Ltr className="mono">{port}</Ltr>{t(" از WAN روی فایروال باز می‌شود. اگر روتر پشت مودم یا روتر دیگری است، آن پورت را روی آن دستگاه به این روتر فوروارد کنید.", " is opened from WAN in the firewall. If this router is behind a modem or another router, forward that port to this router there.")}
          </div>
        </div>
      </div>
    </Modal>
  );
}

function ServerCard({ s, live }: { s: V2RayServer; live?: RzLive }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const [pub, setPub] = useState("");
  const [show, setShow] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  const [settings, setSettings] = useState(false);
  const reality = (s.protocol || "vless_reality") === "vless_reality";
  useEffect(() => {
    if (!reality || !s.reality_private_key) return;
    api<{ public_key: string }>("/api/v1/wireguard/pubkey", { method: "POST", body: { private_key: b64std(s.reality_private_key) } }).then((r) => setPub(b64url(r.public_key))).catch(() => setPub(""));
  }, [s.reality_private_key, reality]);
  const host = s.address || wanIP;
  const port = s.public_port || 443;
  const target = s.reality_target || TARGETS[0];
  const sni = target.replace(/:\d+$/, "");
  const users = s.users || [];
  const linkFor = (u: { name: string; secret: string }) => {
    const h = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    if (reality) return `vless://${u.secret}@${h}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${s.reality_short_id}&type=tcp#${encodeURIComponent(u.name)}`;
    return `ss://${encodeURIComponent(`2022-blake3-aes-128-gcm:${s.ss_key}:${u.secret}`)}@${h}:${port}#${encodeURIComponent(u.name)}`;
  };
  const fwOpen = (cfg?.firewall?.filter || []).some((r) => r.comment === FW);
  const chip = s.disabled ? <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>
    : !live?.active || live.active === "inactive" ? <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>
    : live.active === "active" ? <Chip tone="idle">{t("فعال", "running")}</Chip>
    : live.active === "failed" ? <Chip tone="talk">{t("خطا", "failed")}</Chip> : <Chip tone="ring">{live.active}</Chip>;
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="server" className="size-5 text-accent" />
        <h2 className="card-title">{reality ? "VLESS + Reality" : "Shadowsocks 2022"}</h2>
        {chip}
        <div className="ms-auto flex flex-wrap gap-2">
          <button className="btn btn-primary btn-sm" disabled={reality && !pub} onClick={() => setAdding(true)}><Icon name="plus" className="size-4" />{t("کاربر جدید", "New user")}</button>
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setSettings(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t("سرور V2Ray و همه‌ی کاربرانش حذف شود؟", "Delete the V2Ray server and all its users?")} onConfirm={() => edit((c) => { c.v2ray_server = undefined; clearServerFw(c); }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آدرس برای کلاینت‌ها", "Address for clients")}><Ltr className="mono">{host || "—"}:{port}</Ltr>{!fwOpen && <span className="ms-2 text-xs text-ring">{t("روی فایروال باز نیست", "not open in firewall")}</span>}</Info>
        {reality ? <Info label={t("سایت پوششی", "Cover site")}><Ltr className="mono">{target}</Ltr></Info> : <Info label={t("رمزنگاری", "Cipher")}><Ltr className="mono">2022-blake3-aes-128-gcm</Ltr></Info>}
        <Info label={t("دسترسی کلاینت‌ها", "Client access")}>{s.allow_lan ? t("اینترنت و شبکه‌ی داخلی", "internet and LAN") : t("فقط اینترنت", "internet only")}</Info>
        <Info label={t("کاربران", "Users")}>{users.filter((u) => !u.disabled).length} / {users.length}</Info>
      </div>
      {!users.length ? <div className="border-t border-line"><Empty title={t("هنوز کاربری ندارد", "No users yet")} /></div> : (
        <div className="overflow-x-auto border-t border-line">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-line">
              {users.map((u, k) => (
                <tr key={u.secret}>
                  <td className="px-4 py-2.5 font-medium">{u.name}{u.disabled && <span className="ms-2 chip bg-talk-soft text-talk">{t("غیرفعال", "disabled")}</span>}</td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-end">
                    <button className="btn btn-sm" disabled={!host || (reality && !pub)} onClick={() => setShow(k)}><Icon name="link" className="size-4" />{t("لینک و QR", "Link & QR")}</button>
                    <button className="btn btn-sm ms-1" onClick={() => edit((c) => { const x = c.v2ray_server!.users![k]; x.disabled = !x.disabled || undefined; }, t("تغییر کرد (هنوز اعمال نشده)", "Changed (not applied yet)"))}>{u.disabled ? t("فعال کن", "Enable") : t("غیرفعال کن", "Disable")}</button>
                    <ConfirmButton className="icon-btn text-talk" question={t(`«${u.name}» حذف شود؟`, `Delete "${u.name}"?`)} onConfirm={() => edit((c) => { c.v2ray_server!.users = (c.v2ray_server!.users || []).filter((_, j) => j !== k); }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <LogView live={live} />
      {show !== null && users[show] && <LinkDialog name={users[show].name} link={linkFor(users[show])} onClose={() => setShow(null)} />}
      {adding && <NewUser s={s} onClose={() => setAdding(false)} />}
      {settings && <ServerSettings s={s} onClose={() => setSettings(false)} />}
    </div>
  );
}

function NewUser({ s, onClose }: { s: V2RayServer; onClose: () => void }) {
  const { edit } = useConfig();
  const [name, setName] = useState("");
  const names = new Set((s.users || []).map((u) => u.name));
  const label = name.trim() || `user-${(s.users || []).length + 1}`;
  const save = async () => {
    const secret = (s.protocol || "vless_reality") === "vless_reality" ? uuid() : randKey16();
    const ok = await edit((c) => { c.v2ray_server!.users = [...(c.v2ray_server!.users || []), { name: label, secret }]; }, t("کاربر ساخته شد (هنوز اعمال نشده)", "User created (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open onClose={onClose} title={t("کاربر جدید V2Ray", "New V2Ray user")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={names.has(label)} onClick={save}>{t("ساختن", "Create")}</button></>}>
      <Field label={t("نام", "Name")} hint={t("بعد از ساختن، از دکمه‌ی «لینک و QR» لینک را بگیرید.", "After creating, get the link from the \"Link & QR\" button.")}><TextInput ltr={false} value={name} placeholder={t("مثلاً گوشی علی", "e.g. Ali's phone")} onChange={setName} /></Field>
      {names.has(label) && <p className="mt-2 text-sm text-talk">{t("این نام قبلاً استفاده شده", "This name is already used")}</p>}
    </Modal>
  );
}

function LinkDialog({ name, link, onClose }: { name: string; link: string; onClose: () => void }) {
  const toast = useToast();
  const svg = useMemo(() => { const q = qrcode(0, "M"); q.addData(link); q.make(); return q.createSvgTag({ cellSize: 4, margin: 4, scalable: true }); }, [link]);
  const copy = () => navigator.clipboard?.writeText(link).then(() => toast(t("کپی شد", "Copied")));
  return (
    <Modal open wide onClose={onClose} title={t(`لینک «${name}»`, `Link for "${name}"`)}
      footer={<><button className="btn" onClick={copy}><Icon name="file" className="size-4" />{t("کپی لینک", "Copy link")}</button><button className="btn btn-primary" onClick={onClose}>{t("تمام", "Done")}</button></>}>
      <div className="grid gap-5 md:grid-cols-[260px_1fr]">
        <div className="rounded-lg bg-white p-2" dangerouslySetInnerHTML={{ __html: svg }} />
        <div className="min-w-0 space-y-3">
          <ol className="list-decimal space-y-1 ps-5 text-sm text-ink-2">
            <li>{t("در v2rayNG، v2rayN، Hiddify یا Streisand این QR را اسکن کنید یا لینک را از کلیپ‌بورد وارد کنید.", "In v2rayNG, v2rayN, Hiddify or Streisand scan this QR or import the link from the clipboard.")}</li>
            <li>{t("اگر کاربر تازه است، در صفحه‌ی «تغییرات» تغییر را اعمال و تأیید کنید.", "If the user is new, apply and confirm the change on the Changes page.")}</li>
          </ol>
          <pre className="ltr mono max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-surface-2 p-3 text-left text-xs">{link}</pre>
        </div>
      </div>
    </Modal>
  );
}

function ServerSettings({ s, onClose }: { s: V2RayServer; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const reality = (s.protocol || "vless_reality") === "vless_reality";
  const [port, setPort] = useState(s.public_port || 443);
  const [target, setTarget] = useState(s.reality_target || TARGETS[0]);
  const [address, setAddress] = useState(s.address || "");
  const [allowLan, setAllowLan] = useState(!!s.allow_lan);
  const [disabled, setDisabled] = useState(!!s.disabled);
  const [openFw, setOpenFw] = useState((cfg?.firewall?.filter || []).some((r) => r.comment === FW));
  const save = async () => {
    const ok = await edit((c) => {
      const n: V2RayServer = { ...c.v2ray_server!, public_port: port === 443 ? undefined : port, address: address || undefined, allow_lan: allowLan || undefined, disabled: disabled || undefined };
      if (reality) n.reality_target = target === TARGETS[0] ? undefined : target;
      c.v2ray_server = n;
      if (openFw) setServerFw(c, n); else clearServerFw(c);
    }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open onClose={onClose} title={t("تنظیمات سرور V2Ray", "V2Ray server settings")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!(port > 0 && port < 65536)} onClick={save}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("پورت عمومی", "Public port")}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>
        <Field label={t("آدرس عمومی برای لینک‌ها", "Public address for links")} hint={t("خالی = IP فعلی WAN", "empty = current WAN IP")}><TextInput value={address} onChange={setAddress} /></Field>
        {reality && <Field label={t("سایت پوششی Reality", "Reality cover site")}><TextInput value={target} onChange={setTarget} /></Field>}
        <div className="space-y-3 sm:col-span-2">
          <Check label={t("دسترسی کلاینت‌ها به شبکه‌ی داخلی و روتر", "Clients may reach the LAN and this router")} checked={allowLan} onChange={setAllowLan} />
          <Check label={t("پورت روی فایروال باز باشد (از WAN)", "Port open in the firewall (from WAN)")} checked={openFw} onChange={setOpenFw} />
          <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />
        </div>
        <p className="text-xs text-ink-3 sm:col-span-2">{t("تغییر پورت، آدرس یا سایت پوششی یعنی لینک کاربران هم باید دوباره داده شود.", "Changing the port, address or cover site means users need their links again.")}</p>
      </div>
    </Modal>
  );
}
