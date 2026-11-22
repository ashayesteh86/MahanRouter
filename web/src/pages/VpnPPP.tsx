import { useState } from "react";
import { api, fmtBytes, fmtDuration, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Config, Iface, PPPServer, PPPUser, Rule } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, ListInput, Ltr, Modal, Select, TextInput, useToast } from "../ui";
import { Info, parseCidr, useWanIP } from "./Vpn";
import { LogView, RoutingFields, liveChip, removeIface, routingLabel, routingOf, setRouting } from "./VpnRozaneh";
import type { Routing, RzLive } from "./VpnRozaneh";

// SSTP / L2TP / PPTP tab: pppd clients (routed by policy, like the other
// tunnels) and one accel-ppp server for all three, with shared users.

type Proto = "sstp" | "l2tp" | "pptp";
const LABEL: Record<Proto, string> = { sstp: "SSTP", l2tp: "L2TP/IPsec", pptp: "PPTP" };
export const FW = "PPP server";
export const SESS = "ppps";

export interface Session { ifname: string; username: string; ip: string; type: string; state: string; uptime: number; from: string; rx_bytes: number; tx_bytes: number }
export interface Live { interfaces: RzLive[]; server: (RzLive & { sessions: Session[] }) | null }

export const hostRe = /^(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}|\d{1,3}(\.\d{1,3}){3})$/;
export const safe = (s: string) => s.length > 0 && s.length <= 128 && !/["\\\x00-\x1f\x7f]/.test(s);
export const randPass = (n = 12) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"[b % 56]).join("");
const serverOK = (proto: Proto, s: string) => {
  const m = proto === "sstp" ? /^(.+?)(?::(\d{1,5}))?$/.exec(s) : [s, s];
  return !!m && hostRe.test(m[1]) && (!m[2] || (+m[2] > 0 && +m[2] < 65536));
};

export default function PPPTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<Live>("/api/v1/ppp/status", 5000);
  const [dialog, setDialog] = useState<"client" | "server" | null>(null);
  if (!cfg) return null;
  const clients = cfg.interfaces.filter((i) => i.type === "sstp" || i.type === "l2tp" || i.type === "pptp");
  return (
    <div className="space-y-6">
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("اتصال روتر به سرور SSTP، L2TP یا PPTP", "Connect this router to an SSTP, L2TP or PPTP server")}</h2>
            <p className="text-sm text-ink-3">{t("مثل sstp-client و l2tp-client در میکروتیک. انتخاب کنید ترافیک کدام دستگاه‌ها از تونل برود.", "Like sstp-client and l2tp-client in MikroTik. Choose which traffic goes through the tunnel.")}</p>
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => setDialog("client")}><Icon name="plus" className="size-4" />{t("اتصال جدید", "New connection")}</button>
        </div>
        {!clients.length && <div className="card"><Empty icon="link" title={t("هنوز اتصالی ساخته نشده", "No connection yet")}>{t("آدرس سرور، نام کاربری و رمز را از مدیر سرور VPN بگیرید.", "Get the server address, user name and password from the VPN server's admin.")}</Empty></div>}
        {clients.map((c) => <ClientCard key={c.name} ifc={c} live={(live?.interfaces || []).find((x) => x.name === c.name)} />)}
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("سرور SSTP / L2TP / PPTP روی این روتر", "SSTP / L2TP / PPTP server on this router")}</h2>
            <p className="text-sm text-ink-3">{t("ویندوز، مک، آیفون و روترهای دیگر (میکروتیک و …) بدون نصب برنامه وصل می‌شوند. هر سه پروتکل کاربران مشترک دارند.", "Windows, Mac, iPhone and other routers (MikroTik, …) connect without extra apps. All three protocols share the users.")}</p>
          </div>
          {!cfg.ppp_server && <button className="btn btn-primary btn-sm" onClick={() => setDialog("server")}><Icon name="plus" className="size-4" />{t("راه‌اندازی سرور", "Set up the server")}</button>}
        </div>
        {cfg.ppp_server ? <ServerCard s={cfg.ppp_server} live={live?.server || undefined} /> : <div className="card"><Empty icon="server" title={t("سرور راه‌اندازی نشده", "No server yet")} /></div>}
      </section>
      {dialog === "client" && <ClientDialog onClose={() => setDialog(null)} />}
      {dialog === "server" && <ServerDialog onClose={() => setDialog(null)} />}
    </div>
  );
}

// ---- client ---------------------------------------------------------------

function ClientDialog({ ifc, routing: initial, onClose }: { ifc?: Iface; routing?: Routing; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const used = new Set((cfg?.interfaces || []).map((i) => i.name));
  const [proto, setProto] = useState<Proto>((ifc?.type as Proto) || "sstp");
  const defName = (p: Proto) => { let n = 1; while (used.has(`${p}-out${n}`)) n++; return `${p}-out${n}`; };
  const [name, setName] = useState(ifc?.name || defName("sstp"));
  const [nameEdited, setNameEdited] = useState(false);
  const p = ifc?.ppp;
  const [server, setServer] = useState(p?.server || "");
  const [user, setUser] = useState(p?.username || "");
  const [pass, setPass] = useState(p?.password || "");
  const [psk, setPsk] = useState(p?.ipsec_secret || "");
  const [verify, setVerify] = useState(!!p?.verify_cert);
  const [disabled, setDisabled] = useState(!!ifc?.disabled);
  const [routing, setR] = useState<Routing>(initial || { mode: "except_iran", devices: [], dns: false, block: false });
  const nameOK = !!ifc || (/^[a-z][a-z0-9-]{0,14}$/.test(name) && !used.has(name) && !name.startsWith(SESS));
  const valid = nameOK && serverOK(proto, server.trim()) && safe(user) && safe(pass) && (!psk || safe(psk)) && (routing.mode !== "devices" || routing.devices.length > 0);
  const pickProto = (v: Proto) => { setProto(v); if (!ifc && !nameEdited) setName(defName(v)); };
  const save = async () => {
    const ppp = { server: server.trim(), username: user, password: pass, ipsec_secret: proto === "l2tp" && psk ? psk : undefined, verify_cert: proto === "sstp" && verify ? true : undefined };
    const ok = await edit((c) => {
      if (ifc) {
        const i = c.interfaces.find((x) => x.name === ifc.name)!;
        i.ppp = ppp;
        i.comment = `${LABEL[proto]} ${ppp.server}`;
        i.disabled = disabled || undefined;
      } else {
        c.interfaces.push({ name, type: proto, comment: `${LABEL[proto]} ${ppp.server}`, ppp });
        c.interface_lists = c.interface_lists || {};
        c.interface_lists.WAN = [...new Set([...(c.interface_lists.WAN || []), name])];
      }
      setRouting(c, ifc?.name || name, routing);
    }, ifc ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("اتصال ساخته شد (هنوز اعمال نشده)", "Connection created (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={ifc ? `${t("تنظیمات", "Settings")} ${ifc.name}` : t("اتصال روتر به سرور SSTP / L2TP / PPTP", "Connect the router to an SSTP / L2TP / PPTP server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{ifc ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          {!ifc && <Field label={t("پروتکل", "Protocol")}>
            <Select value={proto} onChange={(v) => pickProto(v as Proto)} options={[
              { value: "sstp", label: t("SSTP (پیشنهادی، از پورت 443)", "SSTP (recommended, over port 443)") },
              { value: "l2tp", label: "L2TP/IPsec" },
              { value: "pptp", label: t("PPTP (قدیمی و ناامن)", "PPTP (old and insecure)") },
            ]} />
          </Field>}
          {proto === "pptp" && <p className="rounded-md bg-talk-soft p-3 text-xs leading-6 text-talk">{t("رمزنگاری PPTP شکسته شده است. فقط وقتی سرور چیز دیگری ندارد از آن استفاده کنید.", "PPTP's encryption is broken. Use it only when the server offers nothing else.")}</p>}
          <Field label={t("آدرس سرور", "Server address")} hint={proto === "sstp" ? t("دامنه یا IP؛ پورت غیر از 443 را با : بنویسید، مثل vpn.example.com:4443", "Domain or IP; add a port other than 443 with :, like vpn.example.com:4443") : t("دامنه یا IP", "Domain or IP")}>
            <TextInput value={server} placeholder="vpn.example.com" onChange={setServer} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("نام کاربری", "User name")}><TextInput value={user} onChange={setUser} /></Field>
            <Field label={t("رمز", "Password")}><TextInput value={pass} onChange={setPass} /></Field>
          </div>
          {proto === "l2tp" && <Field label={t("کلید IPsec (Pre-shared key)", "IPsec pre-shared key")} hint={t("خالی = L2TP بدون IPsec (بیشتر سرورها قبول نمی‌کنند)", "empty = L2TP without IPsec (most servers refuse it)")}>
            <TextInput value={psk} onChange={setPsk} />
          </Field>}
          {proto === "sstp" && <Check label={t("گواهی سرور بررسی شود", "Verify the server certificate")} checked={verify} onChange={setVerify}
            hint={t("خاموش برای سرورهایی با گواهی خودامضا (میکروتیک، ویندوز). روشن فقط وقتی گواهی معتبر دارد.", "Off for servers with a self-signed certificate (MikroTik, Windows). On only when it has a trusted one.")} />}
          {!ifc && <Field label={t("نام اینترفیس", "Interface name")}><TextInput value={name} onChange={(v) => { setName(v.toLowerCase()); setNameEdited(true); }} /></Field>}
          {ifc && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
        </div>
        <RoutingFields value={routing} onChange={setR} />
      </div>
    </Modal>
  );
}

function ClientCard({ ifc, live }: { ifc: Iface; live?: RzLive }) {
  const { cfg, edit } = useConfig();
  const [editing, setEditing] = useState(false);
  const routing = routingOf((cfg?.policy_routes || []).find((p) => p.interface === ifc.name));
  const proto = ifc.type as Proto;
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="link" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        {liveChip(ifc, live)}
        {proto === "pptp" && <Chip tone="ring">{t("ناامن", "insecure")}</Chip>}
        <div className="ms-auto flex gap-2">
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`اتصال ${ifc.name} حذف شود؟`, `Delete connection ${ifc.name}?`)} onConfirm={() => edit((c) => removeIface(c, ifc.name), t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-5">
        <Info label={t("پروتکل", "Protocol")}>{LABEL[proto]}{proto === "l2tp" && !ifc.ppp?.ipsec_secret ? t(" (بدون IPsec)", " (no IPsec)") : ""}</Info>
        <Info label={t("سرور", "Server")}><Ltr className="mono">{ifc.ppp?.server || "—"}</Ltr></Info>
        <Info label={t("آدرس در تونل", "Tunnel address")}><Ltr className="mono">{live?.addresses?.filter((a) => !a.includes(":")).join(", ") || "—"}</Ltr></Info>
        <Info label={t("دانلود / آپلود", "Down / Up")}><Ltr className="mono">{live?.up ? `${fmtBytes(live.rx_bytes)} / ${fmtBytes(live.tx_bytes)}` : "—"}</Ltr></Info>
        <Info label={t("مسیریابی", "Routing")}>{routingLabel(routing)}</Info>
      </div>
      <LogView live={live} />
      {editing && <ClientDialog ifc={ifc} routing={routing} onClose={() => setEditing(false)} />}
    </div>
  );
}

// ---- server ---------------------------------------------------------------

const sstpPorts = (s: PPPServer) => ({ pub: s.sstp?.public_port || 443, listen: s.sstp?.listen_port || 8445 });

/** Opens the enabled protocols from WAN. */
export function setServerFw(c: Config, s: PPPServer) {
  clearServerFw(c);
  c.firewall = c.firewall || {};
  const filter = (c.firewall.filter = c.firewall.filter || []);
  const acc = (protocol: string, dst_port?: string): Rule => ({ chain: "input", action: "accept", protocol, dst_port, in_interface_list: "WAN", comment: FW });
  const rules: Rule[] = [];
  if (s.pptp?.enabled) rules.push(acc("tcp", "1723"), acc("gre"));
  if (s.l2tp?.enabled) {
    rules.push(acc("udp", s.l2tp.ipsec_secret ? "500,4500,1701" : "1701"));
    if (s.l2tp.ipsec_secret) rules.push(acc("esp"));
  }
  if (s.sstp?.enabled) {
    const { pub, listen } = sstpPorts(s);
    rules.push(acc("tcp", String(listen)));
    if (pub !== listen) (c.firewall.nat = c.firewall.nat || []).unshift({ chain: "dstnat", action: "redirect", protocol: "tcp", dst_port: String(pub), in_interface_list: "WAN", to_port: String(listen), comment: FW });
  }
  if (s.openvpn?.enabled) rules.push(acc(s.openvpn.protocol || "tcp", String(s.openvpn.port || 1194)));
  let pos = filter.findIndex((r) => r.chain === "input" && (r.action === "drop" || r.action === "reject") && !r.connection_state);
  if (pos < 0) pos = filter.length;
  filter.splice(pos, 0, ...rules);
}

export function clearServerFw(c: Config) {
  if (c.firewall?.filter) c.firewall.filter = c.firewall.filter.filter((r) => r.comment !== FW);
  if (c.firewall?.nat) c.firewall.nat = c.firewall.nat.filter((r) => r.comment !== FW);
}

/** Sessions count as LAN (router + LAN reachable) only with allow_lan. */
export function setLanAccess(c: Config, allow: boolean) {
  c.interface_lists = c.interface_lists || {};
  const L = (c.interface_lists.LAN || []).filter((x) => x !== SESS);
  c.interface_lists.LAN = allow ? [...L, SESS] : L;
}

function ServerDialog({ s, onClose }: { s?: PPPServer; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const toast = useToast();
  const rz = (cfg?.interfaces || []).find((i) => i.type === "rozaneh_server");
  const port443 = (rz && (rz.rozaneh_server?.public_port || 443) === 443) || (cfg?.v2ray_server && (cfg.v2ray_server.public_port || 443) === 443);
  const [sstp, setSstp] = useState(s ? !!s.sstp?.enabled : true);
  const [l2tp, setL2tp] = useState(s ? !!s.l2tp?.enabled : true);
  const [pptp, setPptp] = useState(!!s?.pptp?.enabled);
  const [psk, setPsk] = useState(s?.l2tp?.ipsec_secret ?? randPass(16));
  const [port, setPort] = useState(s?.sstp?.public_port || (port443 && !s ? 4443 : 443));
  const [host, setHost] = useState(s?.sstp?.domain || "");
  const [own, setOwn] = useState(false);
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [addr, setAddr] = useState(s?.address || "10.80.0.1/24");
  const [dns, setDns] = useState<string[]>(s?.client_dns || []);
  const [allowLan, setAllowLan] = useState(!!s?.allow_lan);
  const [openFw, setOpenFw] = useState(s ? (cfg?.firewall?.filter || []).some((r) => r.comment === FW) : true);
  const [disabled, setDisabled] = useState(!!s?.disabled);
  const [busy, setBusy] = useState(false);
  const name = host.trim() || wanIP;
  const cidr = parseCidr(addr);
  const valid = (sstp || l2tp || pptp || !!s?.openvpn || !!s?.ikev2) && !!cidr && cidr.len >= 16 && cidr.len <= 29 && (!l2tp || !psk || safe(psk)) && port > 0 && port < 65536
    && (!sstp || (own ? certPem.includes("BEGIN CERTIFICATE") && keyPem.includes("PRIVATE KEY") : hostRe.test(name) || !!s?.sstp?.cert_pem));
  const save = async () => {
    setBusy(true);
    try {
      let cert = s?.sstp?.cert_pem || "", key = s?.sstp?.key_pem || "";
      if (sstp && own) { cert = certPem.trim(); key = keyPem.trim(); }
      else if (sstp && (!cert || (s?.sstp?.domain || "") !== host.trim())) {
        const r = await api<{ cert_pem: string; key_pem: string }>("/api/v1/ppp/sstp-cert", { method: "POST", body: { name } });
        cert = r.cert_pem; key = r.key_pem;
      }
      const n: PPPServer = {
        ...(s || {}), address: addr.trim(), client_dns: dns.length ? dns : undefined, allow_lan: allowLan || undefined, disabled: disabled || undefined,
        pptp: pptp ? { enabled: true } : undefined,
        l2tp: l2tp ? { enabled: true, ipsec_secret: psk || undefined } : undefined,
        sstp: sstp ? { enabled: true, public_port: port === 443 ? undefined : port, domain: host.trim() || name || undefined, cert_pem: cert, key_pem: key } : undefined,
        users: s?.users || [],
      };
      const ok = await edit((c) => {
        c.ppp_server = n;
        if (openFw) setServerFw(c, n); else clearServerFw(c);
        setLanAccess(c, allowLan);
      }, s ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("سرور ساخته شد (هنوز اعمال نشده)", "Server created (not applied yet)"));
      if (ok) onClose();
    } catch (e) { toast((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Modal open wide onClose={onClose} title={s ? t("تنظیمات سرور", "Server settings") : t("راه‌اندازی سرور SSTP / L2TP / PPTP", "Set up an SSTP / L2TP / PPTP server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid || busy} onClick={save}>{s ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <div className="space-y-3">
            <div className="text-sm font-medium">{t("پروتکل‌ها", "Protocols")}</div>
            <Check label={t("SSTP (پیشنهادی)", "SSTP (recommended)")} checked={sstp} onChange={setSstp} hint={t("روی TLS پورت 443؛ از بیشتر فایروال‌ها رد می‌شود. ویندوز و میکروتیک.", "Over TLS on port 443; passes most firewalls. Windows and MikroTik.")} />
            <Check label="L2TP/IPsec" checked={l2tp} onChange={setL2tp} hint={t("ویندوز، مک، آیفون و میکروتیک بدون برنامه.", "Windows, Mac, iPhone and MikroTik without apps.")} />
            <Check label={t("PPTP (ناامن)", "PPTP (insecure)")} checked={pptp} onChange={setPptp} hint={t("فقط برای دستگاه‌های قدیمی؛ رمزنگاری‌اش شکسته شده است.", "Only for old devices; its encryption is broken.")} />
          </div>
          {l2tp && <Field label={t("کلید IPsec (Pre-shared key)", "IPsec pre-shared key")} hint={t("همین را روی دستگاه‌ها وارد کنید. خالی = L2TP بدون IPsec (توصیه نمی‌شود)", "Enter the same on the devices. Empty = L2TP without IPsec (not recommended)")}>
            <div className="flex gap-2"><TextInput value={psk} onChange={setPsk} /><button className="btn btn-sm" type="button" onClick={() => setPsk(randPass(16))}>{t("تازه", "New")}</button></div>
          </Field>}
          {sstp && <>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("پورت SSTP", "SSTP port")} hint={port443 && port === 443 ? <span className="text-talk">{t("سرور دیگری از 443 استفاده می‌کند", "Another server uses 443")}</span> : undefined}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>
              <Field label={t("آدرسی که کلاینت‌ها می‌زنند", "Address clients dial")} hint={t("دامنه یا IP عمومی؛ خالی = IP فعلی WAN", "Public domain or IP; empty = current WAN IP")}><TextInput value={host} placeholder={wanIP || "vpn.example.com"} onChange={setHost} /></Field>
            </div>
            <Check label={t("گواهی خودم را دارم", "I have my own certificate")} checked={own} onChange={setOwn} hint={t("خاموش = گواهی خودامضا ساخته می‌شود که باید روی ویندوز نصب شود.", "Off = a self-signed certificate is made, which Windows must import.")} />
            {own && <>
              <Field label={t("گواهی (PEM، با زنجیره)", "Certificate (PEM, with chain)")}><textarea className="input mono ltr min-h-20 text-left text-xs" dir="ltr" value={certPem} onChange={(e) => setCertPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
              <Field label={t("کلید خصوصی (PEM)", "Private key (PEM)")}><textarea className="input mono ltr min-h-20 text-left text-xs" dir="ltr" value={keyPem} onChange={(e) => setKeyPem(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" /></Field>
            </>}
          </>}
        </div>
        <div className="space-y-4">
          <Field label={t("آدرس روتر و زیرشبکه‌ی کلاینت‌ها", "Router address and client subnet")} hint={cidr ? t(`کلاینت‌ها از ${cidr.size - 3} آدرس این شبکه IP می‌گیرند`, `Clients get one of ${cidr.size - 3} addresses of this subnet`) : undefined}>
            <TextInput value={addr} onChange={setAddr} />
          </Field>
          <Field label={t("DNS برای کلاینت‌ها", "DNS for clients")} hint={t("خالی = 1.1.1.1 و 8.8.8.8", "empty = 1.1.1.1 and 8.8.8.8")}><ListInput value={dns} onChange={setDns} rows={2} placeholder="1.1.1.1" /></Field>
          <Check label={t("دسترسی کلاینت‌ها به شبکه‌ی داخلی و روتر", "Clients may reach the LAN and this router")} checked={allowLan} onChange={setAllowLan} hint={t("خاموش = فقط اینترنت. برای اتصال شعبه یا کار از خانه روشن کنید.", "Off = internet only. Turn on for branch offices or working from home.")} />
          <Check label={t("پورت‌ها روی فایروال باز شوند (از WAN)", "Open the ports in the firewall (from WAN)")} checked={openFw} onChange={setOpenFw} />
          {s && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("پورت‌ها: ", "Ports: ")}
            {[sstp && `SSTP TCP ${port}`, l2tp && (psk ? "L2TP/IPsec UDP 500, 4500, 1701 + ESP" : "L2TP UDP 1701"), pptp && "PPTP TCP 1723 + GRE", s?.openvpn?.enabled && `OpenVPN ${(s.openvpn.protocol || "tcp").toUpperCase()} ${s.openvpn.port || 1194}`].filter(Boolean).join(" · ") || "—"}.
            {t(" اگر روتر پشت مودم است، این پورت‌ها را روی مودم به این روتر فوروارد کنید (GRE و ESP روی بیشتر مودم‌ها فوروارد نمی‌شوند؛ آنجا SSTP بهتر است).", " If this router is behind a modem, forward these ports to it there (most modems cannot forward GRE and ESP; SSTP is better then).")}
          </div>
        </div>
      </div>
    </Modal>
  );
}

function downloadCert(s: PPPServer) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([s.sstp?.cert_pem || ""], { type: "application/x-x509-ca-cert" }));
  a.download = `${(s.sstp?.domain || "mahan-router").replace(/[^a-zA-Z0-9.-]/g, "_")}-sstp.crt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function ServerCard({ s, live }: { s: PPPServer; live?: RzLive & { sessions: Session[] } }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const toast = useToast();
  const [settings, setSettings] = useState(false);
  const [user, setUser] = useState<PPPUser | "new" | null>(null);
  const [showPsk, setShowPsk] = useState(false);
  const [help, setHelp] = useState(false);
  const users = s.users || [];
  const host = s.sstp?.domain || wanIP || "—";
  const { pub } = sstpPorts(s);
  const fwOpen = (cfg?.firewall?.filter || []).some((r) => r.comment === FW);
  const chip = s.disabled ? <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>
    : !live?.active || live.active === "inactive" ? <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>
    : live.active === "active" ? <Chip tone="idle">{t("فعال", "running")}</Chip>
    : live.active === "failed" ? <Chip tone="talk">{t("خطا", "failed")}</Chip> : <Chip tone="ring">{live.active}</Chip>;
  const protos = [s.sstp?.enabled && "SSTP", s.l2tp?.enabled && (s.l2tp.ipsec_secret ? "L2TP/IPsec" : "L2TP"), s.pptp?.enabled && "PPTP", s.openvpn?.enabled && "OpenVPN", s.ikev2?.enabled && "IKEv2"].filter(Boolean) as string[];
  const kick = (ifname: string) => api("/api/v1/ppp/disconnect", { method: "POST", body: { ifname } }).then(() => toast(t("قطع شد", "Disconnected"))).catch((e) => toast(e.message));
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="server" className="size-5 text-accent" />
        <h2 className="card-title">{protos.join(" · ") || t("سرور PPP", "PPP server")}</h2>
        {chip}
        <div className="ms-auto flex flex-wrap gap-2">
          <button className="btn btn-primary btn-sm" onClick={() => setUser("new")}><Icon name="plus" className="size-4" />{t("کاربر جدید", "New user")}</button>
          {s.sstp?.enabled && <button className="btn btn-sm" onClick={() => downloadCert(s)}><Icon name="file" className="size-4" />{t("گواهی SSTP", "SSTP certificate")}</button>}
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setSettings(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={s.openvpn || s.ikev2 ? t("سرور (همراه با OpenVPN و IKEv2) و همه‌ی کاربرانش حذف شود؟", "Delete the server (OpenVPN and IKEv2 included) and all its users?") : t("سرور و همه‌ی کاربرانش حذف شود؟", "Delete the server and all its users?")} onConfirm={() => edit((c) => { c.ppp_server = undefined; clearServerFw(c); setLanAccess(c, false); }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آدرس سرور برای کلاینت‌ها", "Server address for clients")}><Ltr className="mono">{host}{s.sstp?.enabled && pub !== 443 ? `:${pub}` : ""}</Ltr>{!fwOpen && <span className="ms-2 text-xs text-ring">{t("روی فایروال باز نیست", "not open in firewall")}</span>}</Info>
        {s.l2tp?.enabled && <Info label={t("کلید IPsec", "IPsec key")}>{s.l2tp.ipsec_secret ? <button className="mono ltr text-start" onClick={() => setShowPsk(!showPsk)}>{showPsk ? s.l2tp.ipsec_secret : "••••••••  " + t("(نمایش)", "(show)")}</button> : t("بدون IPsec", "no IPsec")}</Info>}
        <Info label={t("زیرشبکه‌ی کلاینت‌ها", "Client subnet")}><Ltr className="mono">{s.address}</Ltr></Info>
        <Info label={t("دسترسی کلاینت‌ها", "Client access")}>{s.allow_lan ? t("اینترنت و شبکه‌ی داخلی", "internet and LAN") : t("فقط اینترنت", "internet only")}</Info>
      </div>

      {!!live?.sessions?.length && (
        <div className="overflow-x-auto border-t border-line">
          <div className="px-5 pt-3 text-xs font-medium text-ink-3">{t("متصل‌ها", "Connected now")}</div>
          <table className="w-full text-sm">
            <thead className="text-xs text-ink-3"><tr>
              <th className="px-4 py-2 text-start font-normal">{t("کاربر", "User")}</th><th className="px-4 py-2 text-start font-normal">{t("پروتکل", "Protocol")}</th>
              <th className="px-4 py-2 text-start font-normal">IP</th><th className="px-4 py-2 text-start font-normal">{t("از", "From")}</th>
              <th className="px-4 py-2 text-start font-normal">{t("مدت", "Uptime")}</th><th className="px-4 py-2 text-start font-normal">{t("دانلود / آپلود", "Down / Up")}</th><th />
            </tr></thead>
            <tbody className="divide-y divide-line">
              {live.sessions.map((x) => (
                <tr key={x.ifname || x.from + x.type}>
                  <td className="px-4 py-2 font-medium">{x.username || "—"}</td>
                  <td className="px-4 py-2 uppercase">{x.type}{x.state !== "active" && <span className="ms-2 text-xs text-ring">{x.state}</span>}</td>
                  <td className="px-4 py-2"><Ltr className="mono">{x.ip || "—"}</Ltr></td>
                  <td className="px-4 py-2"><Ltr className="mono">{x.from}</Ltr></td>
                  <td className="px-4 py-2">{fmtDuration(x.uptime)}</td>
                  <td className="px-4 py-2"><Ltr className="mono">{fmtBytes(x.tx_bytes)} / {fmtBytes(x.rx_bytes)}</Ltr></td>
                  <td className="px-4 py-2 text-end">{x.ifname && <ConfirmButton className="btn btn-sm" question={t(`اتصال ${x.username} قطع شود؟`, `Disconnect ${x.username}?`)} onConfirm={() => kick(x.ifname)}>{t("قطع", "Disconnect")}</ConfirmButton>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!users.length ? <div className="border-t border-line"><Empty title={t("هنوز کاربری ندارد", "No users yet")} /></div> : (
        <div className="overflow-x-auto border-t border-line">
          <div className="px-5 pt-3 text-xs font-medium text-ink-3">{t("کاربران", "Users")}</div>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-line">
              {users.map((u, k) => (
                <tr key={u.name}>
                  <td className="px-4 py-2.5 font-medium"><Ltr>{u.name}</Ltr>{u.disabled && <span className="ms-2 chip bg-talk-soft text-talk">{t("غیرفعال", "disabled")}</span>}</td>
                  <td className="px-4 py-2.5 text-ink-3"><Ltr className="mono">{u.ip || t("IP خودکار", "automatic IP")}</Ltr></td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-end">
                    <button className="btn btn-sm" onClick={() => setUser(u)}><Icon name="settings" className="size-4" />{t("ویرایش", "Edit")}</button>
                    <button className="btn btn-sm ms-1" onClick={() => edit((c) => { const x = c.ppp_server!.users![k]; x.disabled = !x.disabled || undefined; }, t("تغییر کرد (هنوز اعمال نشده)", "Changed (not applied yet)"))}>{u.disabled ? t("فعال کن", "Enable") : t("غیرفعال کن", "Disable")}</button>
                    <ConfirmButton className="icon-btn text-talk" question={t(`«${u.name}» حذف شود؟`, `Delete "${u.name}"?`)} onConfirm={() => edit((c) => { c.ppp_server!.users = (c.ppp_server!.users || []).filter((_, j) => j !== k); }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="border-t border-line px-5 py-2">
        <button className="text-xs text-accent" onClick={() => setHelp(!help)}>{help ? t("بستن راهنما", "Hide help") : t("راهنمای اتصال دستگاه‌ها", "How to connect devices")}</button>
        {help && <ConnectHelp s={s} host={host} />}
      </div>
      <LogView live={live} />
      {settings && <ServerDialog s={s} onClose={() => setSettings(false)} />}
      {user && <UserDialog s={s} user={user === "new" ? undefined : user} onClose={() => setUser(null)} />}
    </div>
  );
}

function ConnectHelp({ s, host }: { s: PPPServer; host: string }) {
  const { pub } = sstpPorts(s);
  const sstpHost = pub === 443 ? host : `${host}:${pub}`;
  return (
    <div className="mt-2 space-y-3 text-xs leading-6 text-ink-2">
      <div><b>{t("ویندوز", "Windows")}</b>: {t("تنظیمات ← شبکه ← VPN ← افزودن. نوع VPN را SSTP یا «L2TP/IPsec با کلید از پیش مشترک» بگذارید، آدرس سرور ", "Settings → Network → VPN → Add. Set the VPN type to SSTP or \"L2TP/IPsec with pre-shared key\", server ")}<Ltr className="mono">{sstpHost}</Ltr>{t("، نام کاربری و رمز.", ", user name and password.")}
        {s.sstp?.enabled && t(" برای SSTP با گواهی خودامضا: فایل «گواهی SSTP» را باز کنید ← Install Certificate ← Local Machine ← Trusted Root Certification Authorities. اگر خطای بررسی ابطال (revocation) گرفتید، کلید رجیستری NoCertRevocationCheck=1 را در HKLM\\SYSTEM\\CurrentControlSet\\Services\\SstpSvc\\Parameters بسازید.", " For SSTP with the self-signed certificate: open the \"SSTP certificate\" file → Install Certificate → Local Machine → Trusted Root Certification Authorities. On a revocation check error, create the registry value NoCertRevocationCheck=1 (DWORD) in HKLM\\SYSTEM\\CurrentControlSet\\Services\\SstpSvc\\Parameters.")}</div>
      {s.l2tp?.enabled && <div><b>{t("آیفون و مک", "iPhone and Mac")}</b>: {t("تنظیمات ← VPN ← افزودن ← L2TP؛ سرور، حساب (نام کاربری)، رمز و Secret (کلید IPsec).", "Settings → VPN → Add → L2TP; server, account (user name), password and secret (the IPsec key).")}</div>}
      <div><b>{t("اندروید", "Android")}</b>: {t("نسخه‌های جدید اندروید PPTP و L2TP داخلی ندارند؛ یک برنامه‌ی SSTP نصب کنید، یا از WireGuard یا روزنه استفاده کنید.", "Recent Android versions have no built-in PPTP or L2TP; install an SSTP app, or use WireGuard or Rozaneh.")}</div>
      <div><b>{t("میکروتیک", "MikroTik")}</b>: <Ltr className="mono">{s.sstp?.enabled ? `/interface sstp-client add connect-to=${sstpHost} user=NAME password=PASS disabled=no` : s.l2tp?.enabled ? `/interface l2tp-client add connect-to=${host} user=NAME password=PASS use-ipsec=yes ipsec-secret=… disabled=no` : `/interface pptp-client add connect-to=${host} user=NAME password=PASS disabled=no`}</Ltr></div>
      <div><b>{t("روتر Mahan دیگر", "Another Mahan Router")}</b>: {t("VPN ← SSTP / L2TP / PPTP ← اتصال جدید.", "VPN → SSTP / L2TP / PPTP → New connection.")}</div>
    </div>
  );
}

export function UserDialog({ s, user, onClose }: { s: PPPServer; user?: PPPUser; onClose: () => void }) {
  const { edit } = useConfig();
  const [name, setName] = useState(user?.name || "");
  const [pass, setPass] = useState(user?.password || randPass());
  const [ip, setIp] = useState(user?.ip || "");
  const others = (s.users || []).filter((u) => u.name !== user?.name);
  const cidr = parseCidr(s.address);
  const ipOK = !ip || (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !!cidr && ((ip.split(".").reduce((a, b) => a * 256 + +b, 0) - cidr.net) >>> 0) < cidr.size && ip !== cidr.ip && !others.some((u) => u.ip === ip));
  const valid = safe(name) && !/\s/.test(name) && !others.some((u) => u.name === name) && safe(pass) && ipOK;
  const save = async () => {
    const u: PPPUser = { name, password: pass, ip: ip || undefined, disabled: user?.disabled };
    const ok = await edit((c) => {
      const list = c.ppp_server!.users || [];
      const i = user ? list.findIndex((x) => x.name === user.name) : -1;
      if (i >= 0) list[i] = u; else list.push(u);
      c.ppp_server!.users = list;
    }, user ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("کاربر ساخته شد (هنوز اعمال نشده)", "User created (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open onClose={onClose} title={user ? t(`ویرایش «${user.name}»`, `Edit "${user.name}"`) : t("کاربر جدید", "New user")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{user ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("نام کاربری", "User name")} hint={t("بدون فاصله، مثلاً ali یا branch-shiraz", "No spaces, e.g. ali or branch-shiraz")}><TextInput value={name} onChange={setName} /></Field>
        <Field label={t("رمز", "Password")}><div className="flex gap-2"><TextInput value={pass} onChange={setPass} /><button className="btn btn-sm" type="button" onClick={() => setPass(randPass())}>{t("تازه", "New")}</button></div></Field>
        <Field label={t("IP ثابت (اختیاری)", "Fixed IP (optional)")} hint={t(`داخل ${s.address}؛ خالی = خودکار. برای شعبه‌ها و دسترسی از LAN به آن.`, `Inside ${s.address}; empty = automatic. For branch offices and reaching it from the LAN.`)}><TextInput value={ip} onChange={setIp} placeholder={cidr ? cidr.ip.replace(/\d+$/, "50") : ""} /></Field>
      </div>
      {!ipOK && <p className="mt-2 text-sm text-talk">{t("IP خارج از زیرشبکه یا تکراری است", "The IP is outside the subnet or already used")}</p>}
    </Modal>
  );
}
