import { useState } from "react";
import { api, fmtBytes, fmtDuration, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Iface, OpenVPNClient, OpenVPNServer, PPPServer, PPPUser } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, Ltr, Modal, Select, TextInput, useToast } from "../ui";
import { Info, parseCidr, useWanIP } from "./Vpn";
import { FW, SESS, UserDialog, clearServerFw, hostRe, safe, setLanAccess, setServerFw } from "./VpnPPP";
import type { Live } from "./VpnPPP";
import { LogView, RoutingFields, liveChip, removeIface, routingLabel, routingOf, setRouting } from "./VpnRozaneh";
import type { Routing, RzLive } from "./VpnRozaneh";

// OpenVPN tab: clients (an imported .ovpn file, or MikroTik-style fields)
// and the OpenVPN server, which logs in the PPP server's users.

const CIPHERS = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC", "AES-192-CBC", "AES-128-CBC"];
/** MikroTik ovpn-client cipher names (RouterOS 7). */
const MT_CIPHER: Record<string, string> = { "AES-256-GCM": "aes256-gcm", "AES-128-GCM": "aes128-gcm", "AES-256-CBC": "aes256-cbc", "AES-192-CBC": "aes192-cbc", "AES-128-CBC": "aes128-cbc" };
const AUTHS = ["SHA1", "SHA256", "SHA512", "MD5"];
const fpOK = (s: string) => /^[0-9a-fA-F]{64}$/.test(s.replace(/[:\s-]/g, ""));

/** The first "remote" host of a .ovpn file. */
const ovpnRemote = (text: string) => /^\s*remote\s+(\S+)/m.exec(text)?.[1] || "";
const ovpnNeedsLogin = (text: string) => /^\s*(auth-user-pass\b|<auth-user-pass>)/m.test(text);
/** Options the router refuses (they run programs or open a management port). */
const ovpnBad = (text: string) => /^\s*(--)?(up|down|route-up|route-pre-down|ipchange|tls-verify|plugin|client-connect|client-disconnect|learn-address|auth-user-pass-verify|management[\w-]*|config|cd|chroot|iproute|mode|server|tls-server)\b/im.exec(text)?.[2];

export default function OpenVPNTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<Live & { server: (Live["server"] & { openvpn?: RzLive }) | null }>("/api/v1/ppp/status", 5000);
  const [dialog, setDialog] = useState<"client" | "server" | null>(null);
  if (!cfg) return null;
  const clients = cfg.interfaces.filter((i) => i.type === "openvpn");
  const srv = cfg.ppp_server;
  return (
    <div className="space-y-6">
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("اتصال روتر به سرور OpenVPN", "Connect this router to an OpenVPN server")}</h2>
            <p className="text-sm text-ink-3">{t("مثل ovpn-client در میکروتیک؛ یا فایل .ovpn سرویس‌دهنده را وارد کنید.", "Like ovpn-client in MikroTik; or import a provider's .ovpn file.")}</p>
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => setDialog("client")}><Icon name="plus" className="size-4" />{t("اتصال جدید", "New connection")}</button>
        </div>
        {!clients.length && <div className="card"><Empty icon="link" title={t("هنوز اتصالی ساخته نشده", "No connection yet")}>{t("فایل .ovpn یا آدرس سرور و گواهی آن را از مدیر سرور بگیرید.", "Get the .ovpn file, or the server address and its certificate, from the server's admin.")}</Empty></div>}
        {clients.map((c) => <ClientCard key={c.name} ifc={c} live={(live?.interfaces || []).find((x) => x.name === c.name)} />)}
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("سرور OpenVPN روی این روتر", "OpenVPN server on this router")}</h2>
            <p className="text-sm text-ink-3">{t("برای برنامه‌ی OpenVPN در ویندوز، اندروید، آیفون و مک، و ovpn-client میکروتیک. کاربران با سرور SSTP / L2TP / PPTP مشترک‌اند.", "For the OpenVPN apps on Windows, Android, iPhone and Mac, and MikroTik's ovpn-client. Users are shared with the SSTP / L2TP / PPTP server.")}</p>
          </div>
          {!srv?.openvpn && <button className="btn btn-primary btn-sm" onClick={() => setDialog("server")}><Icon name="plus" className="size-4" />{t("راه‌اندازی سرور", "Set up the server")}</button>}
        </div>
        {srv?.openvpn ? <ServerCard s={srv} o={srv.openvpn} live={live?.server || undefined} /> : <div className="card"><Empty icon="server" title={t("سرور راه‌اندازی نشده", "No server yet")} /></div>}
      </section>
      {dialog === "client" && <ClientDialog onClose={() => setDialog(null)} />}
      {dialog === "server" && <ServerDialog onClose={() => setDialog(null)} />}
    </div>
  );
}

// ---- client ---------------------------------------------------------------

function Pem({ label, value, onChange, placeholder, hint }: { label: string; value: string; onChange: (v: string) => void; placeholder: string; hint?: string }) {
  return (
    <Field label={label} hint={hint}>
      <textarea className="input mono ltr min-h-20 text-left text-xs" dir="ltr" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </Field>
  );
}

function ClientDialog({ ifc, routing: initial, onClose }: { ifc?: Iface; routing?: Routing; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const toast = useToast();
  const used = new Set((cfg?.interfaces || []).map((i) => i.name));
  const o = ifc?.openvpn;
  const defName = () => { let n = 1; while (used.has(`ovpn-out${n}`)) n++; return `ovpn-out${n}`; };
  const [name, setName] = useState(ifc?.name || defName());
  const [mode, setMode] = useState<"fields" | "file">(o?.config ? "file" : "fields");
  const [file, setFile] = useState(o?.config || "");
  const [server, setServer] = useState(o?.server || "");
  const [port, setPort] = useState(o?.port || 1194);
  const [proto, setProto] = useState<"tcp" | "udp">(o?.protocol || "tcp");
  const [trust, setTrust] = useState<"ca" | "fp">(o?.fingerprint ? "fp" : "ca");
  const [ca, setCa] = useState(o?.ca_pem || "");
  const [fp, setFp] = useState(o?.fingerprint || "");
  const [useCert, setUseCert] = useState(!!o?.cert_pem);
  const [cert, setCert] = useState(o?.cert_pem || "");
  const [key, setKey] = useState(o?.key_pem || "");
  const [cipher, setCipher] = useState(o?.cipher || "AES-256-CBC");
  const [auth, setAuth] = useState(o?.auth || "SHA1");
  const [user, setUser] = useState(o?.username || "");
  const [pass, setPass] = useState(o?.password || "");
  const [disabled, setDisabled] = useState(!!ifc?.disabled);
  const [routing, setR] = useState<Routing>(initial || { mode: "except_iran", devices: [], dns: false, block: false });
  const nameOK = !!ifc || (/^[a-z][a-z0-9-]{0,14}$/.test(name) && !used.has(name) && !name.startsWith(SESS));
  const login = !!user || !!pass;
  const loginOK = !login || (safe(user) && safe(pass));
  const bad = mode === "file" ? ovpnBad(file) : undefined;
  const needsLogin = mode === "file" && ovpnNeedsLogin(file);
  const fileOK = mode === "file" && !!ovpnRemote(file) && !bad && /<ca>|^\s*(ca|peer-fingerprint)\s/m.test(file) && (!needsLogin || (!!user && !!pass)) && !/^\s*dev(-type)?\s+tap/m.test(file);
  const fieldsOK = mode === "fields" && hostRe.test(server.trim()) && port > 0 && port < 65536
    && (trust === "ca" ? ca.includes("BEGIN CERTIFICATE") : fpOK(fp))
    && (useCert ? cert.includes("BEGIN CERTIFICATE") && key.includes("PRIVATE KEY") : !!user);
  const valid = nameOK && loginOK && (fileOK || fieldsOK) && (routing.mode !== "devices" || routing.devices.length > 0);
  const readFile = (f?: File) => f && f.size < 65536 ? f.text().then(setFile) : f && toast(t("فایل بزرگ‌تر از 64KB است", "The file is larger than 64KB"));
  const save = async () => {
    const n: OpenVPNClient = mode === "file"
      ? { config: file.replace(/\r/g, ""), username: user || undefined, password: pass || undefined }
      : {
        server: server.trim(), port: port === 1194 ? undefined : port, protocol: proto === "tcp" ? undefined : proto,
        ca_pem: trust === "ca" ? ca.trim() : undefined, fingerprint: trust === "fp" ? fp.trim() : undefined,
        cert_pem: useCert ? cert.trim() : undefined, key_pem: useCert ? key.trim() : undefined,
        cipher: cipher === "AES-256-CBC" ? undefined : cipher, auth: auth === "SHA1" ? undefined : auth,
        username: user || undefined, password: pass || undefined,
      };
    const host = n.server || ovpnRemote(file);
    const ok = await edit((c) => {
      if (ifc) {
        const i = c.interfaces.find((x) => x.name === ifc.name)!;
        i.openvpn = n;
        i.comment = `OpenVPN ${host}`;
        i.disabled = disabled || undefined;
      } else {
        c.interfaces.push({ name, type: "openvpn", comment: `OpenVPN ${host}`, openvpn: n });
        c.interface_lists = c.interface_lists || {};
        c.interface_lists.WAN = [...new Set([...(c.interface_lists.WAN || []), name])];
      }
      setRouting(c, ifc?.name || name, routing);
    }, ifc ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("اتصال ساخته شد (هنوز اعمال نشده)", "Connection created (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={ifc ? `${t("تنظیمات", "Settings")} ${ifc.name}` : t("اتصال روتر به سرور OpenVPN", "Connect the router to an OpenVPN server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{ifc ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <Field label={t("روش", "How")}>
            <Select value={mode} onChange={(v) => setMode(v as "fields" | "file")} options={[
              { value: "fields", label: t("آدرس سرور و گواهی (مثل میکروتیک)", "Server address and certificate (MikroTik style)") },
              { value: "file", label: t("وارد کردن فایل .ovpn", "Import a .ovpn file") },
            ]} />
          </Field>
          {mode === "file" ? <>
            <Field label={t("فایل .ovpn", ".ovpn file")} hint={t("فایل را انتخاب کنید یا متنش را اینجا بچسبانید. گواهی‌ها باید داخل فایل باشند (<ca> و …).", "Pick the file or paste its text. Certificates must be inside the file (<ca>, …).")}>
              <input type="file" accept=".ovpn,.conf,text/plain" className="mb-2 block text-xs" onChange={(e) => readFile(e.target.files?.[0])} />
              <textarea className="input mono ltr min-h-40 text-left text-xs" dir="ltr" value={file} onChange={(e) => setFile(e.target.value)} placeholder={"client\nremote vpn.example.com 1194\n<ca>\n…\n</ca>"} />
            </Field>
            {file && (bad ? <p className="text-sm text-talk">{t(`گزینه‌ی «${bad}» روی روتر مجاز نیست (برنامه اجرا می‌کند).`, `The option "${bad}" is not allowed on the router (it runs programs).`)}</p>
              : /^\s*dev(-type)?\s+tap/m.test(file) ? <p className="text-sm text-talk">{t("حالت TAP (ethernet) پشتیبانی نمی‌شود؛ برای لایه ۲ از EoIP استفاده کنید.", "TAP (ethernet) mode is not supported; use EoIP for layer 2.")}</p>
              : !ovpnRemote(file) ? <p className="text-sm text-talk">{t("فایل خط remote (آدرس سرور) ندارد.", "The file has no remote line (server address).")}</p>
              : <p className="text-xs text-ink-3">{t("سرور: ", "Server: ")}<Ltr className="mono">{ovpnRemote(file)}</Ltr>{needsLogin && t(" · نام کاربری و رمز لازم است", " · needs a user name and password")}</p>)}
          </> : <>
            <Field label={t("آدرس سرور", "Server address")} hint={t("دامنه یا IP", "Domain or IP")}><TextInput value={server} placeholder="vpn.example.com" onChange={setServer} /></Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("پورت", "Port")}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>
              <Field label={t("پروتکل", "Protocol")} hint={t("میکروتیک نسخه ۶ فقط TCP", "MikroTik v6: TCP only")}><Select value={proto} onChange={(v) => setProto(v as "tcp" | "udp")} options={["tcp", "udp"]} ltr /></Field>
            </div>
            <Field label={t("اعتماد به سرور", "Trust the server by")}>
              <Select value={trust} onChange={(v) => setTrust(v as "ca" | "fp")} options={[
                { value: "ca", label: t("گواهی CA سرور", "The server's CA certificate") },
                { value: "fp", label: t("اثر انگشت گواهی سرور (SHA-256)", "The server certificate's fingerprint (SHA-256)") },
              ]} />
            </Field>
            {trust === "ca" ? <Pem label={t("گواهی CA (PEM)", "CA certificate (PEM)")} value={ca} onChange={setCa} placeholder="-----BEGIN CERTIFICATE-----" hint={t("میکروتیک: /certificate export-file CA", "MikroTik: /certificate export-file CA")} />
              : <Field label={t("اثر انگشت", "Fingerprint")} hint={t("میکروتیک: /certificate print detail ← fingerprint گواهی سرور", "MikroTik: /certificate print detail → the server certificate's fingerprint")}><TextInput value={fp} onChange={setFp} placeholder="3f:9a:…" /></Field>}
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("رمزنگاری", "Cipher")} hint={t("برای سرورهایی که مذاکره نمی‌کنند (میکروتیک ۶)", "For servers that do not negotiate (MikroTik 6)")}><Select value={cipher} onChange={setCipher} options={CIPHERS} ltr /></Field>
              <Field label="Auth (HMAC)"><Select value={auth} onChange={setAuth} options={AUTHS} ltr /></Field>
            </div>
            <Check label={t("گواهی کلاینت دارم", "I have a client certificate")} checked={useCert} onChange={setUseCert} hint={t("وقتی سرور گواهی کلاینت می‌خواهد (require-client-certificate)", "When the server requires one (require-client-certificate)")} />
            {useCert && <>
              <Pem label={t("گواهی کلاینت (PEM)", "Client certificate (PEM)")} value={cert} onChange={setCert} placeholder="-----BEGIN CERTIFICATE-----" />
              <Pem label={t("کلید خصوصی کلاینت (PEM، بدون رمز)", "Client private key (PEM, unencrypted)")} value={key} onChange={setKey} placeholder="-----BEGIN PRIVATE KEY-----" />
            </>}
          </>}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("نام کاربری", "User name")}><TextInput value={user} onChange={setUser} /></Field>
            <Field label={t("رمز", "Password")}><TextInput value={pass} onChange={setPass} /></Field>
          </div>
          {!loginOK && <p className="text-sm text-talk">{t("نام کاربری و رمز هر دو لازم‌اند، بدون \" و \\", "Both user name and password, without \" or \\")}</p>}
          {!ifc && <Field label={t("نام اینترفیس", "Interface name")}><TextInput value={name} onChange={(v) => setName(v.toLowerCase())} /></Field>}
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
  const o = ifc.openvpn || {};
  const server = o.config ? ovpnRemote(o.config) : `${o.server}${o.port && o.port !== 1194 ? `:${o.port}` : ""}`;
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="link" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        {liveChip(ifc, live)}
        {o.config && <Chip tone="idle"><Ltr>.ovpn</Ltr></Chip>}
        <div className="ms-auto flex gap-2">
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`اتصال ${ifc.name} حذف شود؟`, `Delete connection ${ifc.name}?`)} onConfirm={() => edit((c) => removeIface(c, ifc.name), t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-5">
        <Info label={t("سرور", "Server")}><Ltr className="mono">{server || "—"}</Ltr>{!o.config && <span className="ms-2 text-xs text-ink-3 uppercase">{o.protocol || "tcp"}</span>}</Info>
        <Info label={t("کاربر", "User")}><Ltr className="mono">{o.username || (o.cert_pem ? t("گواهی", "certificate") : "—")}</Ltr></Info>
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

const ovpnDefaults = (o: OpenVPNServer) => ({ port: o.port || 1194, proto: o.protocol || "tcp", addr: o.address || "10.81.0.1/24", cipher: o.cipher || "AES-256-CBC", auth: o.auth || "SHA1" });

function ServerDialog({ s, onClose }: { s?: PPPServer; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const toast = useToast();
  const o = s?.openvpn;
  const d = ovpnDefaults(o || { enabled: true, cert_pem: "", key_pem: "" });
  const ppp = cfg?.ppp_server;
  const [port, setPort] = useState(d.port);
  const [proto, setProto] = useState<"tcp" | "udp">(d.proto);
  const [addr, setAddr] = useState(d.addr);
  const [host, setHost] = useState(o?.domain || "");
  const [cipher, setCipher] = useState(d.cipher);
  const [auth, setAuth] = useState(d.auth);
  const [split, setSplit] = useState(!!o?.split_tunnel);
  const [allowLan, setAllowLan] = useState(!!ppp?.allow_lan);
  const [own, setOwn] = useState(false);
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [openFw, setOpenFw] = useState(ppp ? (cfg?.firewall?.filter || []).some((r) => r.comment === FW) : true);
  const [disabled, setDisabled] = useState(o ? !o.enabled : false);
  const [busy, setBusy] = useState(false);
  const name = host.trim() || wanIP;
  const cidr = parseCidr(addr);
  const pppCidr = ppp ? parseCidr(ppp.address) : null;
  const overlap = !!cidr && !!pppCidr && Math.max(cidr.net, pppCidr.net) < Math.min(cidr.net + cidr.size, pppCidr.net + pppCidr.size);
  const valid = !!cidr && cidr.len >= 16 && cidr.len <= 29 && !overlap && port > 0 && port < 65536
    && (own ? certPem.includes("BEGIN CERTIFICATE") && keyPem.includes("PRIVATE KEY") : hostRe.test(name) || !!o?.cert_pem);
  const save = async () => {
    setBusy(true);
    try {
      let cert = o?.cert_pem || "", key = o?.key_pem || "";
      if (own) { cert = certPem.trim(); key = keyPem.trim(); }
      else if (!cert || (o?.domain || "") !== host.trim()) {
        const r = await api<{ cert_pem: string; key_pem: string }>("/api/v1/ppp/sstp-cert", { method: "POST", body: { name } });
        cert = r.cert_pem; key = r.key_pem;
      }
      const n: OpenVPNServer = {
        enabled: !disabled, port: port === 1194 ? undefined : port, protocol: proto === "tcp" ? undefined : proto,
        address: addr.trim() === "10.81.0.1/24" ? undefined : addr.trim(), domain: host.trim() || name || undefined, cert_pem: cert, key_pem: key,
        cipher: cipher === "AES-256-CBC" ? undefined : cipher, auth: auth === "SHA1" ? undefined : auth, split_tunnel: split || undefined,
      };
      const ok = await edit((c) => {
        const p: PPPServer = c.ppp_server || { address: "10.80.0.1/24", users: [] };
        p.openvpn = n;
        p.allow_lan = allowLan || undefined;
        c.ppp_server = p;
        if (openFw) setServerFw(c, p); else clearServerFw(c);
        setLanAccess(c, allowLan);
      }, o ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("سرور ساخته شد (هنوز اعمال نشده)", "Server created (not applied yet)"));
      if (ok) onClose();
    } catch (e) { toast((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Modal open wide onClose={onClose} title={o ? t("تنظیمات سرور OpenVPN", "OpenVPN server settings") : t("راه‌اندازی سرور OpenVPN", "Set up an OpenVPN server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid || busy} onClick={save}>{o ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("پورت", "Port")}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>
            <Field label={t("پروتکل", "Protocol")} hint={t("TCP برای میکروتیک ۶ و شبکه‌های سخت‌گیر", "TCP for MikroTik 6 and strict networks")}><Select value={proto} onChange={(v) => setProto(v as "tcp" | "udp")} options={["tcp", "udp"]} ltr /></Field>
          </div>
          <Field label={t("آدرسی که کلاینت‌ها می‌زنند", "Address clients dial")} hint={t("دامنه یا IP عمومی؛ خالی = IP فعلی WAN", "Public domain or IP; empty = current WAN IP")}><TextInput value={host} placeholder={wanIP || "vpn.example.com"} onChange={setHost} /></Field>
          <Check label={t("گواهی خودم را دارم", "I have my own certificate")} checked={own} onChange={setOwn} hint={t("خاموش = گواهی خودامضا ساخته می‌شود و داخل فایل .ovpn کاربران قرار می‌گیرد.", "Off = a self-signed certificate is made and put into the users' .ovpn file.")} />
          {own && <>
            <Pem label={t("گواهی (PEM، با زنجیره)", "Certificate (PEM, with chain)")} value={certPem} onChange={setCertPem} placeholder="-----BEGIN CERTIFICATE-----" />
            <Pem label={t("کلید خصوصی (PEM)", "Private key (PEM)")} value={keyPem} onChange={setKeyPem} placeholder="-----BEGIN PRIVATE KEY-----" />
          </>}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("رمزنگاری برای کلاینت‌های قدیمی", "Cipher for old clients")} hint={t("کلاینت‌های جدید AES-GCM می‌گیرند", "New clients get AES-GCM")}><Select value={cipher} onChange={setCipher} options={CIPHERS} ltr /></Field>
            <Field label="Auth (HMAC)"><Select value={auth} onChange={setAuth} options={AUTHS} ltr /></Field>
          </div>
        </div>
        <div className="space-y-4">
          <Field label={t("آدرس روتر و زیرشبکه‌ی کلاینت‌های OpenVPN", "Router address and OpenVPN client subnet")} hint={overlap ? <span className="text-talk">{t(`با زیرشبکه‌ی PPP (${ppp?.address}) هم‌پوشانی دارد`, `Overlaps the PPP subnet (${ppp?.address})`)}</span> : cidr ? t(`کلاینت‌ها از ${cidr.size - 3} آدرس این شبکه IP می‌گیرند`, `Clients get one of ${cidr.size - 3} addresses of this subnet`) : undefined}>
            <TextInput value={addr} onChange={setAddr} />
          </Field>
          <Check label={t("فقط ترافیک شبکه‌ی داخلی از تونل (split tunnel)", "Only LAN traffic through the tunnel (split tunnel)")} checked={split} onChange={setSplit} hint={t("خاموش = همه‌ی اینترنت کلاینت از روتر می‌رود.", "Off = all of the client's internet goes through the router.")} />
          <Check label={t("دسترسی کلاینت‌ها به شبکه‌ی داخلی و روتر", "Clients may reach the LAN and this router")} checked={allowLan} onChange={setAllowLan} hint={t("برای همه‌ی سرورهای PPP و OpenVPN مشترک است.", "Shared by the PPP and OpenVPN servers.")} />
          <Check label={t("پورت روی فایروال باز شود (از WAN)", "Open the port in the firewall (from WAN)")} checked={openFw} onChange={setOpenFw} />
          {o && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("پورت: ", "Port: ")}<Ltr className="mono">OpenVPN {proto.toUpperCase()} {port}</Ltr>.
            {t(" اگر روتر پشت مودم است، این پورت را روی مودم به این روتر فوروارد کنید.", " If this router is behind a modem, forward this port to it there.")}
          </div>
        </div>
      </div>
    </Modal>
  );
}

/** A client profile for the OpenVPN apps (user name and password are asked by the app). */
export function clientProfile(o: OpenVPNServer, host: string) {
  const d = ovpnDefaults(o);
  return [
    "client", "dev tun", `proto ${d.proto === "udp" ? "udp" : "tcp-client"}`, `remote ${host} ${d.port}`,
    "resolv-retry infinite", "nobind", "persist-key", "persist-tun", "auth-user-pass", "remote-cert-tls server",
    `data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:${d.cipher}`, `data-ciphers-fallback ${d.cipher}`, `auth ${d.auth}`, "verb 3",
    "<ca>", o.cert_pem.trim(), "</ca>", "",
  ].join("\n");
}

function download(text: string, fileName: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/x-openvpn-profile" }));
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(a.href);
}

function ServerCard({ s, o, live }: { s: PPPServer; o: OpenVPNServer; live?: Live["server"] & { openvpn?: RzLive } }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const toast = useToast();
  const [settings, setSettings] = useState(false);
  const [user, setUser] = useState<PPPUser | "new" | null>(null);
  const [help, setHelp] = useState(false);
  const d = ovpnDefaults(o);
  const host = o.domain || wanIP || "";
  const users = s.users || [];
  const ov = live?.openvpn;
  const fwOpen = (cfg?.firewall?.filter || []).some((r) => r.comment === FW && r.protocol === d.proto && r.dst_port === String(d.port));
  const chip = s.disabled || !o.enabled ? <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>
    : !ov?.active || ov.active === "inactive" ? <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>
    : ov.active === "active" ? <Chip tone="idle">{t("فعال", "running")}</Chip>
    : ov.active === "failed" ? <Chip tone="talk">{t("خطا", "failed")}</Chip> : <Chip tone="ring">{ov.active}</Chip>;
  const sessions = (live?.sessions || []).filter((x) => x.type === "openvpn");
  const kick = (ifname: string) => api("/api/v1/ppp/disconnect", { method: "POST", body: { ifname } }).then(() => toast(t("قطع شد", "Disconnected"))).catch((e) => toast(e.message));
  const others = !!(s.sstp || s.l2tp || s.pptp || s.ikev2);
  const remove = () => edit((c) => {
    if (others) {
      c.ppp_server!.openvpn = undefined;
      if ((c.firewall?.filter || []).some((r) => r.comment === FW)) setServerFw(c, c.ppp_server!);
    } else {
      c.ppp_server = undefined;
      clearServerFw(c);
      setLanAccess(c, false);
    }
  }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"));
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="server" className="size-5 text-accent" />
        <h2 className="card-title">OpenVPN</h2>
        {chip}
        <div className="ms-auto flex flex-wrap gap-2">
          <button className="btn btn-primary btn-sm" onClick={() => setUser("new")}><Icon name="plus" className="size-4" />{t("کاربر جدید", "New user")}</button>
          <button className="btn btn-sm" disabled={!host} onClick={() => download(clientProfile(o, host), `${host.replace(/[^a-zA-Z0-9.-]/g, "_") || "mahan-router"}.ovpn`)}><Icon name="file" className="size-4" />{t("فایل .ovpn کاربران", "Users' .ovpn file")}</button>
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setSettings(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={others ? t("سرور OpenVPN حذف شود؟ (کاربران و سرور SSTP / L2TP / PPTP می‌مانند)", "Delete the OpenVPN server? (Users and the SSTP / L2TP / PPTP server stay)") : t("سرور OpenVPN و همه‌ی کاربرانش حذف شود؟", "Delete the OpenVPN server and all its users?")} onConfirm={remove}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آدرس سرور برای کلاینت‌ها", "Server address for clients")}><Ltr className="mono">{host || "—"}:{d.port} {d.proto.toUpperCase()}</Ltr>{!fwOpen && <span className="ms-2 text-xs text-ring">{t("روی فایروال باز نیست", "not open in firewall")}</span>}</Info>
        <Info label={t("زیرشبکه‌ی کلاینت‌ها", "Client subnet")}><Ltr className="mono">{d.addr}</Ltr></Info>
        <Info label={t("ترافیک کلاینت‌ها", "Client traffic")}>{o.split_tunnel ? t("فقط شبکه‌ی داخلی", "LAN only (split)") : t("همه‌ی اینترنت", "all internet")}</Info>
        <Info label={t("دسترسی کلاینت‌ها", "Client access")}>{s.allow_lan ? t("اینترنت و شبکه‌ی داخلی", "internet and LAN") : t("فقط اینترنت", "internet only")}</Info>
      </div>

      {!!sessions.length && (
        <div className="overflow-x-auto border-t border-line">
          <div className="px-5 pt-3 text-xs font-medium text-ink-3">{t("متصل‌ها", "Connected now")}</div>
          <table className="w-full text-sm">
            <thead className="text-xs text-ink-3"><tr>
              <th className="px-4 py-2 text-start font-normal">{t("کاربر", "User")}</th><th className="px-4 py-2 text-start font-normal">IP</th>
              <th className="px-4 py-2 text-start font-normal">{t("از", "From")}</th><th className="px-4 py-2 text-start font-normal">{t("مدت", "Uptime")}</th>
              <th className="px-4 py-2 text-start font-normal">{t("دانلود / آپلود", "Down / Up")}</th><th />
            </tr></thead>
            <tbody className="divide-y divide-line">
              {sessions.map((x) => (
                <tr key={x.ifname}>
                  <td className="px-4 py-2 font-medium">{x.username || "—"}</td>
                  <td className="px-4 py-2"><Ltr className="mono">{x.ip || "—"}</Ltr></td>
                  <td className="px-4 py-2"><Ltr className="mono">{x.from}</Ltr></td>
                  <td className="px-4 py-2">{fmtDuration(x.uptime)}</td>
                  <td className="px-4 py-2"><Ltr className="mono">{fmtBytes(x.tx_bytes)} / {fmtBytes(x.rx_bytes)}</Ltr></td>
                  <td className="px-4 py-2 text-end"><ConfirmButton className="btn btn-sm" question={t(`اتصال ${x.username} قطع شود؟`, `Disconnect ${x.username}?`)} onConfirm={() => kick(x.ifname)}>{t("قطع", "Disconnect")}</ConfirmButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!users.length ? <div className="border-t border-line"><Empty title={t("هنوز کاربری ندارد", "No users yet")} /></div> : (
        <div className="overflow-x-auto border-t border-line">
          <div className="px-5 pt-3 text-xs font-medium text-ink-3">{t("کاربران (مشترک با SSTP / L2TP / PPTP)", "Users (shared with SSTP / L2TP / PPTP)")}</div>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-line">
              {users.map((u) => (
                <tr key={u.name}>
                  <td className="px-4 py-2.5 font-medium"><Ltr>{u.name}</Ltr>{u.disabled && <span className="ms-2 chip bg-talk-soft text-talk">{t("غیرفعال", "disabled")}</span>}</td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-end">
                    <button className="btn btn-sm" onClick={() => setUser(u)}><Icon name="settings" className="size-4" />{t("ویرایش", "Edit")}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="border-t border-line px-5 py-2">
        <button className="text-xs text-accent" onClick={() => setHelp(!help)}>{help ? t("بستن راهنما", "Hide help") : t("راهنمای اتصال دستگاه‌ها", "How to connect devices")}</button>
        {help && (
          <div className="mt-2 space-y-3 text-xs leading-6 text-ink-2">
            <div><b>{t("ویندوز، اندروید، آیفون، مک", "Windows, Android, iPhone, Mac")}</b>: {t("برنامه‌ی OpenVPN Connect (یا OpenVPN GUI در ویندوز) را نصب کنید، «فایل .ovpn کاربران» را در آن Import کنید و نام کاربری و رمز خودتان را بزنید.", "Install OpenVPN Connect (or OpenVPN GUI on Windows), import the \"Users' .ovpn file\" and enter your own user name and password.")}</div>
            <div><b>{t("میکروتیک", "MikroTik")}</b>: <Ltr className="mono">{`/interface ovpn-client add connect-to=${host || "HOST"} port=${d.port} protocol=${d.proto} mode=ip user=NAME password=PASS cipher=${MT_CIPHER[d.cipher] || "aes256-cbc"} auth=${d.auth.toLowerCase()} verify-server-certificate=no disabled=no`}</Ltr>
              <div className="text-ink-3">{t("روی RouterOS 6 فقط protocol=tcp و cipher=aes256 بنویسید.", "On RouterOS 6 use protocol=tcp and cipher=aes256.")}</div></div>
            <div><b>{t("روتر Mahan دیگر", "Another Mahan Router")}</b>: {t("VPN ← OpenVPN ← اتصال جدید ← وارد کردن فایل .ovpn.", "VPN → OpenVPN → New connection → Import a .ovpn file.")}</div>
          </div>
        )}
      </div>
      <LogView live={ov} />
      {settings && <ServerDialog s={s} onClose={() => setSettings(false)} />}
      {user && <UserDialog s={s} user={user === "new" ? undefined : user} onClose={() => setUser(null)} />}
    </div>
  );
}
