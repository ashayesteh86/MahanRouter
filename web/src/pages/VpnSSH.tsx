import { useState } from "react";
import { api, fmtBytes, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Iface, SSHClient } from "../types";
import { Check, ConfirmButton, Empty, Field, Icon, Ltr, Modal, Select, TextInput, useToast } from "../ui";
import { Info } from "./Vpn";
import { hostRe } from "./VpnPPP";
import { LogView, RoutingFields, liveChip, removeIface, routingLabel, routingOf, setRouting } from "./VpnRozaneh";
import type { Routing, RzLive } from "./VpnRozaneh";

// SSH tab. The router logs in to an ordinary SSH server and sends TCP
// traffic through it (sing-box TUN + SSH outbound, routed by policy like
// the V2Ray client). The server needs no VPN software.

const keyRe = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+-----END [A-Z0-9 ]*PRIVATE KEY-----/;
const hostKeyRe = /^(ssh-|ecdsa-|sk-)\S+ [A-Za-z0-9+/=]{40,}$/;
const keyType = (k: string) => k.split(" ")[0].replace(/^ssh-/, "").replace(/^ecdsa-sha2-nistp/, "ecdsa-");

export default function SSHTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ interfaces: RzLive[] }>("/api/v1/ssh/status", 5000);
  const [dialog, setDialog] = useState(false);
  if (!cfg) return null;
  const clients = cfg.interfaces.filter((i) => i.type === "ssh");
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="card-title">{t("اتصال روتر به یک سرور SSH", "Connect this router to an SSH server")}</h2>
          <p className="text-sm text-ink-3">{t("هر سرور لینوکسی که SSH دارد کافی است؛ نرم‌افزار VPN روی سرور لازم نیست. انتخاب کنید ترافیک کدام دستگاه‌ها از تونل برود.", "Any Linux server with SSH will do; it needs no VPN software. Choose which traffic goes through the tunnel.")}</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setDialog(true)}><Icon name="plus" className="size-4" />{t("اتصال جدید", "New connection")}</button>
      </div>
      {!clients.length && <div className="card"><Empty icon="lock" title={t("هنوز اتصالی ساخته نشده", "No connection yet")}>{t("آدرس سرور، نام کاربری و رمز یا کلید SSH را وارد کنید (همان چیزی که با دستور ssh استفاده می‌کنید).", "Enter the server address, user name and the password or SSH key (what you use with the ssh command).")}</Empty></div>}
      {clients.map((c) => <ClientCard key={c.name} ifc={c} live={(live?.interfaces || []).find((x) => x.name === c.name)} />)}
      <p className="text-xs text-ink-3">{t("تونل SSH فقط TCP را عبور می‌دهد: وب، ایمیل و بیشتر برنامه‌ها کار می‌کنند و DNS از داخل تونل جواب داده می‌شود، ولی بقیه‌ی UDP (تماس صوتی و تصویری، بعضی بازی‌ها، QUIC) از این تونل نمی‌گذرد. روی سرور باید AllowTcpForwarding فعال باشد (پیش‌فرض OpenSSH همین است).", "An SSH tunnel carries TCP only: web, mail and most apps work and DNS is answered through the tunnel, but other UDP (voice and video calls, some games, QUIC) does not pass. The server must allow TCP forwarding (AllowTcpForwarding, OpenSSH's default).")}</p>
      {dialog && <ClientDialog onClose={() => setDialog(false)} />}
    </div>
  );
}

function ClientDialog({ ifc, routing: initial, onClose }: { ifc?: Iface; routing?: Routing; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const toast = useToast();
  const used = new Set((cfg?.interfaces || []).map((i) => i.name));
  let n = 1;
  while (used.has(`ssh${n}`)) n++;
  const o = ifc?.ssh;
  const [name, setName] = useState(ifc?.name || `ssh${n}`);
  const [server, setServer] = useState(o?.server || "");
  const [port, setPort] = useState(String(o?.port || 22));
  const [username, setUsername] = useState(o?.username || "");
  const [mode, setMode] = useState<"password" | "key">(o?.private_key ? "key" : "password");
  const [password, setPassword] = useState(o?.password || "");
  const [key, setKey] = useState(o?.private_key || "");
  const [passphrase, setPassphrase] = useState(o?.passphrase || "");
  const [pub, setPub] = useState("");
  const [hostKeys, setHostKeys] = useState<string[]>(o?.host_keys || []);
  const [busy, setBusy] = useState("");
  const [disabled, setDisabled] = useState(!!ifc?.disabled);
  const [routing, setR] = useState<Routing>(initial || { mode: "except_iran", devices: [], dns: true, block: false });

  const portOK = /^\d{1,5}$/.test(port) && +port > 0 && +port < 65536;
  const targetOK = hostRe.test(server.trim()) && portOK;
  const authOK = mode === "password" ? password.length > 0 && !/[\r\n]/.test(password) : keyRe.test(key);
  const valid = (!!ifc || (/^[a-z][a-z0-9-]{0,14}$/.test(name) && !used.has(name))) && targetOK && /^\S{1,64}$/.test(username) && authOK
    && hostKeys.every((k) => hostKeyRe.test(k)) && (routing.mode !== "devices" || routing.devices.length > 0);

  const generate = async () => {
    setBusy("key");
    try {
      const kp = await api<{ private_key: string; public_key: string }>("/api/v1/ssh/keypair", { method: "POST" });
      setKey(kp.private_key); setPub(kp.public_key); setPassphrase("");
    } catch (e) { toast((e as Error).message); } finally { setBusy(""); }
  };
  const readHostKey = async () => {
    setBusy("host");
    try {
      const r = await api<{ host_keys: string[] }>("/api/v1/ssh/hostkey", { method: "POST", body: { server: server.trim(), port: +port } });
      setHostKeys(r.host_keys);
    } catch (e) { toast((e as Error).message); } finally { setBusy(""); }
  };
  const copy = (s: string) => navigator.clipboard?.writeText(s).then(() => toast(t("کپی شد", "Copied")));
  const save = async () => {
    const ssh: SSHClient = {
      server: server.trim(), port: +port === 22 ? undefined : +port, username,
      password: mode === "password" ? password : undefined,
      private_key: mode === "key" ? key.trim() + "\n" : undefined,
      passphrase: mode === "key" && passphrase ? passphrase : undefined,
      host_keys: hostKeys.length ? hostKeys : undefined,
    };
    const ok = await edit((c) => {
      if (ifc) {
        const i = c.interfaces.find((x) => x.name === ifc.name)!;
        i.ssh = ssh;
        i.disabled = disabled || undefined;
      } else {
        c.interfaces.push({ name, type: "ssh", comment: `SSH ${ssh.server}`, ssh });
        c.interface_lists = c.interface_lists || {};
        c.interface_lists.WAN = [...new Set([...(c.interface_lists.WAN || []), name])];
      }
      setRouting(c, ifc?.name || name, routing);
    }, ifc ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("اتصال ساخته شد (هنوز اعمال نشده)", "Connection created (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={ifc ? `${t("تنظیمات", "Settings")} ${ifc.name}` : t("اتصال روتر به سرور SSH", "Connect the router to an SSH server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{ifc ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <Field className="col-span-2" label={t("آدرس سرور", "Server address")}><TextInput value={server} placeholder="vps.example.com" onChange={setServer} /></Field>
            <Field label={t("پورت", "Port")}><TextInput value={port} onChange={setPort} /></Field>
          </div>
          <Field label={t("نام کاربری", "User name")}><TextInput value={username} placeholder="root" onChange={setUsername} /></Field>
          <Field label={t("روش ورود", "Sign-in method")}>
            <Select value={mode} onChange={(v) => setMode(v as "password" | "key")} options={[{ value: "password", label: t("رمز عبور", "Password") }, { value: "key", label: t("کلید SSH", "SSH key") }]} />
          </Field>
          {mode === "password" && <Field label={t("رمز عبور", "Password")}><TextInput type="password" value={password} onChange={setPassword} /></Field>}
          {mode === "key" && <>
            <Field label={t("کلید خصوصی", "Private key")} hint={key && !keyRe.test(key) ? <span className="text-talk">{t("کلید خصوصی شناخته نشد", "Not a private key")}</span> : t("محتوای فایل id_ed25519 یا id_rsa را وارد کنید، یا کلید تازه بسازید.", "Paste the contents of id_ed25519 or id_rsa, or make a new key.")}>
              <textarea className="input mono ltr min-h-24 text-left text-xs" dir="ltr" spellCheck={false} value={key} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" onChange={(e) => { setKey(e.target.value); setPub(""); }} />
            </Field>
            <button className="btn btn-sm" disabled={busy === "key"} onClick={generate}><Icon name="plus" className="size-4" />{t("ساخت کلید تازه", "Make a new key")}</button>
            {pub && <Field label={t("کلید عمومی (روی سرور بگذارید)", "Public key (put it on the server)")} hint={<>{t("این خط را به فایل ", "Add this line to ")}<Ltr className="mono">~/.ssh/authorized_keys</Ltr>{t(" همان کاربر روی سرور اضافه کنید.", " of that user on the server.")}</>}>
              <div className="flex gap-2"><input className="input mono ltr text-left text-xs" dir="ltr" readOnly value={pub} onFocus={(e) => e.target.select()} /><button className="btn btn-sm" onClick={() => copy(pub)}>{t("کپی", "Copy")}</button></div>
            </Field>}
            {!pub && <Field label={t("رمز کلید", "Key passphrase")} hint={t("اگر کلید رمز ندارد خالی بگذارید", "leave empty if the key has none")}><TextInput type="password" value={passphrase} onChange={setPassphrase} /></Field>}
          </>}
          {/* not a Field: a <label> around buttons would press the first one */}
          <div>
            <span className="label">{t("کلید سرور (host key)", "Server host key")}</span>
            <div className="flex flex-wrap items-center gap-2">
              <button className="btn btn-sm" disabled={!targetOK || busy === "host"} onClick={readHostKey}>{busy === "host" ? t("در حال خواندن…", "Reading…") : t("خواندن از سرور", "Read from the server")}</button>
              {hostKeys.map((k) => <Ltr key={k} className="mono rounded bg-surface-2 px-2 py-1 text-xs" >{keyType(k)} …{k.slice(-12)}</Ltr>)}
              {hostKeys.length > 0 && <button className="btn btn-sm" onClick={() => setHostKeys([])}>{t("حذف", "Clear")}</button>}
            </div>
            <span className="mt-1 block text-xs text-ink-3">{hostKeys.length ? t("روتر فقط به سروری با همین کلید وصل می‌شود.", "The router only connects to a server with this key.") : t("بدون آن، روتر هر کلیدی را می‌پذیرد و کسی در مسیر می‌تواند خود را جای سرور جا بزند.", "Without it the router accepts any key, and someone on the path could pose as the server.")}</span>
          </div>
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
  const o = ifc.ssh;
  const routing = routingOf((cfg?.policy_routes || []).find((p) => p.interface === ifc.name));
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="lock" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        {liveChip(ifc, live)}
        <div className="ms-auto flex gap-2">
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`اتصال ${ifc.name} حذف شود؟`, `Delete connection ${ifc.name}?`)} onConfirm={() => edit((c) => removeIface(c, ifc.name), t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-5">
        <Info label={t("سرور", "Server")}><Ltr className="mono">{o ? `${o.server}:${o.port || 22}` : "—"}</Ltr></Info>
        <Info label={t("کاربر", "User")}><Ltr className="mono">{o?.username || "—"}</Ltr></Info>
        <Info label={t("ورود", "Sign-in")}>{o?.private_key ? t("کلید SSH", "SSH key") : t("رمز عبور", "password")}{o?.host_keys?.length ? t(" · کلید سرور قفل شده", " · host key pinned") : ""}</Info>
        <Info label={t("دانلود / آپلود", "Down / Up")}><Ltr className="mono">{live?.up ? `${fmtBytes(live.rx_bytes)} / ${fmtBytes(live.tx_bytes)}` : "—"}</Ltr></Info>
        <Info label={t("مسیریابی", "Routing")}>{routingLabel(routing)}</Info>
      </div>
      <LogView live={live} />
      {editing && <ClientDialog ifc={ifc} routing={routing} onClose={() => setEditing(false)} />}
    </div>
  );
}
