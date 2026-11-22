import { useState } from "react";
import { api, fmtBytes, fmtDuration, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { IKEv2Server, PPPServer, PPPUser } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, Ltr, Modal, TextInput, useToast } from "../ui";
import { Info, parseCidr, useWanIP } from "./Vpn";
import { UserDialog, hostRe, setLanAccess } from "./VpnPPP";
import type { Live } from "./VpnPPP";
import { LogView } from "./VpnRozaneh";
import type { RzLive } from "./VpnRozaneh";

// IKEv2 server for phones and laptops: the VPN type built into Windows,
// iPhone, Mac and Android. It uses the users of the SSTP / L2TP / PPTP
// server and its own client subnet. The firewall rules it needs are made
// by the router.

const SUBNET = "10.82.0.1/24";
type SrvLive = Live["server"] & { ikev2?: RzLive };

function download(text: string, fileName: string, type: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = fileName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

function Pem({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder: string }) {
  return <Field label={label}><textarea className="input ltr mono h-24 text-left text-xs" dir="ltr" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} /></Field>;
}

export default function IKEv2Section() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ server: SrvLive | null }>("/api/v1/ppp/status", 5000);
  const [dialog, setDialog] = useState(false);
  if (!cfg) return null;
  const srv = cfg.ppp_server;
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="card-title">{t("سرور IKEv2 برای گوشی و لپ‌تاپ", "IKEv2 server for phones and laptops")}</h2>
          <p className="text-sm text-ink-3">{t("VPN داخلی ویندوز، آیفون، مک و اندروید، بدون نصب برنامه. کاربران با نام کاربری و رمز وارد می‌شوند و با سرور SSTP / L2TP / PPTP مشترک‌اند.", "The VPN built into Windows, iPhone, Mac and Android, with no app to install. Users sign in with a user name and password, shared with the SSTP / L2TP / PPTP server.")}</p>
        </div>
        {!srv?.ikev2 && <button className="btn btn-primary btn-sm" onClick={() => setDialog(true)}><Icon name="plus" className="size-4" />{t("راه‌اندازی سرور", "Set up the server")}</button>}
      </div>
      {srv?.ikev2 ? <ServerCard s={srv} o={srv.ikev2} live={live?.server || undefined} /> : <div className="card"><Empty icon="server" title={t("سرور راه‌اندازی نشده", "No server yet")} /></div>}
      {dialog && <ServerDialog onClose={() => setDialog(false)} />}
    </section>
  );
}

function ServerDialog({ s, onClose }: { s?: PPPServer; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const wanIP = useWanIP(cfg);
  const toast = useToast();
  const o = s?.ikev2;
  const ppp = cfg?.ppp_server;
  const [host, setHost] = useState(o?.domain || "");
  const [addr, setAddr] = useState(o?.address || SUBNET);
  const [split, setSplit] = useState(!!o?.split_tunnel);
  const [allowLan, setAllowLan] = useState(!!ppp?.allow_lan);
  const [own, setOwn] = useState(false);
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [caPem, setCaPem] = useState("");
  const [disabled, setDisabled] = useState(o ? !o.enabled : false);
  const [busy, setBusy] = useState(false);
  const name = host.trim() || wanIP || "";
  const cidr = parseCidr(addr);
  const clash = [ppp?.address, ppp?.openvpn ? ppp.openvpn.address || "10.81.0.1/24" : undefined].map((x) => (x ? parseCidr(x) : null))
    .some((p) => !!cidr && !!p && Math.max(cidr.net, p.net) < Math.min(cidr.net + cidr.size, p.net + p.size));
  const valid = !!cidr && cidr.len >= 16 && cidr.len <= 29 && !clash && hostRe.test(name)
    && (!own || (certPem.includes("BEGIN CERTIFICATE") && keyPem.includes("PRIVATE KEY")));
  const save = async () => {
    setBusy(true);
    try {
      let cert = o?.cert_pem || "", key = o?.key_pem || "", ca = o?.ca_pem;
      if (own) { cert = certPem.trim(); key = keyPem.trim(); ca = caPem.trim() || undefined; }
      else if (!cert || o?.domain !== name) {
        const r = await api<{ ca_pem: string; cert_pem: string; key_pem: string }>("/api/v1/ppp/ikev2-cert", { method: "POST", body: { name } });
        cert = r.cert_pem; key = r.key_pem; ca = r.ca_pem;
      }
      const n: IKEv2Server = { enabled: !disabled, address: addr.trim() === SUBNET ? undefined : addr.trim(), domain: name, cert_pem: cert, key_pem: key, ca_pem: ca, split_tunnel: split || undefined };
      const ok = await edit((c) => {
        const p: PPPServer = c.ppp_server || { address: "10.80.0.1/24", users: [] };
        p.ikev2 = n;
        p.allow_lan = allowLan || undefined;
        c.ppp_server = p;
        setLanAccess(c, allowLan);
      }, o ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("سرور ساخته شد (هنوز اعمال نشده)", "Server created (not applied yet)"));
      if (ok) onClose();
    } catch (e) { toast((e as Error).message, "error"); } finally { setBusy(false); }
  };
  const renew = !own && !!o?.cert_pem && o.domain !== name;
  return (
    <Modal open wide onClose={onClose} title={o ? t("تنظیمات سرور IKEv2", "IKEv2 server settings") : t("راه‌اندازی سرور IKEv2", "Set up an IKEv2 server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid || busy} onClick={save}>{o ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <Field label={t("آدرسی که دستگاه‌ها می‌زنند", "Address the devices dial")} hint={t("دامنه یا IP عمومی؛ خالی = IP فعلی WAN. دستگاه‌ها باید دقیقاً همین را وارد کنند.", "Public domain or IP; empty = current WAN IP. Devices must enter exactly this.")}><TextInput value={host} placeholder={wanIP || "vpn.example.com"} onChange={setHost} /></Field>
          {renew && <p className="text-xs text-ring">{t("با عوض شدن آدرس، گواهی تازه ساخته می‌شود و دستگاه‌ها باید گواهی جدید را نصب کنند.", "A new address means a new certificate, and devices must install the new one.")}</p>}
          <Check label={t("گواهی خودم را دارم", "I have my own certificate")} checked={own} onChange={setOwn} hint={t("خاموش = روتر یک گواهی می‌سازد که دستگاه‌ها یک بار نصبش می‌کنند. با گواهی معتبر (مثلاً Let's Encrypt) نصب لازم نیست.", "Off = the router makes a certificate that devices install once. With a public certificate (Let's Encrypt, for example) nothing is installed.")} />
          {own && <>
            <Pem label={t("گواهی سرور (PEM)", "Server certificate (PEM)")} value={certPem} onChange={setCertPem} placeholder="-----BEGIN CERTIFICATE-----" />
            <Pem label={t("کلید خصوصی (PEM)", "Private key (PEM)")} value={keyPem} onChange={setKeyPem} placeholder="-----BEGIN PRIVATE KEY-----" />
            <Pem label={t("گواهی مرجع صادرکننده (اختیاری)", "Issuing authority's certificate (optional)")} value={caPem} onChange={setCaPem} placeholder="-----BEGIN CERTIFICATE-----" />
          </>}
        </div>
        <div className="space-y-4">
          <Field label={t("آدرس روتر و زیرشبکه‌ی کلاینت‌های IKEv2", "Router address and IKEv2 client subnet")} hint={clash ? <span className="text-talk">{t("با زیرشبکه‌ی PPP یا OpenVPN هم‌پوشانی دارد", "Overlaps the PPP or OpenVPN subnet")}</span> : cidr ? t(`کلاینت‌ها از ${cidr.size - 3} آدرس این شبکه IP می‌گیرند`, `Clients get one of ${cidr.size - 3} addresses of this subnet`) : undefined}>
            <TextInput value={addr} onChange={setAddr} />
          </Field>
          <Check label={t("فقط شبکه‌های این روتر پیشنهاد شود (split tunnel)", "Offer only this router's networks (split tunnel)")} checked={split} onChange={setSplit} hint={t("خاموش = همه‌ی اینترنت دستگاه از روتر می‌رود. ویندوز و آیفون خودشان هم در این باره تصمیم می‌گیرند.", "Off = all of the device's internet goes through the router. Windows and iPhone also decide this themselves.")} />
          <Check label={t("دسترسی کلاینت‌ها به شبکه‌ی داخلی و روتر", "Clients may reach the LAN and this router")} checked={allowLan} onChange={setAllowLan} hint={t("برای همه‌ی سرورهای PPP، OpenVPN و IKEv2 مشترک است.", "Shared by the PPP, OpenVPN and IKEv2 servers.")} />
          {o && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("پورت‌ها: ", "Ports: ")}<Ltr className="mono">UDP 500, 4500</Ltr>{t("؛ روتر خودش آن‌ها را روی فایروال باز می‌کند. اگر روتر پشت مودم است، این دو پورت را روی مودم به این روتر فوروارد کنید.", "; the router opens them in its firewall itself. If this router is behind a modem, forward both ports to it there.")}
          </div>
        </div>
      </div>
    </Modal>
  );
}

function ServerCard({ s, o, live }: { s: PPPServer; o: IKEv2Server; live?: SrvLive }) {
  const { edit } = useConfig();
  const toast = useToast();
  const [settings, setSettings] = useState(false);
  const [user, setUser] = useState<PPPUser | "new" | null>(null);
  const [help, setHelp] = useState(false);
  const ik = live?.ikev2;
  const users = s.users || [];
  const chip = s.disabled || !o.enabled ? <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>
    : !ik?.active || ik.active === "inactive" ? <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>
      : ik.active === "active" && ik.up ? <Chip tone="idle">{t("فعال", "running")}</Chip>
        : ik.active === "failed" ? <Chip tone="talk">{t("خطا", "failed")}</Chip> : <Chip tone="ring">{ik.active}</Chip>;
  const sessions = (live?.sessions || []).filter((x) => x.type === "ikev2");
  const kick = (ifname: string) => api("/api/v1/ppp/disconnect", { method: "POST", body: { ifname } }).then(() => toast(t("قطع شد", "Disconnected"))).catch((e) => toast(e.message, "error"));
  const others = !!(s.sstp || s.l2tp || s.pptp || s.openvpn);
  const remove = () => edit((c) => {
    if (others) c.ppp_server!.ikev2 = undefined;
    else { c.ppp_server = undefined; setLanAccess(c, false); }
  }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"));
  const file = o.domain.replace(/[^a-zA-Z0-9.-]/g, "_");
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="server" className="size-5 text-accent" />
        <h2 className="card-title">IKEv2</h2>
        {chip}
        <div className="ms-auto flex flex-wrap gap-2">
          <button className="btn btn-primary btn-sm" onClick={() => setUser("new")}><Icon name="plus" className="size-4" />{t("کاربر جدید", "New user")}</button>
          {o.ca_pem && <button className="btn btn-sm" onClick={() => download(o.ca_pem!, `${file}-ca.crt`, "application/x-x509-ca-cert")}><Icon name="file" className="size-4" />{t("گواهی برای دستگاه‌ها", "Certificate for devices")}</button>}
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setSettings(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={others ? t("سرور IKEv2 حذف شود؟ (کاربران و بقیه‌ی سرورها می‌مانند)", "Delete the IKEv2 server? (Users and the other servers stay)") : t("سرور IKEv2 و همه‌ی کاربرانش حذف شود؟", "Delete the IKEv2 server and all its users?")} onConfirm={remove}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آدرس سرور برای دستگاه‌ها", "Server address for devices")}><Ltr className="mono">{o.domain}</Ltr></Info>
        <Info label={t("زیرشبکه‌ی کلاینت‌ها", "Client subnet")}><Ltr className="mono">{o.address || SUBNET}</Ltr></Info>
        <Info label={t("ترافیک کلاینت‌ها", "Client traffic")}>{o.split_tunnel ? t("فقط شبکه‌های روتر", "router's networks only (split)") : t("همه‌ی اینترنت", "all internet")}</Info>
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
          <div className="px-5 pt-3 text-xs font-medium text-ink-3">{t("کاربران (مشترک با SSTP / L2TP / PPTP و OpenVPN)", "Users (shared with SSTP / L2TP / PPTP and OpenVPN)")}</div>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-line">
              {users.map((u) => (
                <tr key={u.name}>
                  <td className="px-4 py-2.5 font-medium"><Ltr>{u.name}</Ltr>{u.disabled && <span className="chip ms-2 bg-talk-soft text-talk">{t("غیرفعال", "disabled")}</span>}</td>
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
            {o.ca_pem && <div><b>{t("اول، گواهی", "First, the certificate")}</b>: {t("«گواهی برای دستگاه‌ها» را دانلود و روی هر دستگاه یک بار نصب کنید. ویندوز: دابل‌کلیک ← Install Certificate ← Local Machine ← Trusted Root Certification Authorities. آیفون و مک: فایل را باز کنید، پروفایل را نصب کنید و در Settings ← General ← About ← Certificate Trust Settings به آن اعتماد کامل بدهید. اندروید: Settings ← Security ← Install a certificate ← CA certificate.", "Download \"Certificate for devices\" and install it once on each device. Windows: double-click → Install Certificate → Local Machine → Trusted Root Certification Authorities. iPhone and Mac: open the file, install the profile, and give it full trust under Settings → General → About → Certificate Trust Settings. Android: Settings → Security → Install a certificate → CA certificate.")}</div>}
            <div><b>{t("ویندوز", "Windows")}</b>: {t("تنظیمات ← شبکه ← VPN ← افزودن؛ نوع VPN را IKEv2 بگذارید، آدرس سرور ", "Settings → Network → VPN → Add; VPN type IKEv2, server ")}<Ltr className="mono">{o.domain}</Ltr>{t("، نوع ورود «نام کاربری و رمز».", ", sign-in type \"User name and password\".")}</div>
            <div><b>{t("آیفون و مک", "iPhone and Mac")}</b>: {t("Settings ← VPN ← Add ← IKEv2؛ Server و Remote ID هر دو ", "Settings → VPN → Add → IKEv2; Server and Remote ID both ")}<Ltr className="mono">{o.domain}</Ltr>{t("، Local ID خالی، User Authentication = Username.", ", Local ID empty, User Authentication = Username.")}</div>
            <div><b>{t("اندروید", "Android")}</b>: {t("Settings ← Network ← VPN ← افزودن؛ نوع IKEv2/IPSec MSCHAPv2، آدرس سرور و IPSec identifier هر دو ", "Settings → Network → VPN → Add; type IKEv2/IPSec MSCHAPv2, server address and IPSec identifier both ")}<Ltr className="mono">{o.domain}</Ltr>{t("، و گواهی CA همانی که نصب کردید. برنامه‌ی strongSwan هم کار می‌کند.", ", with the CA certificate you installed. The strongSwan app works too.")}</div>
          </div>
        )}
      </div>
      <LogView live={ik} />
      {settings && <ServerDialog s={s} onClose={() => setSettings(false)} />}
      {user && <UserDialog s={s} user={user === "new" ? undefined : user} onClose={() => setUser(null)} />}
    </div>
  );
}
