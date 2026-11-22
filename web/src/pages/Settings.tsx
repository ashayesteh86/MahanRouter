import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, t } from "../lib";
import { useConfig, usePoll } from "../store";
import { Check, ConfirmButton, Field, Icon, ListInput, Ltr, PageHead, Tabs, TextInput, useToast } from "../ui";

export default function Settings() {
  const { tab = "system" } = useParams();
  const nav = useNavigate();
  return (
    <div className="space-y-4">
      <PageHead title={t("تنظیمات", "Settings")} />
      <Tabs value={tab} onChange={(id) => nav(`/settings/${id}`)} tabs={[
        { id: "system", label: t("سیستم و زمان", "System and time"), icon: "server" },
        { id: "users", label: t("کاربران پنل", "Panel users"), icon: "users" },
        { id: "backup", label: t("پشتیبان", "Backup"), icon: "disk" },
      ]} />
      {tab === "users" ? <Users /> : tab === "backup" ? <Backup /> : <SystemTab />}
    </div>
  );
}

function SystemTab() {
  const { cfg, edit } = useConfig();
  const [host, setHost] = useState("");
  const [tz, setTz] = useState("");
  const [fwd, setFwd] = useState(true);
  const [ntp, setNtp] = useState<string[]>([]);
  const [serve, setServe] = useState<string[]>([]);
  useEffect(() => {
    if (!cfg) return;
    setHost(cfg.system.hostname); setTz(cfg.system.timezone || ""); setFwd(cfg.system.ip_forwarding !== false);
    setNtp(cfg.ntp?.servers || []); setServe(cfg.ntp?.serve_to || []);
  }, [cfg]);
  const save = () => edit((c) => {
    c.system = { hostname: host, timezone: tz || undefined, ip_forwarding: fwd ? undefined : false };
    c.ntp = ntp.length || serve.length ? { servers: ntp.length ? ntp : undefined, serve_to: serve.length ? serve : undefined } : undefined;
  }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <div className="card space-y-4 p-5">
        <Field label={t("نام روتر (hostname)", "Host name")}><TextInput value={host} onChange={setHost} /></Field>
        <Field label={t("منطقه‌ی زمانی", "Time zone")} hint="Asia/Tehran, Asia/Dubai, UTC"><TextInput value={tz} onChange={setTz} /></Field>
        <Check label={t("مسیریابی بسته‌ها (IP forwarding)", "Route packets (IP forwarding)")} checked={fwd} onChange={setFwd} hint={t("بدون آن، دستگاه روتر نیست", "Without it the device is not a router")} />
      </div>
      <div className="card space-y-4 p-5">
        <Field label={t("سرورهای NTP", "NTP servers")} hint="pool.ntp.org"><ListInput value={ntp} onChange={setNtp} /></Field>
        <Field label={t("سرویس زمان به این شبکه‌ها", "Serve time to these networks")} hint="192.168.88.0/24"><ListInput value={serve} onChange={setServe} /></Field>
      </div>
      <div><button className="btn btn-primary" onClick={save}><Icon name="check" className="size-4" />{t("ذخیره", "Save")}</button></div>
    </div>
  );
}

function Users() {
  const [users, reload] = usePoll<{ name: string; must_change?: boolean }[]>("/panel/api/users", 0);
  const [me] = usePoll<{ user: string }>("/panel/api/me", 0);
  const toast = useToast();
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [nw2, setNw2] = useState("");
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const change = async (e: React.FormEvent) => {
    e.preventDefault();
    if (nw !== nw2) { toast(t("دو رمز جدید یکی نیستند", "The two new passwords differ"), "error"); return; }
    try {
      await api("/panel/api/password", { method: "POST", body: { current: cur, new: nw } });
      toast(t("رمز عوض شد", "Password changed"));
      setCur(""); setNw(""); setNw2("");
      setTimeout(() => location.reload(), 800);
    } catch (x) { toast((x as Error).message, "error"); }
  };
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await api("/panel/api/users", { method: "POST", body: { name, password: pw } }); toast(t("کاربر اضافه شد", "User added")); setName(""); setPw(""); reload(); }
    catch (x) { toast((x as Error).message, "error"); }
  };
  const del = async (n: string) => {
    try { await api(`/panel/api/users/${encodeURIComponent(n)}`, { method: "DELETE" }); reload(); }
    catch (x) { toast((x as Error).message, "error"); }
  };
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <form onSubmit={change} className="card space-y-4 p-5">
        <h2 className="card-title">{t("تغییر رمز خودم", "Change my password")}</h2>
        <Field label={t("رمز فعلی", "Current password")}><TextInput type="password" value={cur} onChange={setCur} /></Field>
        <Field label={t("رمز جدید", "New password")} hint={t("حداقل ۸ حرف", "At least 8 characters")}><TextInput type="password" value={nw} onChange={setNw} /></Field>
        <Field label={t("تکرار رمز جدید", "Repeat new password")}><TextInput type="password" value={nw2} onChange={setNw2} /></Field>
        <button className="btn btn-primary" disabled={!cur || nw.length < 8}><Icon name="lock" className="size-4" />{t("تغییر رمز", "Change password")}</button>
        <p className="text-xs text-ink-3">{t("این رمز فقط برای پنل وب است. رمز ورود به کنسول (root) با دستور passwd عوض می‌شود.", "This password is for the web panel only. The console (root) password is changed with passwd.")}</p>
      </form>
      <div className="card p-5">
        <h2 className="card-title mb-3">{t("کاربران پنل", "Panel users")}</h2>
        <ul className="mb-4 divide-y divide-line rounded-lg border border-line">
          {(users || []).map((u) => (
            <li key={u.name} className="flex items-center gap-2 px-3 py-2 text-sm">
              <Icon name="user" className="size-4 text-ink-3" /><span className="flex-1"><Ltr>{u.name}</Ltr>{u.must_change && <span className="ms-2 text-xs text-ring">{t("رمز پیش‌فرض", "default password")}</span>}</span>
              {u.name !== me?.user && <ConfirmButton className="icon-btn text-talk" question={t(`کاربر ${u.name} حذف شود؟`, `Delete user ${u.name}?`)} onConfirm={() => del(u.name)}><Icon name="trash" className="size-4" /></ConfirmButton>}
            </li>
          ))}
        </ul>
        <form onSubmit={add} className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
          <Field label={t("نام کاربری", "User name")}><TextInput value={name} onChange={(v) => setName(v.toLowerCase())} /></Field>
          <Field label={t("رمز", "Password")}><TextInput type="password" value={pw} onChange={setPw} /></Field>
          <button className="btn" disabled={!name || pw.length < 8}><Icon name="plus" className="size-4" />{t("افزودن", "Add")}</button>
        </form>
        <p className="mt-3 text-xs text-ink-3">{t("همه‌ی کاربران فعلاً دسترسی کامل دارند. نقش‌ها و دسترسی محدود در نسخه‌های بعد اضافه می‌شود.", "All users have full access for now. Roles come in a later version.")}</p>
      </div>
    </div>
  );
}

// Backup = the running configuration as one file. Restore loads a file as
// the candidate; it is applied on the Changes page like any other edit.
function Backup() {
  const { reload, refreshStatus, status } = useConfig();
  const nav = useNavigate();
  const toast = useToast();
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [file, setFile] = useState<{ name: string; text: string } | null>(null);
  const [rpw, setRpw] = useState("");
  const [result, setResult] = useState<{ valid: boolean; problems?: string[]; hostname?: string; unchanged?: boolean } | null>(null);
  const encrypted = !!file && /"format"\s*:\s*"mahan-router-backup"/.test(file.text.slice(0, 400));

  const download = async () => {
    if (pw !== pw2) { toast(t("دو رمز یکی نیستند", "The two passwords differ"), "error"); return; }
    setBusy(true);
    try {
      const res = await fetch("/api/v1/backup", {
        method: "POST", credentials: "same-origin",
        headers: { "X-Requested-With": "mahan-panel", "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw }),
      });
      if (!res.ok) throw new Error((await res.json().catch(() => null))?.error || `HTTP ${res.status}`);
      const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "")?.[1] || "mahan-router-backup.yaml";
      const a = document.createElement("a");
      a.href = URL.createObjectURL(await res.blob());
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      toast(t("فایل پشتیبان ساخته شد", "Backup file made"));
      setPw(""); setPw2("");
    } catch (x) { toast((x as Error).message, "error"); }
    finally { setBusy(false); }
  };

  const pick = (f?: File) => {
    setResult(null); setRpw("");
    if (!f) { setFile(null); return; }
    if (f.size > 2 << 20) { toast(t("فایل بزرگ‌تر از 2MB است", "The file is larger than 2MB"), "error"); return; }
    f.text().then((text) => setFile({ name: f.name, text }));
  };

  const restore = async () => {
    if (!file) return;
    setBusy(true);
    try {
      const r = await api<{ valid: boolean; problems?: string[]; hostname?: string; unchanged?: boolean }>("/api/v1/backup/restore", { method: "POST", body: { content: file.text, password: rpw } });
      setResult(r);
      await reload(); await refreshStatus();
      toast(r.unchanged ? t("این پشتیبان با تنظیمات فعلی یکی است", "This backup is the same as the current settings") : t("پشتیبان بارگذاری شد (هنوز اعمال نشده)", "Backup loaded (not applied yet)"));
    } catch (x) { toast((x as Error).message, "error"); }
    finally { setBusy(false); }
  };

  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <div className="card space-y-4 p-5">
        <h2 className="card-title">{t("گرفتن پشتیبان", "Make a backup")}</h2>
        <p className="text-sm text-ink-2">{t("همه‌ی تنظیمات فعال روتر در یک فایل: اینترفیس‌ها، فایروال، DHCP، DNS، مسیرها و VPNها.", "Every active setting of the router in one file: interfaces, firewall, DHCP, DNS, routes and VPNs.")}</p>
        <Field label={t("رمز فایل (اختیاری)", "File password (optional)")}><TextInput type="password" value={pw} onChange={setPw} /></Field>
        {pw && <Field label={t("تکرار رمز", "Repeat password")}><TextInput type="password" value={pw2} onChange={setPw2} /></Field>}
        <p className="text-xs text-ink-3">{pw
          ? t("فایل رمزنگاری می‌شود و بدون این رمز باز نمی‌شود. رمز را جایی نگه دارید؛ راهی برای بازیابی آن نیست.", "The file is encrypted and cannot be opened without this password. Keep it somewhere; it cannot be recovered.")
          : t("بدون رمز، فایل یک متن YAML خواناست و رمزها و کلیدهای VPN داخل آن دیده می‌شوند.", "Without a password the file is readable YAML text, and VPN passwords and keys are visible in it.")}</p>
        <button className="btn btn-primary" disabled={busy || (!!pw && pw !== pw2)} onClick={download}><Icon name="down" className="size-4" />{t("دانلود پشتیبان", "Download backup")}</button>
        <p className="text-xs text-ink-3">{t("کاربران و رمزهای پنل و گواهی HTTPS پنل در پشتیبان نیستند.", "Panel users, their passwords and the panel HTTPS certificate are not in the backup.")}</p>
      </div>
      <div className="card space-y-4 p-5">
        <h2 className="card-title">{t("بازگردانی پشتیبان", "Restore a backup")}</h2>
        <p className="text-sm text-ink-2">{t("فایل به‌عنوان تغییرات اعمال‌نشده بارگذاری می‌شود. تا در صفحه‌ی «تغییرات و تاریخچه» اعمال نکنید، چیزی روی روتر عوض نمی‌شود.", "The file is loaded as unapplied changes. Nothing changes on the router until you apply it on the Changes & history page.")}</p>
        <input type="file" accept=".yaml,.yml,.mrbackup,.json,text/plain" className="block text-xs" onChange={(e) => pick(e.target.files?.[0])} />
        {encrypted && <Field label={t("رمز فایل", "File password")}><TextInput type="password" value={rpw} onChange={setRpw} /></Field>}
        {status?.has_candidate && !result && <p className="text-xs text-ring">{t("تغییرات اعمال‌نشده‌ی فعلی با این فایل جایگزین می‌شوند.", "The current unapplied changes will be replaced by this file.")}</p>}
        <button className="btn" disabled={busy || !file || (encrypted && !rpw)} onClick={restore}><Icon name="up" className="size-4" />{t("بارگذاری پشتیبان", "Load backup")}</button>
        {result && (
          <div className="space-y-3 rounded-lg border border-line p-3 text-sm">
            <p>{t("بارگذاری شد", "Loaded")}{result.hostname && <> — <Ltr>{result.hostname}</Ltr></>}</p>
            {!result.valid && (
              <div className="text-talk">
                <p>{t("این تنظیمات روی این دستگاه ایراد دارد و تا رفع آن اعمال نمی‌شود:", "These settings have problems on this device and cannot be applied until they are fixed:")}</p>
                <ul className="ltr mt-1 list-disc ps-5 text-left text-xs" dir="ltr">{(result.problems || []).slice(0, 8).map((p) => <li key={p}>{p}</li>)}</ul>
              </div>
            )}
            {result.unchanged && <p className="text-ink-2">{t("این پشتیبان با تنظیمات فعلی روتر یکی است؛ چیزی برای اعمال نیست.", "This backup is the same as the router's current settings; there is nothing to apply.")}</p>}
            {!result.unchanged && <button className="btn btn-primary btn-sm" onClick={() => nav("/changes")}><Icon name="play" className="size-4" />{t("بررسی و اعمال", "Review and apply")}</button>}
          </div>
        )}
        <p className="text-xs text-ink-3">{t("اگر نام کارت‌های شبکه‌ی این دستگاه با دستگاه قبلی فرق دارد، پیش از اعمال آن‌ها را اصلاح کنید.", "If this device's network port names differ from the old device, fix them before applying.")}</p>
      </div>
    </div>
  );
}
