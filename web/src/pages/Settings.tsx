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
      ]} />
      {tab === "users" ? <Users /> : <SystemTab />}
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
