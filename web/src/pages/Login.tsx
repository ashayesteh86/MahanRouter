import { useState } from "react";
import { api, ApiError, isFa, setLang, t } from "../lib";
import { Icon, Spinner } from "../ui";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUser] = useState("admin");
  const [password, setPass] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api("/panel/api/login", { method: "POST", body: { username, password } });
      onLogin();
    } catch (x) {
      const er = x as ApiError;
      setErr(er.status === 429
        ? t(`تلاش‌های ناموفق زیاد بود. ${er.body?.retry_after || ""} ثانیه صبر کنید.`, `Too many failed attempts. Wait ${er.body?.retry_after || ""} s.`)
        : er.status === 401 ? t("نام کاربری یا رمز اشتباه است.", "Wrong user name or password.") : er.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login-bg flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-sm p-7 shadow-xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-ink"><Icon name="router" className="size-6" /></div>
          <div>
            <div className="ltr text-lg font-bold">Mahan Router</div>
            <div className="text-xs text-ink-3">{t("ورود به پنل مدیریت", "Sign in to the management panel")}</div>
          </div>
        </div>
        <label className="block"><span className="label">{t("نام کاربری", "User name")}</span>
          <input className="input ltr text-left" dir="ltr" autoComplete="username" value={username} onChange={(e) => setUser(e.target.value)} autoFocus /></label>
        <label className="mt-3 block"><span className="label">{t("رمز عبور", "Password")}</span>
          <input className="input ltr text-left" dir="ltr" type="password" autoComplete="current-password" value={password} onChange={(e) => setPass(e.target.value)} /></label>
        {err && <div className="mt-3 rounded-md bg-talk-soft px-3 py-2 text-sm text-talk">{err}</div>}
        <button className="btn btn-primary mt-5 w-full" disabled={busy || !password}>{busy ? <Spinner className="size-4" /> : <Icon name="lock" className="size-4" />}{t("ورود", "Sign in")}</button>
        <div className="mt-4 flex items-center justify-between text-xs text-ink-3">
          <span>{t("پیش‌فرض: admin / mahan", "Default: admin / mahan")}</span>
          <button type="button" className="text-accent" onClick={() => setLang(isFa ? "en" : "fa")}>{isFa ? "English" : "فارسی"}</button>
        </div>
      </form>
    </div>
  );
}
