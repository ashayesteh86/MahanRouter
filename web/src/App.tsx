import { useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, isFa, lang, setLang, t } from "./lib";
import { ConfigProvider, useConfig } from "./store";
import { Icon, Spinner, useToast } from "./ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Interfaces from "./pages/Interfaces";
import Firewall from "./pages/Firewall";
import Dhcp from "./pages/Dhcp";
import Dns from "./pages/Dns";
import RoutesPage from "./pages/Routes";
import Changes from "./pages/Changes";
import Tools from "./pages/Tools";
import Settings from "./pages/Settings";

export interface Me { user: string; must_change: boolean; version: string }

const NAV = [
  { to: "/", icon: "chart", label: t("داشبورد", "Dashboard"), el: <Dashboard /> },
  { to: "/interfaces", icon: "ports", label: t("اینترفیس‌ها", "Interfaces"), el: <Interfaces /> },
  { to: "/firewall", icon: "shield", label: t("فایروال و NAT", "Firewall & NAT"), el: <Firewall />, path: "/firewall/:tab?" },
  { to: "/dhcp", icon: "dhcp", label: t("DHCP سرور", "DHCP server"), el: <Dhcp /> },
  { to: "/dns", icon: "globe", label: "DNS", el: <Dns /> },
  { to: "/routes", icon: "route", label: t("مسیریابی", "Routing"), el: <RoutesPage /> },
  { to: "/tools", icon: "tool", label: t("ابزارها", "Tools"), el: <Tools /> },
  { to: "/changes", icon: "history", label: t("تغییرات و تاریخچه", "Changes & history"), el: <Changes /> },
  { to: "/settings", icon: "settings", label: t("تنظیمات", "Settings"), el: <Settings />, path: "/settings/:tab?" },
];

function useTheme(): [string, (t: string) => void] {
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem("theme") || "system"; } catch { return "system"; } });
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => { document.documentElement.dataset.theme = theme === "system" ? (mq.matches ? "dark" : "light") : theme; };
    apply();
    mq.addEventListener("change", apply);
    try { localStorage.setItem("theme", theme); } catch { /* ignore */ }
    return () => mq.removeEventListener("change", apply);
  }, [theme]);
  return [theme, setTheme];
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const load = () => api<Me>("/panel/api/me").then(setMe).catch(() => setMe(null));
  useEffect(() => {
    load();
    const h = () => setMe(null);
    window.addEventListener("auth:logout", h);
    return () => window.removeEventListener("auth:logout", h);
  }, []);
  if (me === undefined) return <div className="flex h-screen items-center justify-center text-ink-3"><Spinner /></div>;
  if (!me) return <Login onLogin={load} />;
  return (
    <ConfigProvider>
      <Shell me={me} logout={async () => { await api("/panel/api/logout", { method: "POST" }).catch(() => {}); setMe(null); }}>
        <Routes>
          {NAV.map((n) => <Route key={n.to} path={n.path || n.to} element={n.el} />)}
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </Shell>
    </ConfigProvider>
  );
}

function Shell({ me, logout, children }: { me: Me; logout: () => void; children: ReactNode }) {
  const [menu, setMenu] = useState(false);
  const [theme, setTheme] = useTheme();
  const loc = useLocation();
  useEffect(() => setMenu(false), [loc.pathname]);
  const nextTheme = ({ system: "dark", dark: "light", light: "system" } as Record<string, string>)[theme];
  return (
    <div className="flex min-h-screen">
      <aside className={`fixed inset-y-0 start-0 z-40 flex w-64 flex-col bg-[var(--nav-bg)] text-[var(--nav-ink)] transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0 ${menu ? "translate-x-0" : isFa ? "translate-x-full" : "-translate-x-full"}`}>
        <div className="flex h-[68px] shrink-0 items-center gap-2.5 border-b border-[var(--nav-line)] px-5">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-accent text-accent-ink shadow-lg shadow-black/20"><Icon name="router" /></div>
          <div className="min-w-0">
            <div className="ltr truncate text-[15px] font-bold leading-5 text-white">Mahan Router</div>
            <div className="ltr truncate text-[11px] text-[var(--nav-label)]">{me.version}</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-3">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}
              className={({ isActive }) => `group flex items-center gap-3 rounded-md px-3 py-2.5 text-[13.5px] transition ${isActive ? "bg-[var(--nav-active)] font-semibold text-white" : "text-[var(--nav-ink)] hover:bg-[var(--nav-hover)] hover:text-white"}`}>
              <Icon name={n.icon} className="size-[18px] shrink-0" /><span className="truncate">{n.label}</span>
            </NavLink>
          ))}
        </nav>
        <HostBox />
      </aside>
      {menu && <div className="fixed inset-0 z-30 bg-black/40 lg:hidden" onClick={() => setMenu(false)} aria-hidden="true" />}
      <main className="flex min-h-screen min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-[68px] items-center gap-2 border-b border-line bg-surface px-4 lg:px-6">
          <button className="icon-btn lg:hidden" onClick={() => setMenu(true)} aria-label={t("منو", "Menu")}><Icon name="menu" /></button>
          <div className="flex-1" />
          <button className="icon-btn icon-btn-outline px-2 text-[12px] font-semibold" onClick={() => setLang(lang === "fa" ? "en" : "fa")} title={isFa ? "English" : "فارسی"}>{isFa ? "EN" : "فا"}</button>
          <button className="icon-btn icon-btn-outline" onClick={() => setTheme(nextTheme)} title={t("تغییر پوسته", "Theme")} aria-label={t("تغییر پوسته", "Theme")}>
            <Icon name={theme === "dark" ? "moon" : theme === "light" ? "sun" : "pulse"} className="size-[18px]" />
          </button>
          <UserMenu me={me} logout={logout} />
        </header>
        <PendingBanner />
        <div className="flex-1 p-4 pb-24 lg:p-6 lg:pb-24">
          {me.must_change && <MustChange />}
          {children}
        </div>
        <footer className="border-t border-line bg-surface px-4 py-3 text-center text-xs text-ink-3">© {new Date().getFullYear()} <span className="ltr">Mahanet Computer Trading</span></footer>
      </main>
      <ChangesBar />
    </div>
  );
}

function HostBox() {
  const { status } = useConfig();
  return (
    <div className="m-3 rounded-lg border border-[var(--nav-line)] bg-[var(--nav-hover)] p-3 text-xs">
      <div className="flex items-center gap-2 text-white"><span className={`size-2 rounded-full ${status ? "bg-idle" : "bg-talk"}`} />{status ? t("به روتر وصل است", "Connected to the router") : t("اتصال قطع است", "Disconnected")}</div>
      {status && <div className="ltr mt-1 truncate text-[var(--nav-label)]">rev {status.revision.slice(0, 8)}</div>}
    </div>
  );
}

function UserMenu({ me, logout }: { me: Me; logout: () => void }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const nav = useNavigate();
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);
  return (
    <div className="relative" ref={box}>
      <button onClick={() => setOpen(!open)} aria-expanded={open} title={me.user}
        className="flex size-9 items-center justify-center rounded-md bg-accent text-sm font-bold text-accent-ink">{me.user.charAt(0).toUpperCase()}</button>
      {open && (
        <div className="card absolute end-0 top-full z-50 mt-2 w-56 overflow-hidden p-1 shadow-xl">
          <div className="border-b border-line px-3 py-2.5 text-sm font-semibold ltr">{me.user}</div>
          <button onClick={() => { setOpen(false); nav("/settings/users"); }} className="mt-1 flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-start text-sm hover:bg-surface-2"><Icon name="lock" className="size-4 text-ink-3" />{t("تغییر رمز", "Change password")}</button>
          <button onClick={logout} className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-start text-sm text-talk hover:bg-surface-2"><Icon name="logout" className="size-4" />{t("خروج", "Sign out")}</button>
        </div>
      )}
    </div>
  );
}

function MustChange() {
  const nav = useNavigate();
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-ring/30 bg-ring-soft p-3 text-sm text-ring">
      <Icon name="lock" className="size-5" />
      <span className="flex-1">{t("رمز پیش‌فرض پنل هنوز عوض نشده است. هر کسی در شبکه‌ی LAN می‌تواند وارد شود.", "The panel still uses the default password. Anyone on the LAN can sign in.")}</span>
      <button className="btn btn-sm" onClick={() => nav("/settings/users")}>{t("تغییر رمز", "Change password")}</button>
    </div>
  );
}

/** After a commit with confirm: countdown and the Confirm button (RouterOS safe mode). */
function PendingBanner() {
  const { status, refreshStatus, reload } = useConfig();
  const toast = useToast();
  const [left, setLeft] = useState(0);
  const p = status?.pending;
  useEffect(() => {
    if (!p) return;
    const end = new Date(p.deadline).getTime();
    const tick = () => setLeft(Math.max(0, Math.round((end - Date.now()) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [p?.deadline]);
  if (!p) return null;
  const confirm = async () => {
    try {
      await api("/api/v1/confirm", { method: "POST" });
      toast(t("تغییرات دائمی شد", "Changes confirmed"));
      refreshStatus();
      reload();
    } catch (e) { toast((e as Error).message, "error"); }
  };
  return (
    <div className="sticky top-[68px] z-10 flex flex-wrap items-center gap-3 border-b border-ring/30 bg-ring-soft px-4 py-2.5 text-sm text-ring lg:px-6">
      <Icon name="clock" className="size-5" />
      <span className="flex-1 font-medium">
        {t(`تغییرات اعمال شد. اگر تا ${left} ثانیه تأیید نکنید، روتر خودکار به کانفیگ قبلی برمی‌گردد.`, `Changes applied. If you do not confirm within ${left} s, the router rolls back automatically.`)}
      </span>
      <button className="btn btn-primary btn-sm" onClick={confirm}><Icon name="check" className="size-4" />{t("تأیید و نگه داشتن", "Confirm and keep")}</button>
    </div>
  );
}

/** Bottom bar while the candidate differs from the running config. */
function ChangesBar() {
  const { status, problems } = useConfig();
  const loc = useLocation();
  const nav = useNavigate();
  if (!status?.has_candidate || loc.pathname === "/changes") return null;
  return (
    <div className="fixed inset-x-0 bottom-0 z-30 flex justify-center p-3 lg:ps-64">
      <div className="card flex w-full max-w-2xl flex-wrap items-center gap-3 px-4 py-3 shadow-xl">
        <span className={`size-2.5 rounded-full ${problems.length ? "bg-talk" : "bg-ring"}`} />
        <span className="flex-1 text-sm">
          {problems.length
            ? t(`تغییرات ذخیره شده ولی ${problems.length} ایراد دارد و هنوز اعمال نشده است.`, `Changes are saved but have ${problems.length} problem(s) and are not applied yet.`)
            : t("تغییرات ذخیره شده ولی هنوز روی روتر اعمال نشده است.", "Changes are saved but not applied to the router yet.")}
        </span>
        <button className="btn btn-primary btn-sm" onClick={() => nav("/changes")}><Icon name="play" className="size-4" />{t("بررسی و اعمال", "Review and apply")}</button>
      </div>
    </div>
  );
}
