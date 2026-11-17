import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { isFa, t } from "./lib";

const PATHS: Record<string, string> = {
  grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
  chart: "M4 20V10M10 20V4M16 20v-7M22 20H2",
  router: "M3 14h18v6H3zM7 17h.01M11 17h.01M8 10a6 6 0 0 1 8 0M5 7a10 10 0 0 1 14 0",
  ports: "M4 6h16v12H4zM8 10v4M12 10v4M16 10v4",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  route: "M6 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM18 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM6 15V9a4 4 0 0 1 4-4h6M18 9v6a4 4 0 0 1-4 4H8",
  dhcp: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01M12 7h5M12 17h5",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18",
  history: "M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5M12 7v5l3 3",
  tool: "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  x: "M6 6l12 12M18 6L6 18",
  check: "M5 12l5 5L20 7",
  alert: "M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  plus: "M12 5v14M5 12h14",
  edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  up: "M12 19V5M5 12l7-7 7 7",
  down: "M12 5v14M19 12l-7 7-7-7",
  refresh: "M20 11a8 8 0 0 0-14.8-4M4 4v4h4M4 13a8 8 0 0 0 14.8 4M20 20v-4h-4",
  logout: "M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 17l-5-5 5-5M5 12h11",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  pulse: "M3 12h4l3-8 4 16 3-8h4",
  menu: "M4 6h16M4 12h16M4 18h16",
  chevronL: "M15 18l-6-6 6-6",
  chevronR: "M9 18l6-6-6-6",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
  users: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21a7 7 0 0 1 14 0M16 3.5a4 4 0 0 1 0 7.5M22 21a7 7 0 0 0-4-6.3",
  server: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  cpu: "M6 6h12v12H6zM9 9h6v6H9zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4",
  memory: "M3 7h18v10H3zM7 7v10M11 7v10M15 7v10M3 20h18",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  disk: "M4 5h16v14H4zM8 15h.01M4 12h16",
  inbox: "M3 13h5l2 3h4l2-3h5M5 5h14l2 8v6H3v-6z",
  lock: "M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  play: "M7 4l13 8-13 8z",
  file: "M6 3h8l4 4v14H6zM14 3v4h4",
  undo: "M9 14L4 9l5-5M4 9h11a5 5 0 0 1 0 10h-4",
  link: "M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1",
};
const MIRROR: Record<string, string> = { chevronL: "chevronR", chevronR: "chevronL" };

export function Icon({ name, className = "size-5" }: { name: string; className?: string }) {
  if (!isFa && MIRROR[name]) name = MIRROR[name];
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name] || PATHS.inbox} />
    </svg>
  );
}

export function Spinner({ className = "size-5" }: { className?: string }) {
  return (
    <svg className={`${className} animate-spin`} viewBox="0 0 24 24" fill="none" aria-label={t("در حال بارگذاری", "Loading")}>
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity=".25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function Modal({ open, onClose, title, children, wide, footer }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean; footer?: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [open, onClose]);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 pt-[5vh]" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`card w-full ${wide ? "max-w-3xl" : "max-w-lg"} shadow-2xl`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
          <h3 className="text-base font-semibold">{title}</h3>
          <button className="rounded-lg p-1 text-ink-3 hover:bg-surface-2" onClick={onClose} aria-label={t("بستن", "Close")}><Icon name="x" /></button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto p-5">{children}</div>
        {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

type Toast = { id: number; text: string; kind: "ok" | "error" };
const ToastCtx = createContext<(text: string, kind?: "ok" | "error") => void>(() => {});
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: "ok" | "error" = "ok") => {
    const id = Math.random();
    setItems((x) => [...x, { id, text, kind }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), kind === "error" ? 8000 : 4000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 end-4 z-[60] flex max-w-md flex-col gap-2" role="status" aria-live="polite">
        {items.map((x) => (
          <div key={x.id} className={`card pointer-events-auto flex items-start gap-2 px-4 py-2.5 text-sm shadow-lg ${x.kind === "error" ? "text-talk" : ""}`}>
            <Icon name={x.kind === "error" ? "alert" : "check"} className={`mt-0.5 size-4 shrink-0 ${x.kind === "error" ? "text-talk" : "text-idle"}`} />
            <span className="whitespace-pre-line">{x.text}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
export const useToast = () => useContext(ToastCtx);

export function Field({ label, children, hint, className = "" }: { label: string; children: ReactNode; hint?: ReactNode; className?: string }) {
  return (
    <label className={`block ${className}`}>
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-3">{hint}</span>}
    </label>
  );
}

export function Check({ label, checked, onChange, hint }: { label: string; checked: boolean; onChange: (v: boolean) => void; hint?: string }) {
  return (
    <label className="flex cursor-pointer items-start gap-2 text-sm">
      <input type="checkbox" className="mt-0.5 size-4 accent-[var(--accent)]" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>{label}{hint && <span className="block text-xs text-ink-3">{hint}</span>}</span>
    </label>
  );
}

export function Tabs({ tabs, value, onChange }: { tabs: { id: string; label: string; icon?: string }[]; value: string; onChange: (id: string) => void }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-line" role="tablist">
      {tabs.map((x) => (
        <button key={x.id} onClick={() => onChange(x.id)} role="tab" aria-selected={value === x.id}
          className={`-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm ${value === x.id ? "border-accent font-medium text-accent" : "border-transparent text-ink-2 hover:text-ink"}`}>
          {x.icon && <Icon name={x.icon} className="size-4" />}{x.label}
        </button>
      ))}
    </div>
  );
}

export function StatCard({ label, value, sub, icon, tone = "accent" }: { label: string; value: ReactNode; sub?: ReactNode; icon: string; tone?: string }) {
  return (
    <div className="card flex h-full items-center gap-3 p-4 sm:p-5">
      <div className="min-w-0 flex-1">
        <div className="truncate text-[13px] leading-5 text-ink-3">{label}</div>
        <div className="mt-1 truncate text-2xl font-bold leading-tight">{value}</div>
        {sub && <div className="mt-1 truncate text-xs text-ink-3">{sub}</div>}
      </div>
      <span className="stat-icon size-11" style={{ "--tone": `var(--color-${tone})` } as React.CSSProperties}><Icon name={icon} /></span>
    </div>
  );
}

export function Empty({ icon = "inbox", title, children }: { icon?: string; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center text-ink-3">
      <Icon name={icon} className="size-9 opacity-60" />
      <div className="font-medium text-ink-2">{title}</div>
      {children && <div className="max-w-md text-sm">{children}</div>}
    </div>
  );
}

export function PageHead({ title, children, sub }: { title: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3">
      <div className="min-w-0 flex-1">
        <h1 className="text-lg font-bold">{title}</h1>
        {sub && <p className="mt-0.5 text-sm text-ink-3">{sub}</p>}
      </div>
      {children}
    </div>
  );
}

/** Network values (addresses, MACs, names) are always shown left-to-right. */
export const Ltr = ({ children, className = "" }: { children: ReactNode; className?: string }) => <span className={`ltr ${className}`}>{children}</span>;

export function Chip({ tone = "off", children }: { tone?: string; children: ReactNode }) {
  return <span className={`chip bg-${tone}-soft text-${tone}`}>{children}</span>;
}

/** Editable list of strings as one text box (one item per line or comma separated). */
export function ListInput({ value, onChange, placeholder, rows = 3 }: { value?: string[]; onChange: (v: string[]) => void; placeholder?: string; rows?: number }) {
  const [text, setText] = useState((value || []).join("\n"));
  useEffect(() => { setText((value || []).join("\n")); }, [JSON.stringify(value || [])]);
  return (
    <textarea className="input mono ltr text-left" rows={rows} value={text} placeholder={placeholder} dir="ltr"
      onChange={(e) => setText(e.target.value)}
      onBlur={() => onChange(text.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean))} />
  );
}

export function TextInput({ value, onChange, placeholder, ltr = true, type = "text", disabled }: { value?: string | number; onChange: (v: string) => void; placeholder?: string; ltr?: boolean; type?: string; disabled?: boolean }) {
  return <input className={`input ${ltr ? "ltr text-left" : ""}`} dir={ltr ? "ltr" : undefined} type={type} value={value ?? ""} placeholder={placeholder} disabled={disabled} onChange={(e) => onChange(e.target.value)} />;
}

export function Select({ value, onChange, options, ltr }: { value?: string; onChange: (v: string) => void; options: (string | { value: string; label: string })[]; ltr?: boolean }) {
  return (
    <select className={`input ${ltr ? "ltr" : ""}`} value={value ?? ""} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => (typeof o === "string" ? <option key={o} value={o}>{o || "—"}</option> : <option key={o.value} value={o.value}>{o.label}</option>))}
    </select>
  );
}

export function ConfirmButton({ onConfirm, children, className = "btn btn-sm btn-danger", question }: { onConfirm: () => void; children: ReactNode; className?: string; question: string }) {
  return <button className={className} onClick={() => window.confirm(question) && onConfirm()}>{children}</button>;
}

export function Problems({ problems }: { problems?: string[] }) {
  if (!problems?.length) return null;
  return (
    <div className="rounded-lg border border-talk/30 bg-talk-soft p-3 text-sm text-talk">
      <div className="mb-1 flex items-center gap-1.5 font-semibold"><Icon name="alert" className="size-4" />{t("کانفیگ ایراد دارد", "The configuration has problems")}</div>
      <ul className="ltr list-disc space-y-0.5 ps-5 text-left mono text-xs">{problems.map((p, i) => <li key={i}>{p}</li>)}</ul>
    </div>
  );
}
