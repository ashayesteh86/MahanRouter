// API client, language and small helpers shared by every page.

export const lang: "fa" | "en" = (() => {
  try { return localStorage.getItem("lang") === "en" ? "en" : "fa"; } catch { return "fa"; }
})();
export const isFa = lang === "fa";

/** t("فارسی", "English") picks the text of the current language. */
export const t = (fa: string, en: string) => (isFa ? fa : en);

export function setLang(l: "fa" | "en") {
  try { localStorage.setItem("lang", l); } catch { /* ignore */ }
  location.reload();
}

export class ApiError extends Error {
  status: number;
  problems?: string[];
  body: any;
  constructor(status: number, message: string, body: any) {
    super(message);
    this.status = status;
    this.body = body;
    this.problems = body?.problems;
  }
}

/** fetch wrapper: JSON in/out, session cookie, CSRF header, 401 → sign-in page. */
export async function api<T = any>(path: string, opts: { method?: string; body?: any; raw?: string; text?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "mahan-panel" };
  let body: BodyInit | undefined;
  if (opts.raw !== undefined) { body = opts.raw; headers["Content-Type"] = "application/yaml"; }
  else if (opts.body !== undefined) { body = JSON.stringify(opts.body); headers["Content-Type"] = "application/json"; }
  const res = await fetch(path, { method: opts.method || (body ? "POST" : "GET"), headers, body, credentials: "same-origin" });
  if (res.status === 401 && !path.startsWith("/panel/api/login")) window.dispatchEvent(new Event("auth:logout"));
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("json") ? await res.json().catch(() => ({})) : await res.text();
  if (!res.ok) {
    const msg = typeof data === "object" && data?.error ? data.error : typeof data === "string" && data ? data : `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, data);
  }
  return data as T;
}

export function fmtBytes(n?: number): string {
  if (n == null || isNaN(n)) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

export function fmtRate(bps?: number): string {
  if (bps == null || isNaN(bps)) return "—";
  const u = ["bps", "Kbps", "Mbps", "Gbps"];
  let i = 0;
  while (bps >= 1000 && i < u.length - 1) { bps /= 1000; i++; }
  return `${bps.toFixed(bps >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

export function fmtDuration(sec?: number): string {
  if (sec == null) return "—";
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return t(`${d} روز و ${h} ساعت`, `${d}d ${h}h`);
  if (h) return t(`${h} ساعت و ${m} دقیقه`, `${h}h ${m}m`);
  return t(`${m} دقیقه`, `${m}m`);
}

export function fmtTime(ts: string | number): string {
  const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString(isFa ? "fa-IR" : "en-GB", { dateStyle: "short", timeStyle: "short" });
}

export const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

/** Splits a comma / space / newline separated text into a clean list. */
export const splitList = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
