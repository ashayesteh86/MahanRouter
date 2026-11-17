import { useEffect, useState } from "react";
import { api, ApiError, fmtTime, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Revision } from "../types";
import { Check, Empty, Field, Icon, Ltr, Modal, PageHead, Problems, Spinner, Tabs, TextInput, useToast } from "../ui";

export default function Changes() {
  const [tab, setTab] = useState("pending");
  return (
    <div className="space-y-4">
      <PageHead title={t("تغییرات و تاریخچه", "Changes & history")} sub={t("هر اعمال یک نسخه در Git می‌سازد که می‌شود به آن برگشت.", "Every apply creates a Git revision you can roll back to.")} />
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "pending", label: t("تغییرات اعمال‌نشده", "Pending changes"), icon: "play" },
        { id: "history", label: t("تاریخچه", "History"), icon: "history" },
        { id: "yaml", label: t("ویرایش YAML", "Edit YAML"), icon: "file" },
      ]} />
      {tab === "pending" && <Pending />}
      {tab === "history" && <History />}
      {tab === "yaml" && <YamlEditor />}
    </div>
  );
}

function DiffView({ text }: { text: string }) {
  if (!text.trim()) return <Empty icon="check" title={t("تفاوتی با کانفیگ فعلی نیست", "No difference from the running configuration")} />;
  return (
    <pre className="ltr mono overflow-x-auto p-4 text-left text-xs leading-5">
      {text.split("\n").filter((l) => !/^(diff --git|index [0-9a-f])/.test(l)).map((l) => l.replace(/^--- .*/, "--- running").replace(/^\+\+\+ .*/, "+++ candidate")).map((l, i) => (
        <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "diff-add" : l.startsWith("-") && !l.startsWith("---") ? "diff-del" : l.startsWith("@@") ? "diff-hunk" : ""}>{l || " "}</div>
      ))}
    </pre>
  );
}

function Pending() {
  const { status, problems, refreshStatus, reload } = useConfig();
  const toast = useToast();
  const [diff, setDiff] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [safe, setSafe] = useState(true);
  const [seconds, setSeconds] = useState(120);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | null>(null);
  const load = () => api<string>("/api/v1/config/diff").then(setDiff).catch(() => setDiff(""));
  useEffect(() => { load(); }, [status?.has_candidate, status?.revision]);
  const commit = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api("/api/v1/commit", { method: "POST", body: { message: message || t("تغییر از پنل وب", "change from the web panel"), confirm_seconds: safe ? seconds : 0 } });
      toast(safe ? t("اعمال شد. حالا در نوار بالا تأیید کنید.", "Applied. Now confirm in the bar at the top.") : t("اعمال شد", "Applied"));
      setMessage("");
      await Promise.all([refreshStatus(), reload()]);
      load();
    } catch (e) {
      setErr(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const discard = async () => {
    if (!window.confirm(t("همه‌ی تغییرات اعمال‌نشده دور ریخته شود؟", "Discard all pending changes?"))) return;
    await api("/api/v1/config/candidate", { method: "DELETE" });
    await Promise.all([refreshStatus(), reload()]);
    load();
    toast(t("تغییرات دور ریخته شد", "Changes discarded"));
  };
  const has = !!status?.has_candidate;
  return (
    <div className="grid gap-5 xl:grid-cols-3">
      <div className="card overflow-hidden xl:col-span-2">
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5"><h2 className="card-title">{t("تفاوت با کانفیگ فعلی", "Difference from the running configuration")}</h2>
          <button className="icon-btn" onClick={load}><Icon name="refresh" className="size-4" /></button></div>
        {diff === null ? <div className="p-8 text-center text-ink-3"><Spinner /></div> : <DiffView text={has ? diff : ""} />}
      </div>
      <div className="card space-y-4 p-5">
        <h2 className="card-title">{t("اعمال روی روتر", "Apply to the router")}</h2>
        <Problems problems={problems} />
        {err && <div className="space-y-2"><div className="rounded-md bg-talk-soft p-3 text-sm text-talk whitespace-pre-line">{err.message}</div><Problems problems={err.problems} /></div>}
        <Field label={t("توضیح تغییر", "Change note")}><TextInput ltr={false} value={message} placeholder={t("مثلاً: باز کردن پورت دوربین", "e.g. open the camera port")} onChange={setMessage} /></Field>
        <Check label={t("حالت امن (تأیید بعد از اعمال)", "Safe mode (confirm after applying)")} checked={safe} onChange={setSafe}
          hint={t("اگر بعد از اعمال دسترسی‌تان قطع شد و تأیید نکردید، روتر خودکار برمی‌گردد.", "If you lose access and do not confirm, the router rolls back by itself.")} />
        {safe && <Field label={t("مهلت تأیید (ثانیه)", "Confirm within (seconds)")}><TextInput type="number" value={seconds} onChange={(v) => setSeconds(Math.min(3600, Math.max(30, Number(v) || 120)))} /></Field>}
        <div className="flex flex-wrap gap-2">
          <button className="btn btn-primary" disabled={!has || busy || problems.length > 0 || !!status?.pending} onClick={commit}>{busy ? <Spinner className="size-4" /> : <Icon name="play" className="size-4" />}{t("اعمال", "Apply")}</button>
          <button className="btn btn-danger" disabled={!has || busy} onClick={discard}><Icon name="undo" className="size-4" />{t("دور ریختن", "Discard")}</button>
        </div>
        {status?.pending && <p className="text-xs text-ring">{t("یک اعمال منتظر تأیید است؛ اول آن را تأیید کنید.", "An apply is waiting for confirmation; confirm it first.")}</p>}
      </div>
    </div>
  );
}

function History() {
  const [revs, reload] = usePoll<Revision[]>("/api/v1/history?limit=50", 0);
  const { refreshStatus, reload: reloadCfg, status } = useConfig();
  const toast = useToast();
  const [show, setShow] = useState<Revision | null>(null);
  const [text, setText] = useState("");
  const rollback = async (r: Revision) => {
    if (!window.confirm(t(`کانفیگ به نسخه‌ی ${r.short} برگردد؟ این کار فوراً اعمال می‌شود.`, `Roll back to ${r.short}? This is applied immediately.`))) return;
    try {
      await api("/api/v1/rollback", { method: "POST", body: { revision: r.hash } });
      toast(t("برگشت انجام شد", "Rolled back"));
      reload(); refreshStatus(); reloadCfg();
    } catch (e) { toast((e as Error).message, "error"); }
  };
  const open = async (r: Revision) => { setShow(r); setText(""); setText(await api<string>(`/api/v1/history/${r.hash}`)); };
  if (!revs) return <div className="p-8 text-center text-ink-3"><Spinner /></div>;
  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-surface-2 text-xs text-ink-3"><tr>
          <th className="px-4 py-2 text-start font-medium">{t("نسخه", "Revision")}</th><th className="px-4 py-2 text-start font-medium">{t("زمان", "Time")}</th>
          <th className="px-4 py-2 text-start font-medium">{t("کاربر", "User")}</th><th className="px-4 py-2 text-start font-medium">{t("توضیح", "Note")}</th><th className="px-4 py-2" />
        </tr></thead>
        <tbody className="divide-y divide-line">
          {revs.map((r, i) => (
            <tr key={r.hash}>
              <td className="px-4 py-2"><Ltr className="mono text-xs">{r.short}</Ltr>{r.hash === status?.revision && <span className="chip ms-2 bg-idle-soft text-idle">{t("فعلی", "current")}</span>}</td>
              <td className="px-4 py-2 text-xs">{fmtTime(r.time)}</td>
              <td className="px-4 py-2 text-xs"><Ltr>{r.author}</Ltr></td>
              <td className="px-4 py-2 text-xs">{r.message}</td>
              <td className="whitespace-nowrap px-4 py-2 text-end">
                <button className="btn btn-sm" onClick={() => open(r)}>{t("نمایش", "View")}</button>
                {i > 0 && <button className="btn btn-sm ms-1" onClick={() => rollback(r)}><Icon name="undo" className="size-4" />{t("برگشت به این", "Roll back")}</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {show && <Modal open wide onClose={() => setShow(null)} title={`${t("نسخه", "Revision")} ${show.short}`}><pre className="ltr mono overflow-x-auto text-left text-xs">{text || "…"}</pre></Modal>}
    </div>
  );
}

function YamlEditor() {
  const { refreshStatus, reload } = useConfig();
  const toast = useToast();
  const [text, setText] = useState<string | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  useEffect(() => { api<string>("/api/v1/config/candidate").then(setText); }, []);
  const save = async () => {
    try {
      const r = await api<{ valid: boolean; problems?: string[] }>("/api/v1/config/candidate", { method: "PUT", raw: text || "" });
      setProblems(r.problems || []);
      toast(r.valid ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("ذخیره شد ولی ایراد دارد", "Saved, but it has problems"), r.valid ? "ok" : "error");
      refreshStatus(); reload();
    } catch (e) { toast((e as Error).message, "error"); }
  };
  if (text === null) return <div className="p-8 text-center text-ink-3"><Spinner /></div>;
  return (
    <div className="space-y-3">
      <p className="text-sm text-ink-3">{t("کل کانفیگ کاندید. برای تنظیماتی که هنوز فرم ندارند (OSPF، BGP و …). مرجع: examples/branch-office.yaml", "The whole candidate configuration, for settings that have no form yet (OSPF, BGP, …). See examples/branch-office.yaml")}</p>
      <Problems problems={problems} />
      <textarea className="input mono ltr min-h-[60vh] text-left text-xs leading-5" dir="ltr" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} />
      <button className="btn btn-primary" onClick={save}><Icon name="check" className="size-4" />{t("ذخیره در کاندید", "Save to candidate")}</button>
    </div>
  );
}
