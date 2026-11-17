import { useState } from "react";
import { api, t } from "../lib";
import { Field, Icon, PageHead, Select, Spinner, TextInput } from "../ui";

export default function Tools() {
  const [tool, setTool] = useState("ping");
  const [host, setHost] = useState("8.8.8.8");
  const [out, setOut] = useState<{ output: string; ok: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setOut(null);
    try { setOut(await api("/api/v1/tools", { method: "POST", body: { tool, host, count: 4 } })); }
    catch (x) { setOut({ output: (x as Error).message, ok: false }); }
    finally { setBusy(false); }
  };
  return (
    <div className="space-y-4">
      <PageHead title={t("ابزارها", "Tools")} sub={t("از خود روتر اجرا می‌شود", "Runs on the router itself")} />
      <form onSubmit={run} className="card flex flex-wrap items-end gap-3 p-5">
        <Field label={t("ابزار", "Tool")} className="w-40"><Select value={tool} onChange={setTool} options={[{ value: "ping", label: "Ping" }, { value: "traceroute", label: "Traceroute (mtr)" }, { value: "dns", label: t("پرس‌وجوی DNS", "DNS lookup") }]} /></Field>
        <Field label={t("مقصد", "Target")} className="min-w-60 flex-1"><TextInput value={host} onChange={setHost} placeholder="8.8.8.8 / example.com" /></Field>
        <button className="btn btn-primary" disabled={busy || !host}>{busy ? <Spinner className="size-4" /> : <Icon name="play" className="size-4" />}{t("اجرا", "Run")}</button>
      </form>
      {out && <pre className={`card ltr mono overflow-x-auto p-4 text-left text-xs leading-5 ${out.ok ? "" : "text-talk"}`}>{out.output || t("خروجی ندارد", "No output")}</pre>}
    </div>
  );
}
