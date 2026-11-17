import { useState } from "react";
import { clone, t } from "../lib";
import { useConfig, useNames, usePoll } from "../store";
import type { StaticRoute } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, Ltr, Modal, PageHead, Select, TextInput } from "../ui";

interface KRoute { dst: string; gateway?: string; dev?: string; protocol?: string; metric?: number; table?: string; type?: string; prefsrc?: string }

export default function RoutesPage() {
  const { cfg, edit } = useConfig();
  const [live] = usePoll<{ ipv4: KRoute[] }>("/api/v1/routes", 10000);
  const [editing, setEditing] = useState<{ r: StaticRoute; index: number } | null>(null);
  if (!cfg) return null;
  const routes = cfg.routes || [];
  const kernel = (live?.ipv4 || []).filter((r) => !r.table || r.table === "main");
  return (
    <div className="space-y-5">
      <PageHead title={t("مسیریابی", "Routing")} sub={t("مسیرهای ثابت. OSPF و BGP فعلاً از بخش ویرایش YAML در «تغییرات» تنظیم می‌شوند.", "Static routes. OSPF and BGP are set in the YAML editor on the Changes page for now.")}>
        <button className="btn btn-primary btn-sm" onClick={() => setEditing({ r: { dst: "" }, index: -1 })}><Icon name="plus" className="size-4" />{t("مسیر جدید", "New route")}</button>
      </PageHead>
      <div className="card overflow-x-auto">
        <div className="border-b border-line px-5 py-3.5"><h2 className="card-title">{t("مسیرهای ثابت", "Static routes")}</h2></div>
        {!routes.length ? <Empty title={t("مسیر ثابتی تعریف نشده", "No static routes")} /> : (
          <table className="w-full text-sm">
            <thead className="bg-surface-2 text-xs text-ink-3"><tr>
              <th className="px-4 py-2 text-start font-medium">{t("مقصد", "Destination")}</th><th className="px-4 py-2 text-start font-medium">{t("گیت‌وی / اینترفیس", "Gateway / interface")}</th>
              <th className="px-4 py-2 text-start font-medium">{t("فاصله", "Distance")}</th><th className="px-4 py-2 text-start font-medium">{t("توضیح", "Comment")}</th><th className="px-4 py-2" />
            </tr></thead>
            <tbody className="divide-y divide-line">
              {routes.map((r, i) => (
                <tr key={i} className={r.disabled ? "opacity-50" : ""}>
                  <td className="px-4 py-2"><Ltr className="mono text-xs">{r.dst}</Ltr></td>
                  <td className="px-4 py-2">{r.blackhole ? <Chip tone="talk">blackhole</Chip> : <Ltr className="mono text-xs">{[r.gateway, r.interface].filter(Boolean).join(" via ")}</Ltr>}</td>
                  <td className="px-4 py-2 text-xs"><Ltr>{r.distance || 1}</Ltr></td>
                  <td className="px-4 py-2 text-xs text-ink-2">{r.comment}</td>
                  <td className="whitespace-nowrap px-4 py-2 text-end">
                    <button className="icon-btn" onClick={() => setEditing({ r: clone(r), index: i })}><Icon name="edit" className="size-4" /></button>
                    <ConfirmButton className="icon-btn text-talk" question={t("این مسیر حذف شود؟", "Delete this route?")} onConfirm={() => edit((c) => { c.routes!.splice(i, 1); })}><Icon name="trash" className="size-4" /></ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="card overflow-x-auto">
        <div className="border-b border-line px-5 py-3.5"><h2 className="card-title">{t("جدول مسیریابی فعلی (IPv4)", "Current routing table (IPv4)")}</h2></div>
        <table className="w-full text-sm">
          <thead className="bg-surface-2 text-xs text-ink-3"><tr>
            <th className="px-4 py-2 text-start font-medium">{t("مقصد", "Destination")}</th><th className="px-4 py-2 text-start font-medium">{t("گیت‌وی", "Gateway")}</th>
            <th className="px-4 py-2 text-start font-medium">{t("اینترفیس", "Interface")}</th><th className="px-4 py-2 text-start font-medium">{t("منبع", "Source")}</th><th className="px-4 py-2 text-start font-medium">metric</th>
          </tr></thead>
          <tbody className="divide-y divide-line">
            {kernel.map((r, i) => (
              <tr key={i}>
                <td className="px-4 py-2"><Ltr className="mono text-xs">{r.type && r.type !== "unicast" ? `${r.type} ` : ""}{r.dst}</Ltr></td>
                <td className="px-4 py-2"><Ltr className="mono text-xs">{r.gateway || "—"}</Ltr></td>
                <td className="px-4 py-2"><Ltr className="text-xs">{r.dev || "—"}</Ltr></td>
                <td className="px-4 py-2 text-xs"><Ltr>{r.protocol}</Ltr></td>
                <td className="px-4 py-2 text-xs"><Ltr>{r.metric ?? ""}</Ltr></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {editing && <RouteEditor init={editing.r} isNew={editing.index < 0} onClose={() => setEditing(null)}
        onSave={(r) => edit((c) => { c.routes = c.routes || []; if (editing.index < 0) c.routes.push(r); else c.routes[editing.index] = r; }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"))} />}
    </div>
  );
}

function RouteEditor({ init, isNew, onClose, onSave }: { init: StaticRoute; isNew: boolean; onClose: () => void; onSave: (r: StaticRoute) => Promise<boolean> }) {
  const [r, setR] = useState(init);
  const { ifaces } = useNames();
  const set = (p: Partial<StaticRoute>) => setR((x) => ({ ...x, ...p }));
  const save = async () => { if (await onSave(JSON.parse(JSON.stringify(r, (_, v) => (v === "" || v === false ? undefined : v))))) onClose(); };
  return (
    <Modal open onClose={onClose} title={isNew ? t("مسیر جدید", "New route") : t("ویرایش مسیر", "Edit route")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" onClick={save} disabled={!r.dst}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-4">
        <Field label={t("مقصد", "Destination")} hint={t("مثل 10.0.0.0/8 یا 0.0.0.0/0", "e.g. 10.0.0.0/8 or 0.0.0.0/0")}><TextInput value={r.dst} onChange={(v) => set({ dst: v })} /></Field>
        <Check label={t("Blackhole (بسته‌ها دور ریخته شوند)", "Blackhole (drop the traffic)")} checked={!!r.blackhole} onChange={(v) => set({ blackhole: v, ...(v ? { gateway: undefined, interface: undefined } : {}) })} />
        {!r.blackhole && <div className="grid grid-cols-2 gap-4">
          <Field label={t("گیت‌وی", "Gateway")}><TextInput value={r.gateway} onChange={(v) => set({ gateway: v })} /></Field>
          <Field label={t("اینترفیس", "Interface")}><Select ltr value={r.interface} onChange={(v) => set({ interface: v })} options={["", ...ifaces]} /></Field>
        </div>}
        <div className="grid grid-cols-2 gap-4">
          <Field label={t("فاصله (distance)", "Distance")}><TextInput type="number" value={r.distance} placeholder="1" onChange={(v) => set({ distance: v ? Number(v) : undefined })} /></Field>
          <Field label={t("توضیح", "Comment")}><TextInput ltr={false} value={r.comment} onChange={(v) => set({ comment: v })} /></Field>
        </div>
        <Check label={t("غیرفعال", "Disabled")} checked={!!r.disabled} onChange={(v) => set({ disabled: v })} />
      </div>
    </Modal>
  );
}
