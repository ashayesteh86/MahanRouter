import { useState } from "react";
import { clone, fmtTime, t } from "../lib";
import { useConfig, useNames, usePoll } from "../store";
import type { DHCPServer } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, ListInput, Ltr, Modal, PageHead, Select, TextInput } from "../ui";

interface Lease { address: string; mac: string; hostname: string; expires: number }

export default function Dhcp() {
  const { cfg, edit } = useConfig();
  const [leases, reloadLeases] = usePoll<Lease[]>("/api/v1/dhcp/leases", 10000);
  const [editing, setEditing] = useState<{ s: DHCPServer; index: number } | null>(null);
  const [staticFor, setStaticFor] = useState<number | null>(null);
  if (!cfg) return null;
  const servers = cfg.dhcp_servers || [];
  const statics = new Set(servers.flatMap((s) => (s.static_leases || []).map((l) => l.mac.toLowerCase())));
  const makeStatic = (l: Lease) => {
    const idx = servers.findIndex((s) => s.pools.some((p) => sameNet(p.split("-")[0], l.address)));
    if (idx < 0) return;
    edit((c) => { const s = c.dhcp_servers![idx]; s.static_leases = [...(s.static_leases || []), { mac: l.mac, address: l.address, hostname: l.hostname || undefined }]; }, t("رزرو شد (هنوز اعمال نشده)", "Reserved (not applied yet)"));
  };
  return (
    <div className="space-y-5">
      <PageHead title={t("DHCP سرور", "DHCP server")} sub={t("سرویس Kea؛ هر سرور روی یک اینترفیس", "Kea; one server per interface")}>
        <button className="btn btn-primary btn-sm" onClick={() => setEditing({ s: { interface: "", pools: [], lease_time: "12h" }, index: -1 })}><Icon name="plus" className="size-4" />{t("سرور جدید", "New server")}</button>
      </PageHead>
      <div className="grid gap-4 lg:grid-cols-2">
        {servers.map((s, i) => (
          <div key={i} className={`card p-5 ${s.disabled ? "opacity-60" : ""}`}>
            <div className="mb-3 flex items-center gap-2">
              <Icon name="dhcp" className="size-5 text-accent" />
              <span className="flex-1 font-semibold"><Ltr>{s.interface}</Ltr></span>
              {s.disabled && <Chip>{t("غیرفعال", "disabled")}</Chip>}
              <button className="icon-btn" onClick={() => setEditing({ s: clone(s), index: i })}><Icon name="edit" className="size-4" /></button>
              <ConfirmButton className="icon-btn text-talk" question={t("این DHCP سرور حذف شود؟", "Delete this DHCP server?")} onConfirm={() => edit((c) => { c.dhcp_servers!.splice(i, 1); })}><Icon name="trash" className="size-4" /></ConfirmButton>
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              <dt className="text-ink-3">{t("محدوده", "Pools")}</dt><dd><Ltr className="mono text-xs">{s.pools.join(", ")}</Ltr></dd>
              <dt className="text-ink-3">{t("گیت‌وی", "Gateway")}</dt><dd><Ltr className="mono text-xs">{s.gateway || t("خودکار", "auto")}</Ltr></dd>
              <dt className="text-ink-3">DNS</dt><dd><Ltr className="mono text-xs">{(s.dns_servers || []).join(", ") || t("خودکار", "auto")}</Ltr></dd>
              <dt className="text-ink-3">{t("مدت اجاره", "Lease time")}</dt><dd><Ltr className="text-xs">{s.lease_time || "12h"}</Ltr></dd>
            </dl>
            <div className="mt-3 flex items-center justify-between border-t border-line pt-3 text-sm">
              <span>{t(`${s.static_leases?.length || 0} آدرس رزروشده`, `${s.static_leases?.length || 0} reserved addresses`)}</span>
              <button className="btn btn-sm" onClick={() => setStaticFor(i)}>{t("آدرس‌های رزرو", "Reservations")}</button>
            </div>
          </div>
        ))}
        {!servers.length && <div className="card"><Empty title={t("DHCP سروری تعریف نشده", "No DHCP server")} /></div>}
      </div>

      <div className="card overflow-x-auto">
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
          <h2 className="card-title">{t("کلاینت‌های فعلی", "Current leases")}</h2>
          <button className="icon-btn" onClick={reloadLeases} title={t("تازه‌سازی", "Refresh")}><Icon name="refresh" className="size-4" /></button>
        </div>
        {!leases?.length ? <Empty title={t("هنوز کلاینتی آدرس نگرفته", "No client has a lease yet")} /> : (
          <table className="w-full text-sm">
            <thead className="bg-surface-2 text-xs text-ink-3"><tr>
              <th className="px-4 py-2 text-start font-medium">{t("آدرس", "Address")}</th><th className="px-4 py-2 text-start font-medium">MAC</th>
              <th className="px-4 py-2 text-start font-medium">{t("نام دستگاه", "Host name")}</th><th className="px-4 py-2 text-start font-medium">{t("انقضا", "Expires")}</th><th className="px-4 py-2" />
            </tr></thead>
            <tbody className="divide-y divide-line">
              {leases.map((l) => (
                <tr key={l.address}>
                  <td className="px-4 py-2"><Ltr className="mono text-xs">{l.address}</Ltr></td>
                  <td className="px-4 py-2"><Ltr className="mono text-xs">{l.mac}</Ltr></td>
                  <td className="px-4 py-2 text-xs">{l.hostname || "—"}</td>
                  <td className="px-4 py-2 text-xs">{fmtTime(l.expires)}</td>
                  <td className="px-4 py-2 text-end">{statics.has(l.mac.toLowerCase()) ? <Chip tone="idle">{t("رزرو", "reserved")}</Chip> : <button className="btn btn-sm" onClick={() => makeStatic(l)}>{t("رزرو این آدرس", "Reserve")}</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {editing && <ServerEditor init={editing.s} isNew={editing.index < 0} onClose={() => setEditing(null)}
        onSave={(s) => edit((c) => { c.dhcp_servers = c.dhcp_servers || []; if (editing.index < 0) c.dhcp_servers.push(s); else c.dhcp_servers[editing.index] = s; }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"))} />}
      {staticFor !== null && <StaticLeases index={staticFor} onClose={() => setStaticFor(null)} />}
    </div>
  );
}

function sameNet(a: string, b: string) { return a.split(".").slice(0, 3).join(".") === b.split(".").slice(0, 3).join("."); }

function ServerEditor({ init, isNew, onClose, onSave }: { init: DHCPServer; isNew: boolean; onClose: () => void; onSave: (s: DHCPServer) => Promise<boolean> }) {
  const [s, setS] = useState(init);
  const { ifaces } = useNames();
  const set = (p: Partial<DHCPServer>) => setS((x) => ({ ...x, ...p }));
  const save = async () => { if (await onSave(JSON.parse(JSON.stringify(s, (_, v) => (v === "" || v === false ? undefined : v))))) onClose(); };
  return (
    <Modal open onClose={onClose} title={isNew ? t("DHCP سرور جدید", "New DHCP server") : t("ویرایش DHCP سرور", "Edit DHCP server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" onClick={save} disabled={!s.interface || !s.pools.length}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-4">
        <Field label={t("اینترفیس", "Interface")} hint={t("اینترفیس باید آدرس ثابت در همان شبکه داشته باشد", "The interface needs a static address in the same network")}><Select ltr value={s.interface} onChange={(v) => set({ interface: v })} options={["", ...ifaces]} /></Field>
        <Field label={t("محدوده‌ها", "Pools")} hint="192.168.88.10-192.168.88.254"><ListInput value={s.pools} onChange={(v) => set({ pools: v })} rows={2} /></Field>
        <Field label={t("گیت‌وی", "Gateway")} hint={t("خالی = آدرس خود اینترفیس", "Empty = the interface address")}><TextInput value={s.gateway} onChange={(v) => set({ gateway: v })} /></Field>
        <Field label={t("سرورهای DNS", "DNS servers")} hint={t("خالی = خود روتر", "Empty = the router itself")}><ListInput value={s.dns_servers} onChange={(v) => set({ dns_servers: v.length ? v : undefined })} rows={2} /></Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label={t("دامنه", "Domain")}><TextInput value={s.domain} onChange={(v) => set({ domain: v })} /></Field>
          <Field label={t("مدت اجاره", "Lease time")} hint="30m, 12h, 1d"><TextInput value={s.lease_time} onChange={(v) => set({ lease_time: v })} /></Field>
        </div>
        <Check label={t("غیرفعال", "Disabled")} checked={!!s.disabled} onChange={(v) => set({ disabled: v })} />
      </div>
    </Modal>
  );
}

function StaticLeases({ index, onClose }: { index: number; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const [rows, setRows] = useState(clone(cfg?.dhcp_servers?.[index]?.static_leases || []));
  const save = async () => { if (await edit((c) => { c.dhcp_servers![index].static_leases = rows.filter((r) => r.mac && r.address).map((r) => ({ ...r, hostname: r.hostname || undefined })); }, t("ذخیره شد", "Saved"))) onClose(); };
  const set = (i: number, p: Partial<(typeof rows)[0]>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
  return (
    <Modal open wide onClose={onClose} title={t("آدرس‌های رزروشده", "Reserved addresses")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" onClick={save}>{t("ذخیره", "Save")}</button></>}>
      <div className="space-y-2">
        {rows.map((r, i) => (
          <div key={i} className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2">
            <TextInput value={r.mac} placeholder="aa:bb:cc:dd:ee:ff" onChange={(v) => set(i, { mac: v })} />
            <TextInput value={r.address} placeholder="192.168.88.50" onChange={(v) => set(i, { address: v })} />
            <TextInput value={r.hostname} placeholder={t("نام (اختیاری)", "name (optional)")} onChange={(v) => set(i, { hostname: v })} />
            <button className="icon-btn text-talk" onClick={() => setRows(rows.filter((_, j) => j !== i))}><Icon name="trash" className="size-4" /></button>
          </div>
        ))}
        <button className="btn btn-sm" onClick={() => setRows([...rows, { mac: "", address: "" }])}><Icon name="plus" className="size-4" />{t("ردیف جدید", "Add row")}</button>
      </div>
    </Modal>
  );
}
