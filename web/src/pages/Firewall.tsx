import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { clone, fmtBytes, t } from "../lib";
import { useConfig, useNames, usePoll } from "../store";
import type { Rule } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, ListInput, Ltr, Modal, PageHead, Select, Tabs, TextInput } from "../ui";

const FILTER_ACTIONS = ["accept", "drop", "reject", "return", "add-src-to-address-list", "add-dst-to-address-list"];
const NAT_ACTIONS = ["masquerade", "src-nat", "dst-nat", "redirect", "accept", "return"];
const STATES = ["established", "related", "new", "invalid", "untracked"];
const ACTION_TONE: Record<string, string> = { accept: "idle", drop: "talk", reject: "talk", masquerade: "sky", "src-nat": "sky", "dst-nat": "purple", redirect: "purple" };

type Kind = "filter" | "nat";

export default function Firewall() {
  const { tab = "filter" } = useParams();
  const nav = useNavigate();
  return (
    <div className="space-y-4">
      <PageHead title={t("فایروال و NAT", "Firewall & NAT")} sub={t("مثل /ip firewall در میکروتیک: قانون‌ها به ترتیب از بالا بررسی می‌شوند.", "Like /ip firewall in RouterOS: rules are checked from the top down.")} />
      <Tabs value={tab} onChange={(id) => nav(`/firewall/${id}`)} tabs={[
        { id: "filter", label: t("فیلتر", "Filter"), icon: "shield" },
        { id: "nat", label: "NAT", icon: "route" },
        { id: "lists", label: t("لیست آدرس‌ها", "Address lists"), icon: "list" },
      ]} />
      {tab === "lists" ? <AddressLists /> : <RuleTable kind={tab === "nat" ? "nat" : "filter"} />}
    </div>
  );
}

function summary(r: Rule) {
  const parts: string[] = [];
  const io = (p: string, x?: string, l?: string) => x ? `${p}=${x}` : l ? `${p}-list=${l}` : "";
  parts.push(io("in", r.in_interface, r.in_interface_list), io("out", r.out_interface, r.out_interface_list));
  if (r.src_address) parts.push(`src=${r.src_address}`);
  if (r.src_address_list) parts.push(`src-list=${r.src_address_list}`);
  if (r.dst_address) parts.push(`dst=${r.dst_address}`);
  if (r.dst_address_list) parts.push(`dst-list=${r.dst_address_list}`);
  if (r.protocol) parts.push(r.protocol + (r.dst_port ? `:${r.dst_port}` : "") + (r.src_port ? ` sport ${r.src_port}` : ""));
  if (r.connection_state) parts.push(`state=${r.connection_state}`);
  if (r.connection_nat_state) parts.push(`nat-state=${r.connection_nat_state}`);
  if (r.to_address || r.to_port) parts.push(`→ ${r.to_address || ""}${r.to_port ? `:${r.to_port}` : ""}`);
  if (r.address_list) parts.push(`→ list ${r.address_list}${r.address_list_timeout ? ` (${r.address_list_timeout})` : ""}`);
  return parts.filter(Boolean).join("  ");
}

function RuleTable({ kind }: { kind: Kind }) {
  const { cfg, edit, status } = useConfig();
  const [counters] = usePoll<Record<string, { packets: number; bytes: number }>>("/api/v1/firewall/counters", 5000);
  const [editing, setEditing] = useState<{ rule: Rule; index: number } | null>(null);
  const [chain, setChain] = useState("all");
  if (!cfg) return null;
  const rules = cfg.firewall?.[kind] || [];
  const chains = kind === "filter" ? ["input", "forward", "output"] : ["srcnat", "dstnat"];
  const tag = kind === "filter" ? "f" : "n";
  const showCounters = !status?.has_candidate;
  const mutate = (fn: (list: Rule[]) => void, msg?: string) => edit((c) => {
    c.firewall = c.firewall || {};
    const list = (c.firewall[kind] = c.firewall[kind] || []);
    fn(list);
  }, msg);
  const move = (i: number, d: number) => mutate((l) => { const j = i + d; if (j < 0 || j >= l.length) return; [l[i], l[j]] = [l[j], l[i]]; });
  const blank: Rule = kind === "filter" ? { chain: "forward", action: "accept" } : { chain: "srcnat", action: "masquerade" };
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="seg">
          {["all", ...chains].map((c) => <button key={c} aria-pressed={chain === c} onClick={() => setChain(c)}>{c === "all" ? t("همه", "all") : c}</button>)}
        </div>
        <div className="flex-1" />
        {kind === "filter" && <PolicyBox />}
        <button className="btn btn-primary btn-sm" onClick={() => setEditing({ rule: clone(blank), index: -1 })}><Icon name="plus" className="size-4" />{t("قانون جدید", "New rule")}</button>
      </div>
      <div className="card overflow-x-auto">
        {rules.length === 0 ? <Empty title={t("قانونی نیست", "No rules")} /> : (
          <table className="w-full text-sm">
            <thead className="bg-surface-2 text-xs text-ink-3">
              <tr>
                <th className="w-10 px-3 py-2 text-start font-medium">#</th>
                <th className="px-3 py-2 text-start font-medium">chain</th>
                <th className="px-3 py-2 text-start font-medium">action</th>
                <th className="px-3 py-2 text-start font-medium">{t("شرط‌ها", "Match")}</th>
                <th className="px-3 py-2 text-start font-medium">{t("توضیح", "Comment")}</th>
                {showCounters && <th className="px-3 py-2 text-end font-medium">{t("بسته / حجم", "Packets / bytes")}</th>}
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rules.map((r, i) => (chain !== "all" && r.chain !== chain) ? null : (
                <tr key={i} className={r.disabled ? "opacity-50" : ""}>
                  <td className="px-3 py-2 text-xs text-ink-3"><Ltr>{i}</Ltr></td>
                  <td className="px-3 py-2"><Ltr className="text-xs">{r.chain}</Ltr></td>
                  <td className="px-3 py-2"><Chip tone={ACTION_TONE[r.action] || "accent"}><Ltr>{r.action}</Ltr></Chip>{r.log && <span className="ms-1 text-xs text-ring">log</span>}</td>
                  <td className="max-w-md px-3 py-2"><Ltr className="mono text-xs break-all">{summary(r) || t("همه‌ی بسته‌ها", "all packets")}</Ltr></td>
                  <td className="px-3 py-2 text-xs text-ink-2">{r.comment}</td>
                  {showCounters && <td className="whitespace-nowrap px-3 py-2 text-end text-xs"><Ltr className="mono">{counters?.[`${tag}${i}`] ? `${counters[`${tag}${i}`].packets} / ${fmtBytes(counters[`${tag}${i}`].bytes)}` : "—"}</Ltr></td>}
                  <td className="whitespace-nowrap px-2 py-2 text-end">
                    <button className="icon-btn" title={t("بالا", "Up")} onClick={() => move(i, -1)} disabled={i === 0}><Icon name="up" className="size-4" /></button>
                    <button className="icon-btn" title={t("پایین", "Down")} onClick={() => move(i, 1)} disabled={i === rules.length - 1}><Icon name="down" className="size-4" /></button>
                    <button className="icon-btn" title={t("ویرایش", "Edit")} onClick={() => setEditing({ rule: clone(r), index: i })}><Icon name="edit" className="size-4" /></button>
                    <button className="icon-btn" title={r.disabled ? t("فعال کردن", "Enable") : t("غیرفعال کردن", "Disable")} onClick={() => mutate((l) => { l[i].disabled = !l[i].disabled || undefined; })}><Icon name={r.disabled ? "play" : "x"} className="size-4" /></button>
                    <ConfirmButton className="icon-btn text-talk" question={t(`قانون ${i} حذف شود؟`, `Delete rule ${i}?`)} onConfirm={() => mutate((l) => { l.splice(i, 1); }, t("حذف شد", "Deleted"))}><Icon name="trash" className="size-4" /></ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {!showCounters && <p className="text-xs text-ink-3">{t("شمارنده‌ها بعد از اعمال تغییرات دوباره نمایش داده می‌شوند.", "Counters are shown again after the changes are applied.")}</p>}
      {editing && <RuleEditor kind={kind} init={editing.rule} isNew={editing.index < 0} onClose={() => setEditing(null)}
        onSave={(r) => mutate((l) => { if (editing.index < 0) l.push(r); else l[editing.index] = r; }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"))} />}
    </div>
  );
}

function PolicyBox() {
  const { cfg, edit } = useConfig();
  const p = cfg?.firewall?.policy || {};
  const set = (chain: "input" | "forward" | "output", v: string) => edit((c) => { c.firewall = c.firewall || {}; c.firewall.policy = { ...(c.firewall.policy || {}), [chain]: v || undefined }; });
  return (
    <div className="flex items-center gap-2 text-xs text-ink-3">
      {t("سیاست پیش‌فرض:", "Default policy:")}
      {(["input", "forward", "output"] as const).map((ch) => (
        <label key={ch} className="flex items-center gap-1"><Ltr>{ch}</Ltr>
          <select className="input !w-auto !py-1 text-xs" value={p[ch] || "accept"} onChange={(e) => set(ch, e.target.value === "accept" ? "" : e.target.value)}>
            <option value="accept">accept</option><option value="drop">drop</option>
          </select>
        </label>
      ))}
    </div>
  );
}

function RuleEditor({ kind, init, isNew, onClose, onSave }: { kind: Kind; init: Rule; isNew: boolean; onClose: () => void; onSave: (r: Rule) => Promise<boolean> }) {
  const [r, setR] = useState<Rule>(init);
  const { ifaces, lists, addrLists } = useNames();
  const set = (p: Partial<Rule>) => setR((x) => ({ ...x, ...p }));
  const chains = kind === "filter" ? ["input", "forward", "output"] : ["srcnat", "dstnat"];
  const actions = kind === "filter" ? FILTER_ACTIONS : NAT_ACTIONS;
  const states = (r.connection_state || "").split(",").filter(Boolean);
  const ports = ["tcp", "udp"].includes(r.protocol || "");
  const save = async () => {
    const clean: Rule = JSON.parse(JSON.stringify(r, (_, v) => (v === "" || v === false ? undefined : v)));
    if (await onSave(clean)) onClose();
  };
  const ifSel = (v: string | undefined, on: (x: string) => void) => <Select ltr value={v} onChange={on} options={["", ...ifaces]} />;
  const listSel = (v: string | undefined, on: (x: string) => void) => <Select ltr value={v} onChange={on} options={["", ...lists]} />;
  return (
    <Modal open wide onClose={onClose} title={isNew ? t("قانون جدید", "New rule") : t("ویرایش قانون", "Edit rule")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" onClick={save}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="Chain"><Select ltr value={r.chain} onChange={(v) => set({ chain: v })} options={chains} /></Field>
        <Field label="Action"><Select ltr value={r.action} onChange={(v) => set({ action: v })} options={actions} /></Field>
        <Field label={t("توضیح", "Comment")}><TextInput ltr={false} value={r.comment} onChange={(v) => set({ comment: v })} /></Field>

        <Field label="In interface">{ifSel(r.in_interface, (v) => set({ in_interface: v, in_interface_list: v ? undefined : r.in_interface_list }))}</Field>
        <Field label="In interface list">{listSel(r.in_interface_list, (v) => set({ in_interface_list: v, in_interface: v ? undefined : r.in_interface }))}</Field>
        <div className="hidden sm:block" />
        <Field label="Out interface">{ifSel(r.out_interface, (v) => set({ out_interface: v, out_interface_list: v ? undefined : r.out_interface_list }))}</Field>
        <Field label="Out interface list">{listSel(r.out_interface_list, (v) => set({ out_interface_list: v, out_interface: v ? undefined : r.out_interface }))}</Field>
        <div className="hidden sm:block" />

        <Field label="Src address" hint={t("IP یا CIDR؛ با ! برعکس", "IP or CIDR; ! negates")}><TextInput value={r.src_address} onChange={(v) => set({ src_address: v })} /></Field>
        <Field label="Src address list"><Select ltr value={r.src_address_list} onChange={(v) => set({ src_address_list: v })} options={["", ...addrLists]} /></Field>
        <Field label="Protocol"><Select ltr value={r.protocol} onChange={(v) => set({ protocol: v, ...(["tcp", "udp"].includes(v) ? {} : { src_port: undefined, dst_port: undefined }) })} options={["", "tcp", "udp", "icmp", "icmpv6", "gre", "esp"]} /></Field>
        <Field label="Dst address"><TextInput value={r.dst_address} onChange={(v) => set({ dst_address: v })} /></Field>
        <Field label="Dst address list"><Select ltr value={r.dst_address_list} onChange={(v) => set({ dst_address_list: v })} options={["", ...addrLists]} /></Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label="Src port"><TextInput value={r.src_port} disabled={!ports} onChange={(v) => set({ src_port: v })} /></Field>
          <Field label="Dst port" hint="80,443 / 1000-2000"><TextInput value={r.dst_port} disabled={!ports} onChange={(v) => set({ dst_port: v })} /></Field>
        </div>

        <Field label="Connection state" className="sm:col-span-2">
          <div className="flex flex-wrap gap-2">
            {STATES.map((s) => (
              <label key={s} className="flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-1 text-sm">
                <input type="checkbox" className="accent-[var(--accent)]" checked={states.includes(s)} onChange={(e) => set({ connection_state: (e.target.checked ? [...states, s] : states.filter((x) => x !== s)).join(",") || undefined })} /><Ltr>{s}</Ltr>
              </label>
            ))}
          </div>
        </Field>
        <Field label="Connection NAT state"><Select ltr value={r.connection_nat_state} onChange={(v) => set({ connection_nat_state: v })} options={["", "dstnat", "!dstnat", "srcnat", "!srcnat"]} /></Field>

        {["src-nat", "dst-nat"].includes(r.action) && <Field label="To address"><TextInput value={r.to_address} onChange={(v) => set({ to_address: v })} /></Field>}
        {["src-nat", "dst-nat", "redirect", "masquerade"].includes(r.action) && <Field label="To port"><TextInput value={r.to_port} onChange={(v) => set({ to_port: v })} /></Field>}
        {r.action.startsWith("add-") && <>
          <Field label="Address list" hint={t("لیست پویا: آدرس‌ها خودکار اضافه می‌شوند", "Dynamic list: addresses are added automatically")}><TextInput value={r.address_list} onChange={(v) => set({ address_list: v })} /></Field>
          <Field label="Timeout" hint="1h, 30m, 1d"><TextInput value={r.address_list_timeout} onChange={(v) => set({ address_list_timeout: v })} /></Field>
        </>}
        <div className="flex flex-wrap gap-6 sm:col-span-3">
          <Check label={t("ثبت در لاگ", "Log")} checked={!!r.log} onChange={(v) => set({ log: v })} />
          <Check label={t("غیرفعال", "Disabled")} checked={!!r.disabled} onChange={(v) => set({ disabled: v })} />
        </div>
      </div>
    </Modal>
  );
}

function AddressLists() {
  const { cfg, edit } = useConfig();
  const [name, setName] = useState("");
  const lists = cfg?.firewall?.address_lists || {};
  const setList = (k: string, v: string[] | null) => edit((c) => {
    c.firewall = c.firewall || {};
    const m = { ...(c.firewall.address_lists || {}) };
    if (v === null) delete m[k]; else m[k] = v;
    c.firewall.address_lists = Object.keys(m).length ? m : undefined;
  }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
  return (
    <div className="space-y-3">
      <p className="text-sm text-ink-3">{t("لیست‌های ثابت آدرس (IPv4 و IPv6). لیست‌های پویا با قانون‌های add-src-to-address-list پر می‌شوند و این‌جا تعریف نمی‌شوند.", "Static address lists (IPv4 and IPv6). Dynamic lists are filled by add-src-to-address-list rules and are not defined here.")}</p>
      <div className="grid gap-4 md:grid-cols-2">
        {Object.entries(lists).map(([k, v]) => (
          <div key={k} className="card p-4">
            <div className="mb-2 flex items-center justify-between"><span className="font-semibold"><Ltr>{k}</Ltr></span>
              <ConfirmButton className="icon-btn text-talk" question={t(`لیست ${k} حذف شود؟`, `Delete list ${k}?`)} onConfirm={() => setList(k, null)}><Icon name="trash" className="size-4" /></ConfirmButton></div>
            <ListInput value={v} rows={4} onChange={(nv) => setList(k, nv)} placeholder="10.0.0.0/8" />
            <p className="mt-1 text-xs text-ink-3">{t("با خارج شدن از کادر ذخیره می‌شود", "Saved when you leave the box")}</p>
          </div>
        ))}
      </div>
      <div className="flex max-w-md gap-2">
        <TextInput value={name} placeholder={t("نام لیست جدید", "New list name")} onChange={setName} />
        <button className="btn" disabled={!name || !!lists[name]} onClick={() => { setList(name, []); setName(""); }}><Icon name="plus" className="size-4" />{t("افزودن", "Add")}</button>
      </div>
    </div>
  );
}
