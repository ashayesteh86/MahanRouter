import { useState } from "react";
import { clone, fmtRate, t } from "../lib";
import { useConfig } from "../store";
import type { Config, Iface, WGPeer } from "../types";
import { Check, Chip, ConfirmButton, Field, Icon, ListInput, Ltr, Modal, PageHead, Select, TextInput } from "../ui";
import { useLinks } from "./Dashboard";

const TYPE_LABEL: Record<string, string> = {
  ethernet: t("پورت اترنت", "Ethernet"), vlan: "VLAN", bridge: t("بریج", "Bridge"), bond: t("باند (تجمیع)", "Bond"),
  pppoe: t("PPPoE کلاینت", "PPPoE client"), wireguard: "WireGuard", loopback: t("لوپ‌بک", "Loopback"),
  // Made on the VPN page; listed here with their type.
  rozaneh: t("روزنه (کلاینت)", "Rozaneh client"), rozaneh_server: t("روزنه (سرور)", "Rozaneh server"), v2ray: t("V2Ray کلاینت", "V2Ray client"),
  sstp: t("SSTP کلاینت", "SSTP client"), l2tp: t("L2TP کلاینت", "L2TP client"), pptp: t("PPTP کلاینت", "PPTP client"),
  openvpn: t("OpenVPN کلاینت", "OpenVPN client"), ssh: t("تونل SSH", "SSH tunnel"), l2tpv3: "L2TPv3",
  gre: "GRE", ipip: "IPIP", eoip: "EoIP", "6to4": "6to4", eoipv6: "EoIPv6", gre6: "GREv6",
};
const BOND_MODES = ["802.3ad", "active-backup", "balance-rr", "balance-xor", "broadcast", "balance-tlb", "balance-alb"];

export default function Interfaces() {
  const { cfg, edit } = useConfig();
  const { links, addrs, rates } = useLinks();
  const [editing, setEditing] = useState<{ iface: Iface; isNew: boolean } | null>(null);
  const [lists, setLists] = useState(false);
  if (!cfg) return null;
  const live = Object.fromEntries(links.map((l) => [l.ifname, l]));
  const memberOf = (name: string) => Object.entries(cfg.interface_lists || {}).filter(([, v]) => v.includes(name)).map(([k]) => k);
  const slaveOf = (name: string) => cfg.interfaces.find((i) => (i.type === "bridge" || i.type === "bond") && i.members?.includes(name))?.name;

  const remove = (name: string) => edit((c) => {
    c.interfaces = c.interfaces.filter((i) => i.name !== name);
    for (const i of c.interfaces) if (i.members) i.members = i.members.filter((m) => m !== name);
    for (const k of Object.keys(c.interface_lists || {})) c.interface_lists![k] = c.interface_lists![k].filter((m) => m !== name);
  }, t(`${name} حذف شد`, `${name} removed`));

  const toggle = (name: string) => edit((c) => { const i = c.interfaces.find((x) => x.name === name)!; i.disabled = !i.disabled || undefined; });

  const add = (type: Iface["type"]) => {
    const base: Iface = { name: "", type, addressing: type === "pppoe" ? "none" : "static", addresses: [] };
    if (type === "vlan") Object.assign(base, { name: "vlan", parent: cfg.interfaces.find((i) => i.type === "ethernet")?.name || "", vlan_id: 10 });
    if (type === "bridge") Object.assign(base, { name: "bridge", members: [] });
    if (type === "bond") Object.assign(base, { name: "bond1", members: [], bond_mode: "802.3ad" });
    if (type === "pppoe") Object.assign(base, { name: "pppoe-out1", parent: cfg.interface_lists?.WAN?.[0] || "", pppoe: { username: "", password: "", add_default_route: true, use_peer_dns: true }, addressing: undefined });
    if (type === "wireguard") Object.assign(base, { name: "wg0", wireguard: { private_key: "", listen_port: 51820, peers: [] } });
    if (type === "loopback") Object.assign(base, { name: "lo1" });
    setEditing({ iface: base, isNew: true });
  };

  return (
    <div className="space-y-5">
      <PageHead title={t("اینترفیس‌ها", "Interfaces")} sub={t("پورت‌ها، VLAN، بریج، باند، PPPoE و تونل‌های VPN", "Ports, VLANs, bridges, bonds, PPPoE and VPN tunnels")}>
        <button className="btn btn-sm" onClick={() => setLists(true)}><Icon name="list" className="size-4" />{t("لیست‌های اینترفیس", "Interface lists")}</button>
        <AddMenu onAdd={add} />
      </PageHead>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-surface-2 text-xs text-ink-3">
            <tr>
              <th className="px-4 py-2 text-start font-medium">{t("نام", "Name")}</th>
              <th className="px-4 py-2 text-start font-medium">{t("نوع", "Type")}</th>
              <th className="px-4 py-2 text-start font-medium">{t("وضعیت", "State")}</th>
              <th className="px-4 py-2 text-start font-medium">{t("آدرس", "Address")}</th>
              <th className="px-4 py-2 text-start font-medium">{t("لیست‌ها", "Lists")}</th>
              <th className="px-4 py-2 text-end font-medium">{t("ترافیک", "Traffic")}</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {cfg.interfaces.map((i) => {
              const l = live[i.name];
              const up = l && (l.operstate === "UP" || (l.operstate === "UNKNOWN" && l.flags.includes("UP")));
              const slave = slaveOf(i.name);
              const cfgAddr = i.addressing === "dhcp" ? "DHCP" : (i.addresses || []).join(" ");
              return (
                <tr key={i.name} className={i.disabled ? "opacity-60" : ""}>
                  <td className="px-4 py-2.5">
                    <div className="font-medium"><Ltr>{i.name}</Ltr></div>
                    {i.comment && <div className="text-xs text-ink-3">{i.comment}</div>}
                  </td>
                  <td className="px-4 py-2.5 text-xs">{TYPE_LABEL[i.type] || <Ltr>{i.type}</Ltr>}{i.type === "vlan" && <> <Ltr>{i.vlan_id}@{i.parent}</Ltr></>}{i.mac && <div className="ltr mono text-ink-3">{i.mac}</div>}</td>
                  <td className="px-4 py-2.5">
                    {i.disabled ? <Chip tone="off">{t("غیرفعال", "disabled")}</Chip> : !l ? <Chip tone="ring">{t("هنوز ساخته نشده", "not present")}</Chip> : up ? <Chip tone="idle">{t("فعال", "up")}</Chip> : <Chip tone="talk">{t("قطع", "down")}</Chip>}
                    {slave && <div className="mt-1 text-xs text-ink-3">{t("عضو", "in")} <Ltr>{slave}</Ltr></div>}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    <div className="ltr mono">{(addrs[i.name] || []).join("  ") || (slave ? "" : "—")}</div>
                    {cfgAddr && <div className="text-ink-3">{t("تنظیم: ", "set: ")}<Ltr className="mono">{cfgAddr}</Ltr></div>}
                  </td>
                  <td className="px-4 py-2.5"><div className="flex flex-wrap gap-1">{memberOf(i.name).map((x) => <Chip key={x} tone={x === "WAN" ? "sky" : "accent"}>{x}</Chip>)}</div></td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-end text-xs"><Ltr className="mono">↓{fmtRate(rates[i.name]?.rx)} ↑{fmtRate(rates[i.name]?.tx)}</Ltr></td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-end">
                    <button className="icon-btn" title={t("ویرایش", "Edit")} onClick={() => setEditing({ iface: clone(i), isNew: false })}><Icon name="edit" className="size-4" /></button>
                    <button className="icon-btn" title={i.disabled ? t("فعال کردن", "Enable") : t("غیرفعال کردن", "Disable")} onClick={() => toggle(i.name)}><Icon name={i.disabled ? "play" : "x"} className="size-4" /></button>
                    <ConfirmButton className="icon-btn text-talk" question={t(`${i.name} حذف شود؟ قانون‌ها و سرویس‌هایی که از آن استفاده می‌کنند باید جدا اصلاح شوند.`, `Delete ${i.name}? Rules and services that use it must be fixed separately.`)} onConfirm={() => remove(i.name)}><Icon name="trash" className="size-4" /></ConfirmButton>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-ink-3">{t("پورت‌های اترنت با MAC شناسایی و به ether1، ether2 و … تغییر نام داده می‌شوند. تغییرات تا «اعمال» روی روتر اثر ندارد.", "Ethernet ports are matched by MAC and renamed to ether1, ether2, … Changes take effect only after you apply them.")}</p>
      {editing && <IfaceEditor init={editing.iface} isNew={editing.isNew} cfg={cfg} onClose={() => setEditing(null)} />}
      {lists && <ListsEditor onClose={() => setLists(false)} />}
    </div>
  );
}

function AddMenu({ onAdd }: { onAdd: (t: Iface["type"]) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button className="btn btn-primary btn-sm" onClick={() => setOpen(!open)}><Icon name="plus" className="size-4" />{t("افزودن", "Add")}</button>
      {open && (
        <div className="card absolute end-0 top-full z-30 mt-1 w-48 p-1 shadow-xl" onMouseLeave={() => setOpen(false)}>
          {(["vlan", "bridge", "bond", "pppoe", "wireguard", "loopback"] as const).map((x) => (
            <button key={x} className="block w-full rounded-md px-3 py-2 text-start text-sm hover:bg-surface-2" onClick={() => { setOpen(false); onAdd(x); }}>{TYPE_LABEL[x]}</button>
          ))}
        </div>
      )}
    </div>
  );
}

function IfaceEditor({ init, isNew, cfg, onClose }: { init: Iface; isNew: boolean; cfg: Config; onClose: () => void }) {
  const { edit } = useConfig();
  const [i, setI] = useState<Iface>(init);
  const set = (p: Partial<Iface>) => setI((x) => ({ ...x, ...p }));
  const others = cfg.interfaces.filter((x) => x.name !== init.name).map((x) => x.name);
  const ethernets = cfg.interfaces.filter((x) => x.type === "ethernet" || x.type === "vlan" || x.type === "bond").map((x) => x.name);
  const l3 = !["pppoe"].includes(i.type);
  const save = async () => {
    const clean: Iface = JSON.parse(JSON.stringify(i, (_, v) => (v === "" ? undefined : v)));
    if (clean.addressing !== "static") delete clean.addresses;
    if (clean.mtu !== undefined) clean.mtu = Number(clean.mtu) || undefined;
    if (clean.vlan_id !== undefined) clean.vlan_id = Number(clean.vlan_id);
    const ok = await edit((c) => {
      if (isNew) c.interfaces.push(clean);
      else {
        const idx = c.interfaces.findIndex((x) => x.name === init.name);
        c.interfaces[idx] = clean;
        if (clean.name !== init.name) {
          // follow a rename everywhere it is referenced in lists and members
          for (const x of c.interfaces) if (x.members) x.members = x.members.map((m) => (m === init.name ? clean.name : m));
          for (const k of Object.keys(c.interface_lists || {})) c.interface_lists![k] = c.interface_lists![k].map((m) => (m === init.name ? clean.name : m));
        }
      }
    }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={isNew ? t(`افزودن ${TYPE_LABEL[i.type]}`, `Add ${TYPE_LABEL[i.type]}`) : t(`ویرایش ${init.name}`, `Edit ${init.name}`)}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" onClick={save} disabled={!i.name}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("نام", "Name")} hint={t("حداکثر ۱۵ حرف، مثل vlan10 یا bridge-guest", "Max 15 characters, e.g. vlan10 or bridge-guest")}><TextInput value={i.name} onChange={(v) => set({ name: v.trim() })} /></Field>
        <Field label={t("توضیح", "Comment")}><TextInput ltr={false} value={i.comment} onChange={(v) => set({ comment: v })} /></Field>
        {i.type === "ethernet" && <Field label="MAC" hint={t("پورت فیزیکی با این MAC پیدا می‌شود", "The physical port is matched by this MAC")}><TextInput value={i.mac} onChange={(v) => set({ mac: v })} /></Field>}
        {i.type === "vlan" && <>
          <Field label={t("اینترفیس والد", "Parent interface")}><Select ltr value={i.parent} onChange={(v) => set({ parent: v })} options={["", ...ethernets]} /></Field>
          <Field label="VLAN ID"><TextInput type="number" value={i.vlan_id} onChange={(v) => set({ vlan_id: Number(v) })} /></Field>
        </>}
        {(i.type === "bridge" || i.type === "bond") && (
          <Field label={t("اعضا", "Members")} className="sm:col-span-2">
            <div className="flex flex-wrap gap-2 rounded-md border border-line p-2">
              {others.filter((n) => { const x = cfg.interfaces.find((y) => y.name === n)!; return ["ethernet", "vlan", "bond"].includes(x.type); }).map((n) => (
                <label key={n} className="flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-1 text-sm">
                  <input type="checkbox" className="accent-[var(--accent)]" checked={!!i.members?.includes(n)} onChange={(e) => set({ members: e.target.checked ? [...(i.members || []), n] : (i.members || []).filter((m) => m !== n) })} /><Ltr>{n}</Ltr>
                </label>
              ))}
            </div>
          </Field>
        )}
        {i.type === "bridge" && <Check label={t("STP فعال باشد", "Enable STP")} checked={!!i.stp} onChange={(v) => set({ stp: v || undefined })} />}
        {i.type === "bond" && <Field label={t("حالت باند", "Bond mode")}><Select ltr value={i.bond_mode} onChange={(v) => set({ bond_mode: v })} options={BOND_MODES} /></Field>}
        {i.type === "pppoe" && <>
          <Field label={t("روی اینترفیس", "Over interface")}><Select ltr value={i.parent} onChange={(v) => set({ parent: v })} options={["", ...ethernets]} /></Field>
          <Field label="Service name"><TextInput value={i.pppoe?.service_name} onChange={(v) => set({ pppoe: { ...i.pppoe!, service_name: v } })} /></Field>
          <Field label={t("نام کاربری", "User name")}><TextInput value={i.pppoe?.username} onChange={(v) => set({ pppoe: { ...i.pppoe!, username: v } })} /></Field>
          <Field label={t("رمز", "Password")}><TextInput type="password" value={i.pppoe?.password} onChange={(v) => set({ pppoe: { ...i.pppoe!, password: v } })} /></Field>
          <Check label={t("مسیر پیش‌فرض از این اتصال", "Default route via this link")} checked={!!i.pppoe?.add_default_route} onChange={(v) => set({ pppoe: { ...i.pppoe!, add_default_route: v } })} />
          <Check label={t("DNS از سرویس‌دهنده", "Use the provider's DNS")} checked={!!i.pppoe?.use_peer_dns} onChange={(v) => set({ pppoe: { ...i.pppoe!, use_peer_dns: v } })} />
        </>}
        {i.type === "wireguard" && <WGFields i={i} set={set} />}
        <Field label="MTU"><TextInput type="number" value={i.mtu} placeholder={t("پیش‌فرض", "default")} onChange={(v) => set({ mtu: v ? Number(v) : undefined })} /></Field>
        <Field label={t("محدودیت پهنای باند خروجی (CAKE)", "Egress shaping (CAKE)")} hint={t("مثل 95M یا 1G؛ خالی = بدون محدودیت", "e.g. 95M or 1G; empty = none")}>
          <TextInput value={i.shaping?.bandwidth} onChange={(v) => set({ shaping: v ? { bandwidth: v } : undefined })} />
        </Field>
        {l3 && <>
          <Field label={t("آدرس‌دهی", "Addressing")}>
            <Select value={i.addressing || "none"} onChange={(v) => set({ addressing: v as Iface["addressing"] })}
              options={[{ value: "static", label: t("ثابت", "Static") }, { value: "dhcp", label: t("کلاینت DHCP", "DHCP client") }, { value: "none", label: t("بدون آدرس", "None") }]} />
          </Field>
          {i.addressing === "static" && <Field label={t("آدرس‌ها (CIDR)", "Addresses (CIDR)")} hint={t("هر خط یک آدرس، مثل 192.168.88.1/24", "One per line, e.g. 192.168.88.1/24")}><ListInput value={i.addresses} onChange={(v) => set({ addresses: v })} rows={2} /></Field>}
          {i.addressing === "dhcp" && <>
            <Check label={t("DNS از DHCP گرفته شود", "Use DNS from DHCP")} checked={i.dhcp_use_dns !== false} onChange={(v) => set({ dhcp_use_dns: v ? undefined : false })} />
            <Field label={t("فاصله‌ی مسیر پیش‌فرض", "Default route distance")}><TextInput type="number" value={i.dhcp_route_distance} placeholder="1" onChange={(v) => set({ dhcp_route_distance: v ? Number(v) : undefined })} /></Field>
          </>}
        </>}
        <div className="sm:col-span-2"><Check label={t("غیرفعال", "Disabled")} checked={!!i.disabled} onChange={(v) => set({ disabled: v || undefined })} /></div>
      </div>
    </Modal>
  );
}

function WGFields({ i, set }: { i: Iface; set: (p: Partial<Iface>) => void }) {
  const wg = i.wireguard || { private_key: "", peers: [] };
  const setWG = (p: Partial<NonNullable<Iface["wireguard"]>>) => set({ wireguard: { ...wg, ...p } });
  const setPeer = (k: number, p: Partial<WGPeer>) => setWG({ peers: (wg.peers || []).map((x, j) => (j === k ? { ...x, ...p } : x)) });
  return (
    <>
      <Field label={t("کلید خصوصی", "Private key")} hint={t("با wg genkey بسازید", "Create one with wg genkey")}><TextInput type="password" value={wg.private_key} onChange={(v) => setWG({ private_key: v })} /></Field>
      <Field label={t("پورت", "Listen port")}><TextInput type="number" value={wg.listen_port} onChange={(v) => setWG({ listen_port: v ? Number(v) : undefined })} /></Field>
      <div className="space-y-3 sm:col-span-2">
        <div className="flex items-center justify-between"><span className="label mb-0">{t("همتاها", "Peers")}</span>
          <button className="btn btn-sm" onClick={() => setWG({ peers: [...(wg.peers || []), { public_key: "", allowed_ips: [] }] })}><Icon name="plus" className="size-4" />{t("همتا", "Peer")}</button></div>
        {(wg.peers || []).map((p, k) => (
          <div key={k} className="grid gap-3 rounded-lg border border-line p-3 sm:grid-cols-2">
            <Field label={t("کلید عمومی", "Public key")}><TextInput value={p.public_key} onChange={(v) => setPeer(k, { public_key: v })} /></Field>
            <Field label="Endpoint"><TextInput value={p.endpoint} placeholder="host:51820" onChange={(v) => setPeer(k, { endpoint: v })} /></Field>
            <Field label="Allowed IPs"><ListInput value={p.allowed_ips} onChange={(v) => setPeer(k, { allowed_ips: v })} rows={2} /></Field>
            <div className="space-y-2">
              <Field label="Keepalive"><TextInput type="number" value={p.persistent_keepalive} onChange={(v) => setPeer(k, { persistent_keepalive: v ? Number(v) : undefined })} /></Field>
              <Check label={t("مسیر برای Allowed IPs", "Route the allowed IPs")} checked={!!p.route_allowed_ips} onChange={(v) => setPeer(k, { route_allowed_ips: v })} />
              <button className="btn btn-sm btn-danger" onClick={() => setWG({ peers: (wg.peers || []).filter((_, j) => j !== k) })}><Icon name="trash" className="size-4" />{t("حذف همتا", "Remove peer")}</button>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

function ListsEditor({ onClose }: { onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const [lists, setLists] = useState<Record<string, string[]>>(clone(cfg?.interface_lists || {}));
  const [newName, setNewName] = useState("");
  const names = (cfg?.interfaces || []).map((i) => i.name);
  const save = async () => { if (await edit((c) => { c.interface_lists = lists; }, t("ذخیره شد", "Saved"))) onClose(); };
  return (
    <Modal open wide onClose={onClose} title={t("لیست‌های اینترفیس", "Interface lists")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" onClick={save}>{t("ذخیره", "Save")}</button></>}>
      <p className="mb-4 text-sm text-ink-3">{t("قانون‌های فایروال به جای نام تک‌تک پورت‌ها از این لیست‌ها استفاده می‌کنند (مثل WAN و LAN در میکروتیک).", "Firewall rules use these lists instead of single port names (like WAN and LAN in RouterOS).")}</p>
      <div className="space-y-3">
        {Object.entries(lists).map(([k, v]) => (
          <div key={k} className="rounded-lg border border-line p-3">
            <div className="mb-2 flex items-center justify-between"><span className="font-semibold"><Ltr>{k}</Ltr></span>
              <button className="icon-btn text-talk" onClick={() => { const n = { ...lists }; delete n[k]; setLists(n); }}><Icon name="trash" className="size-4" /></button></div>
            <div className="flex flex-wrap gap-2">
              {names.map((n) => (
                <label key={n} className="flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-1 text-sm">
                  <input type="checkbox" className="accent-[var(--accent)]" checked={v.includes(n)} onChange={(e) => setLists({ ...lists, [k]: e.target.checked ? [...v, n] : v.filter((x) => x !== n) })} /><Ltr>{n}</Ltr>
                </label>
              ))}
            </div>
          </div>
        ))}
        <div className="flex gap-2">
          <TextInput value={newName} placeholder={t("نام لیست جدید", "New list name")} onChange={setNewName} />
          <button className="btn" disabled={!newName || !!lists[newName]} onClick={() => { setLists({ ...lists, [newName]: [] }); setNewName(""); }}><Icon name="plus" className="size-4" />{t("افزودن", "Add")}</button>
        </div>
      </div>
    </Modal>
  );
}
