import { useEffect, useState } from "react";
import { api, fmtBytes, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Config, Iface, PolicyRoute, Rule } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, ListInput, Ltr, Modal, Select, TextInput } from "../ui";
import { ClientResult, Info, keygen, nextFree, parseCidr } from "./Vpn";

// Rozaneh tab: this router as a Rozaneh client (to a server abroad, with
// policy routing for the LAN) and as a Rozaneh server for phones/laptops.

interface PeerLive { name: string; public_key: string; ip: string; down_bytes: number; up_bytes: number; last_seen?: string; sessions: number }
export interface RzLive { name: string; type: string; unit: string; active: string; up: boolean; addresses: string[]; rx_bytes: number; tx_bytes: number; log: string[]; peers?: PeerLive[] }
interface Lease { address: string; mac: string; hostname: string }

const fwComment = (name: string) => `Rozaneh ${name}`;

/** Decodes a rozaneh://config/ link; null when it is not one. */
export function decodeLink(link: string): Record<string, any> | null {
  const m = /^(rozaneh|mahanvpn):\/\/config\/([A-Za-z0-9_-]+)=*$/.exec(link.trim());
  if (!m) return null;
  try {
    const b64 = m[2].replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const json = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
    return json.server && json.private_key && json.server_public_key ? json : null;
  } catch { return null; }
}

function encodeLink(cfg: Record<string, unknown>): string {
  const bytes = new TextEncoder().encode(JSON.stringify(cfg));
  let bin = "";
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return "rozaneh://config/" + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const randomPath = () => {
  const a = new Uint8Array(18);
  crypto.getRandomValues(a);
  return "/" + Array.from(a, (b) => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("");
};

export default function RozanehTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ interfaces: RzLive[]; now: number }>("/api/v1/rozaneh/status", 5000);
  const [dialog, setDialog] = useState<"client" | "server" | null>(null);
  if (!cfg) return null;
  const clients = cfg.interfaces.filter((i) => i.type === "rozaneh");
  const server = cfg.interfaces.find((i) => i.type === "rozaneh_server");
  const st = (n: string) => (live?.interfaces || []).find((x) => x.name === n);
  return (
    <div className="space-y-6">
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("اتصال روتر به سرور روزنه", "Connect this router to a Rozaneh server")}</h2>
            <p className="text-sm text-ink-3">{t("روتر با لینک روزنه به یک سرور بیرون وصل می‌شود و ترافیک شبکه را (همه، دستگاه‌های انتخابی، یا همه به‌جز ایران) از تونل می‌فرستد.", "The router connects to a server abroad with a Rozaneh link and sends LAN traffic (all, chosen devices, or all except Iran) through the tunnel.")}</p>
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => setDialog("client")}><Icon name="plus" className="size-4" />{t("اتصال جدید", "New connection")}</button>
        </div>
        {!clients.length && <div className="card"><Empty icon="shield" title={t("هنوز اتصالی ساخته نشده", "No connection yet")}>{t("لینک rozaneh://config/… را از پنل سرور روزنه بگیرید. برای روتر یک اتصال جدا بسازید، نه لینک گوشی.", "Get a rozaneh://config/… link from the Rozaneh server panel. Make a separate connection for the router, not a phone's link.")}</Empty></div>}
        {clients.map((c) => <ClientCard key={c.name} ifc={c} live={st(c.name)} />)}
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="card-title">{t("سرور روزنه روی این روتر", "Rozaneh server on this router")}</h2>
            <p className="text-sm text-ink-3">{t("گوشی و لپ‌تاپ با اپ روزنه از بیرون به این روتر وصل می‌شوند. یک دامنه که به IP عمومی روتر اشاره کند لازم است.", "Phones and laptops connect to this router from outside with the Rozaneh app. You need a domain that points at the router's public IP.")}</p>
          </div>
          {!server && <button className="btn btn-primary btn-sm" onClick={() => setDialog("server")}><Icon name="plus" className="size-4" />{t("راه‌اندازی سرور", "Set up the server")}</button>}
        </div>
        {server ? <ServerCard ifc={server} live={st(server.name)} /> : <div className="card"><Empty icon="server" title={t("سرور روزنه راه‌اندازی نشده", "No Rozaneh server yet")} /></div>}
      </section>
      {dialog === "client" && <NewClient onClose={() => setDialog(null)} />}
      {dialog === "server" && <NewServer onClose={() => setDialog(null)} />}
    </div>
  );
}

// ---- routing choice (shared with V2Ray later) ----------------------------

export type Mode = "lan" | "devices" | "except_iran" | "none";
export interface Routing { mode: Mode; devices: string[]; dns: boolean; block: boolean }

export const routingOf = (p?: PolicyRoute): Routing => !p || p.disabled
  ? { mode: "none", devices: p?.devices || [], dns: p?.dns_via_tunnel ?? true, block: !!p?.block_if_down }
  : { mode: p.from === "devices" ? "devices" : p.except_iran ? "except_iran" : "lan", devices: p.devices || [], dns: !!p.dns_via_tunnel, block: !!p.block_if_down };

/** Writes the policy route of an interface from a Routing choice. */
export function setRouting(c: Config, iface: string, r: Routing) {
  const rest = (c.policy_routes || []).filter((p) => p.interface !== iface);
  if (r.mode === "none") { c.policy_routes = rest.length ? rest : undefined; return; }
  const p: PolicyRoute = {
    interface: iface, from: r.mode === "devices" ? "devices" : "lan", devices: r.mode === "devices" ? r.devices : undefined,
    except_iran: r.mode === "except_iran" || undefined, dns_via_tunnel: r.dns || undefined, block_if_down: r.block || undefined,
  };
  c.policy_routes = [...rest, p];
}

export function routingLabel(r: Routing) {
  switch (r.mode) {
    case "lan": return t("همه‌ی شبکه از تونل", "All LAN traffic through the tunnel");
    case "except_iran": return t("همه به‌جز آدرس‌های ایران", "Everything except Iranian addresses");
    case "devices": return t(`فقط ${r.devices.length} دستگاه انتخابی`, `Only ${r.devices.length} chosen devices`);
    default: return t("هیچ ترافیکی (فقط اتصال)", "No traffic (connection only)");
  }
}

export function RoutingFields({ value, onChange }: { value: Routing; onChange: (r: Routing) => void }) {
  const [leases] = usePoll<Lease[]>("/api/v1/dhcp/leases", 0);
  const set = (p: Partial<Routing>) => onChange({ ...value, ...p });
  const toggle = (ip: string) => set({ devices: value.devices.includes(ip) ? value.devices.filter((d) => d !== ip) : [...value.devices, ip] });
  const known = new Set((leases || []).map((l) => l.address));
  return (
    <div className="space-y-3">
      <Field label={t("چه ترافیکی از تونل برود", "What goes through the tunnel")}>
        <Select value={value.mode} onChange={(v) => set({ mode: v as Mode })} options={[
          { value: "lan", label: t("همه‌ی شبکه‌ی داخلی", "All of the LAN") },
          { value: "devices", label: t("فقط دستگاه‌های انتخابی", "Only chosen devices") },
          { value: "except_iran", label: t("همه به‌جز آدرس‌های ایران", "Everything except Iranian addresses") },
          { value: "none", label: t("هیچ (فقط وصل باشد)", "Nothing (just stay connected)") },
        ]} />
      </Field>
      {value.mode === "except_iran" && <p className="text-xs text-ink-3">{t("سایت‌ها و سرویس‌های داخل ایران (بانک، دولت، …) مستقیم می‌روند و بقیه از تونل. فهرست IPهای ایران از RIPE است و همراه روتر می‌آید.", "Sites and services inside Iran (banks, government, …) go direct and everything else through the tunnel. The list of Iranian IPs comes from RIPE and ships with the router.")}</p>}
      {value.mode === "devices" && (
        <div className="space-y-2 rounded-md border border-line p-3">
          {(leases || []).length > 0 && <div className="grid gap-1 sm:grid-cols-2">
            {(leases || []).map((l) => (
              <Check key={l.address} label={`${l.hostname || l.mac} — ${l.address}`} checked={value.devices.includes(l.address)} onChange={() => toggle(l.address)} />
            ))}
          </div>}
          <Field label={t("آدرس‌های دیگر (هر خط یک IP یا رنج)", "Other addresses (one IP or range per line)")} hint={t("برای ثابت ماندن IP دستگاه، در صفحه‌ی DHCP آن را رزرو کنید.", "Reserve the device's IP on the DHCP page so it does not change.")}>
            <ListInput value={value.devices.filter((d) => !known.has(d))} onChange={(v) => set({ devices: [...value.devices.filter((d) => known.has(d)), ...v] })} placeholder="192.168.88.20" />
          </Field>
        </div>
      )}
      {value.mode !== "none" && <>
        <Check label={t("DNS روتر هم از تونل برود", "Send the router's DNS through the tunnel")} checked={value.dns} onChange={(v) => set({ dns: v })}
          hint={t("در شبکه‌ی فیلترشده جواب‌های جعلی DNS را دور می‌زند.", "Avoids fake DNS answers on a filtered network.")} />
        <Check label={t("اگر تونل قطع شد، این ترافیک هم قطع شود", "Block this traffic while the tunnel is down")} checked={value.block} onChange={(v) => set({ block: v })}
          hint={t("در غیر این صورت موقع قطعی مستقیم از اینترنت عادی می‌رود.", "Otherwise it goes out the normal internet during an outage.")} />
      </>}
    </div>
  );
}

// ---- client ---------------------------------------------------------------

function NewClient({ onClose }: { onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const used = new Set((cfg?.interfaces || []).map((i) => i.name));
  let n = 1;
  while (used.has(`rz${n}`)) n++;
  const [name, setName] = useState(`rz${n}`);
  const [link, setLink] = useState("");
  const [method, setMethod] = useState("auto");
  const [routing, setR] = useState<Routing>({ mode: "except_iran", devices: [], dns: true, block: false });
  const decoded = decodeLink(link);
  const valid = /^[a-z][a-z0-9-]{0,14}$/.test(name) && !used.has(name) && !!decoded && (routing.mode !== "devices" || routing.devices.length > 0);
  const save = async () => {
    const ok = await edit((c) => {
      c.interfaces.push({ name, type: "rozaneh", comment: t(`روزنه به ${decoded!.sni || decoded!.server}`, `Rozaneh to ${decoded!.sni || decoded!.server}`), rozaneh: { link: link.trim(), method: method === "auto" ? undefined : (method as "tunnel" | "dns") } });
      // A tunnel to the outside is an upstream: masquerade out of it and
      // treat new connections from it like WAN.
      c.interface_lists = c.interface_lists || {};
      c.interface_lists.WAN = [...new Set([...(c.interface_lists.WAN || []), name])];
      setRouting(c, name, routing);
    }, t("اتصال ساخته شد (هنوز اعمال نشده)", "Connection created (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={t("اتصال روتر به سرور روزنه", "Connect the router to a Rozaneh server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <Field label={t("لینک روزنه", "Rozaneh link")} hint={decoded ? <span className="text-idle">{t("سرور: ", "Server: ")}<Ltr className="mono">{decoded.server}</Ltr></span> : link ? <span className="text-talk">{t("لینک درست نیست", "This is not a valid link")}</span> : t("از پنل سرور روزنه: «اتصال جدید» ← کپی لینک", "From the Rozaneh server panel: New connection → copy link")}>
            <textarea className="input mono ltr min-h-28 text-left text-xs" dir="ltr" spellCheck={false} value={link} placeholder="rozaneh://config/…" onChange={(e) => setLink(e.target.value)} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("نام اینترفیس", "Interface name")}><TextInput value={name} onChange={(v) => setName(v.toLowerCase())} /></Field>
            <Field label={t("روش اتصال", "Connection method")}>
              <Select value={method} onChange={setMethod} options={[
                { value: "auto", label: t("خودکار (تونل، بعد DNS)", "Automatic (tunnel, then DNS)") },
                { value: "tunnel", label: t("فقط تونل", "Tunnel only") },
                { value: "dns", label: t("فقط DNS (کند)", "DNS only (slow)") },
              ]} />
            </Field>
          </div>
        </div>
        <RoutingFields value={routing} onChange={setR} />
      </div>
    </Modal>
  );
}

export function liveChip(ifc: Iface, live?: RzLive) {
  if (ifc.disabled) return <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>;
  if (!live || !live.active || live.active === "inactive") return <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>;
  if (live.active === "failed") return <Chip tone="talk">{t("خطا", "failed")}</Chip>;
  if (live.up) return <Chip tone="idle">{t("فعال", "up")}</Chip>;
  return <Chip tone="ring">{t("در حال اتصال…", "connecting…")}</Chip>;
}

export function LogView({ live }: { live?: RzLive }) {
  const [open, setOpen] = useState(false);
  if (!live?.log?.length) return null;
  return (
    <div className="border-t border-line px-5 py-2">
      <button className="text-xs text-accent" onClick={() => setOpen(!open)}>{open ? t("بستن گزارش", "Hide log") : t("نمایش گزارش", "Show log")}</button>
      {open && <pre className="ltr mono mt-2 max-h-56 overflow-auto rounded-md bg-surface-2 p-3 text-left text-[11px] leading-5">{live.log.join("\n")}</pre>}
    </div>
  );
}

function ClientCard({ ifc, live }: { ifc: Iface; live?: RzLive }) {
  const { cfg, edit } = useConfig();
  const [editing, setEditing] = useState(false);
  const d = decodeLink(ifc.rozaneh?.link || "");
  const routing = routingOf((cfg?.policy_routes || []).find((p) => p.interface === ifc.name));
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="shield" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        {liveChip(ifc, live)}
        <div className="ms-auto flex gap-2">
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`اتصال ${ifc.name} حذف شود؟`, `Delete connection ${ifc.name}?`)} onConfirm={() => edit((c) => removeIface(c, ifc.name), t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("سرور", "Server")}><Ltr className="mono">{d?.server || "—"}</Ltr></Info>
        <Info label={t("آدرس در تونل", "Tunnel address")}><Ltr className="mono">{live?.addresses?.join(", ") || "—"}</Ltr></Info>
        <Info label={t("دانلود / آپلود", "Down / Up")}><Ltr className="mono">{live?.up ? `${fmtBytes(live.rx_bytes)} / ${fmtBytes(live.tx_bytes)}` : "—"}</Ltr></Info>
        <Info label={t("مسیریابی", "Routing")}>{routingLabel(routing)}</Info>
      </div>
      <LogView live={live} />
      {editing && <ClientSettings ifc={ifc} routing={routing} onClose={() => setEditing(false)} />}
    </div>
  );
}

function ClientSettings({ ifc, routing: initial, onClose }: { ifc: Iface; routing: Routing; onClose: () => void }) {
  const { edit } = useConfig();
  const [link, setLink] = useState(ifc.rozaneh?.link || "");
  const [method, setMethod] = useState(ifc.rozaneh?.method || "auto");
  const [disabled, setDisabled] = useState(!!ifc.disabled);
  const [routing, setR] = useState<Routing>(initial);
  const valid = !!decodeLink(link) && (routing.mode !== "devices" || routing.devices.length > 0);
  const save = async () => {
    const ok = await edit((c) => {
      const i = c.interfaces.find((x) => x.name === ifc.name)!;
      i.rozaneh = { link: link.trim(), method: method === "auto" ? undefined : (method as "tunnel" | "dns") };
      i.disabled = disabled || undefined;
      setRouting(c, ifc.name, routing);
    }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open wide onClose={onClose} title={`${t("تنظیمات", "Settings")} ${ifc.name}`}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <Field label={t("لینک روزنه", "Rozaneh link")}>
            <textarea className="input mono ltr min-h-28 text-left text-xs" dir="ltr" spellCheck={false} value={link} onChange={(e) => setLink(e.target.value)} />
          </Field>
          <Field label={t("روش اتصال", "Connection method")}>
            <Select value={method} onChange={(v) => setMethod(v as "auto")} options={[
              { value: "auto", label: t("خودکار (تونل، بعد DNS)", "Automatic (tunnel, then DNS)") },
              { value: "tunnel", label: t("فقط تونل", "Tunnel only") },
              { value: "dns", label: t("فقط DNS (کند)", "DNS only (slow)") },
            ]} />
          </Field>
          <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />
        </div>
        <RoutingFields value={routing} onChange={setR} />
      </div>
    </Modal>
  );
}

export function removeIface(c: Config, name: string) {
  c.interfaces = c.interfaces.filter((i) => i.name !== name);
  for (const k of Object.keys(c.interface_lists || {})) c.interface_lists![k] = c.interface_lists![k].filter((x) => x !== name);
  if (c.dns?.listen_on) c.dns.listen_on = c.dns.listen_on.filter((x) => x !== name);
  if (c.firewall?.filter) c.firewall.filter = c.firewall.filter.filter((r) => r.comment !== fwComment(name));
  if (c.firewall?.nat) c.firewall.nat = c.firewall.nat.filter((r) => r.comment !== fwComment(name));
  const pr = (c.policy_routes || []).filter((p) => p.interface !== name);
  c.policy_routes = pr.length ? pr : undefined;
}

// ---- server ---------------------------------------------------------------

/** Opens the server port: redirect public→listen from WAN, accept listen. */
function setServerFw(c: Config, name: string, pub: number, listen: number) {
  c.firewall = c.firewall || {};
  const filter = (c.firewall.filter = (c.firewall.filter || []).filter((r) => r.comment !== fwComment(name)));
  const accept: Rule = { chain: "input", action: "accept", protocol: "tcp", dst_port: String(listen), in_interface_list: "WAN", comment: fwComment(name) };
  let pos = filter.findIndex((r) => r.chain === "input" && (r.action === "drop" || r.action === "reject") && !r.connection_state);
  if (pos < 0) pos = filter.length;
  filter.splice(pos, 0, accept);
  const nat = (c.firewall.nat = (c.firewall.nat || []).filter((r) => r.comment !== fwComment(name)));
  if (pub !== listen) nat.unshift({ chain: "dstnat", action: "redirect", protocol: "tcp", dst_port: String(pub), in_interface_list: "WAN", to_port: String(listen), comment: fwComment(name) });
}

function NewServer({ onClose }: { onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const [domain, setDomain] = useState("");
  const [email, setEmail] = useState("");
  const [addr, setAddr] = useState("10.77.0.1/24");
  const [certMode, setCertMode] = useState<"acme" | "own">("acme");
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [port, setPort] = useState(443);
  const [asLan, setAsLan] = useState(true);
  const [busy, setBusy] = useState(false);
  const taken = (cfg?.interfaces || []).some((i) => i.name === "rzs0");
  const valid = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(domain) && !!parseCidr(addr) && !taken &&
    (certMode === "acme" ? port === 443 : cert.includes("BEGIN") && key.includes("BEGIN"));
  const save = async () => {
    setBusy(true);
    try {
      const kp = await keygen();
      const ok = await edit((c) => {
        c.interfaces.push({
          name: "rzs0", type: "rozaneh_server", comment: t("سرور روزنه", "Rozaneh server"), addressing: "static", addresses: [addr],
          rozaneh_server: {
            domain: domain.toLowerCase(), acme_email: certMode === "acme" && email ? email : undefined, path: randomPath(), private_key: kp.private_key,
            public_port: port === 443 ? undefined : port, cert_pem: certMode === "own" ? cert : undefined, key_pem: certMode === "own" ? key : undefined, peers: [],
          },
        });
        if (asLan) {
          c.interface_lists = c.interface_lists || {};
          c.interface_lists.LAN = [...new Set([...(c.interface_lists.LAN || []), "rzs0"])];
          if (c.dns?.enabled) c.dns.listen_on = [...new Set([...(c.dns.listen_on || []), "rzs0"])];
        }
        setServerFw(c, "rzs0", port, 8443);
      }, t("سرور ساخته شد (هنوز اعمال نشده)", "Server created (not applied yet)"));
      if (ok) onClose();
    } catch (e) { alert((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Modal open wide onClose={onClose} title={t("راه‌اندازی سرور روزنه", "Set up a Rozaneh server")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid || busy} onClick={save}>{t("ساختن", "Create")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("دامنه", "Domain")} hint={t("رکورد A این دامنه باید به IP عمومی روتر اشاره کند", "Its A record must point at the router's public IP")}><TextInput value={domain} placeholder="vpn.example.com" onChange={setDomain} /></Field>
        <Field label={t("آدرس روتر در تونل", "Router address in the tunnel")} hint={t("کلاینت‌ها از همین رنج IP می‌گیرند", "Clients get addresses from this range")}><TextInput value={addr} onChange={setAddr} /></Field>
        <Field label={t("گواهی TLS", "TLS certificate")}>
          <Select value={certMode} onChange={(v) => setCertMode(v as "acme")} options={[
            { value: "acme", label: t("خودکار از Let's Encrypt", "Automatic from Let's Encrypt") },
            { value: "own", label: t("گواهی خودم", "My own certificate") },
          ]} />
        </Field>
        {certMode === "acme"
          ? <Field label={t("ایمیل (اختیاری)", "Email (optional)")} hint={t("برای هشدار انقضا از Let's Encrypt", "For expiry notices from Let's Encrypt")}><TextInput value={email} onChange={setEmail} /></Field>
          : <Field label={t("پورت عمومی TCP", "Public TCP port")}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>}
        {certMode === "own" && <>
          <Field label={t("گواهی (PEM، با زنجیره)", "Certificate (PEM, with chain)")}><textarea className="input mono ltr min-h-24 text-left text-xs" dir="ltr" value={cert} onChange={(e) => setCert(e.target.value)} /></Field>
          <Field label={t("کلید خصوصی (PEM)", "Private key (PEM)")}><textarea className="input mono ltr min-h-24 text-left text-xs" dir="ltr" value={key} onChange={(e) => setKey(e.target.value)} /></Field>
        </>}
        <div className="space-y-3 sm:col-span-2">
          <Check label={t("کلاینت‌ها مثل LAN باشند", "Treat clients like the LAN")} checked={asLan} onChange={setAsLan}
            hint={t("به شبکه‌ی داخلی، پنل و DNS روتر دسترسی دارند و از اینترنت روتر استفاده می‌کنند", "They reach the LAN, this panel and the router's DNS, and use the router's internet")} />
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("پورت TCP ", "TCP port ")}<Ltr className="mono">{port}</Ltr>{t(" از WAN روی فایروال باز می‌شود. اگر روتر پشت مودم یا روتر دیگری است، آن پورت را روی آن دستگاه به این روتر فوروارد کنید. هر کسی بدون کلید به این پورت بیاید یک سایت معمولی می‌بیند.", " is opened from WAN in the firewall. If this router is behind a modem or another router, forward that port to this router there. Anyone without a key who connects to it sees an ordinary website.")}
            {certMode === "acme" && t(" Let's Encrypt هم برای صدور گواهی از همین پورت 443 به دامنه وصل می‌شود.", " Let's Encrypt also connects to the domain on this port 443 to issue the certificate.")}
          </div>
        </div>
      </div>
    </Modal>
  );
}

function ServerCard({ ifc, live }: { ifc: Iface; live?: RzLive }) {
  const { cfg, edit } = useConfig();
  const s = ifc.rozaneh_server!;
  const [pub, setPub] = useState("");
  const [dialog, setDialog] = useState<"client" | "settings" | null>(null);
  useEffect(() => {
    api<{ public_key: string }>("/api/v1/wireguard/pubkey", { method: "POST", body: { private_key: s.private_key } }).then((r) => setPub(r.public_key)).catch(() => setPub(""));
  }, [s.private_key]);
  const port = s.public_port || 443;
  const peers = s.peers || [];
  const lan = (cfg?.interface_lists?.LAN || []).includes(ifc.name);
  const fwOpen = (cfg?.firewall?.filter || []).some((r) => r.comment === fwComment(ifc.name));
  const setPeer = (k: number, fn: (p: NonNullable<typeof s.peers>[number]) => void, msg: string) =>
    edit((c) => { const p = c.interfaces.find((i) => i.name === ifc.name)!.rozaneh_server!.peers!; fn(p[k]); }, msg);
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="server" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{s.domain}</Ltr></h2>
        {liveChip(ifc, live)}
        <div className="ms-auto flex flex-wrap gap-2">
          <button className="btn btn-primary btn-sm" disabled={!pub} onClick={() => setDialog("client")}><Icon name="plus" className="size-4" />{t("کلاینت (گوشی / لپ‌تاپ)", "Client (phone / laptop)")}</button>
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setDialog("settings")}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t("سرور روزنه و همه‌ی کلاینت‌هایش حذف شود؟", "Delete the Rozaneh server and all its clients?")} onConfirm={() => edit((c) => removeIface(c, ifc.name), t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آدرس برای کلاینت‌ها", "Address for clients")}><Ltr className="mono">{s.domain}:{port}</Ltr>{!fwOpen && <span className="ms-2 text-xs text-ring">{t("روی فایروال باز نیست", "not open in firewall")}</span>}</Info>
        <Info label={t("گواهی", "Certificate")}>{s.cert_pem ? t("گواهی خودم", "own certificate") : "Let's Encrypt"}</Info>
        <Info label={t("آدرس تونل", "Tunnel address")}><Ltr className="mono">{(ifc.addresses || []).join(", ")}</Ltr></Info>
        <Info label={t("دسترسی کلاینت‌ها", "Client access")}>{lan ? t("مثل LAN", "like the LAN") : t("فقط اینترنت", "internet only")}</Info>
      </div>
      {!peers.length ? <div className="border-t border-line"><Empty title={t("هنوز کلاینتی ندارد", "No clients yet")} /></div> : (
        <div className="overflow-x-auto border-t border-line">
          <table className="w-full text-sm">
            <thead className="bg-surface-2 text-xs text-ink-3"><tr>
              <th className="px-4 py-2 text-start font-medium">{t("نام", "Name")}</th><th className="px-4 py-2 text-start font-medium">IP</th>
              <th className="px-4 py-2 text-start font-medium">{t("آخرین اتصال", "Last seen")}</th>
              <th className="px-4 py-2 text-end font-medium">{t("دانلود / آپلود", "Down / Up")}</th><th className="px-4 py-2" />
            </tr></thead>
            <tbody className="divide-y divide-line">
              {peers.map((p, k) => {
                const st = live?.peers?.find((x) => x.public_key === p.public_key);
                const seen = st?.last_seen ? new Date(st.last_seen) : null;
                const recent = !!seen && Date.now() - seen.getTime() < 3 * 60_000;
                return (
                  <tr key={p.public_key}>
                    <td className="px-4 py-2.5 font-medium">{p.name}{p.disabled && <span className="ms-2"><Chip tone="talk">{t("غیرفعال", "disabled")}</Chip></span>}</td>
                    <td className="px-4 py-2.5 text-xs"><Ltr className="mono">{p.ip}</Ltr></td>
                    <td className="px-4 py-2.5 text-xs">{recent ? <Chip tone="idle">{t("وصل", "online")}</Chip> : seen ? seen.toLocaleString() : t("هرگز", "never")}</td>
                    <td className="px-4 py-2.5 text-end text-xs"><Ltr className="mono">{st ? `${fmtBytes(st.down_bytes)} / ${fmtBytes(st.up_bytes)}` : "—"}</Ltr></td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-end">
                      <button className="btn btn-sm" onClick={() => setPeer(k, (x) => { x.disabled = !x.disabled || undefined; }, t("تغییر کرد (هنوز اعمال نشده)", "Changed (not applied yet)"))}>{p.disabled ? t("فعال کن", "Enable") : t("غیرفعال کن", "Disable")}</button>
                      <ConfirmButton className="icon-btn text-talk" question={t(`«${p.name}» حذف شود؟ دیگر نمی‌تواند وصل شود.`, `Delete "${p.name}"? It will no longer connect.`)}
                        onConfirm={() => edit((c) => { const srv = c.interfaces.find((i) => i.name === ifc.name)!.rozaneh_server!; srv.peers = (srv.peers || []).filter((_, j) => j !== k); }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <LogView live={live} />
      {dialog === "client" && <NewPeer ifc={ifc} serverPub={pub} onClose={() => setDialog(null)} />}
      {dialog === "settings" && <ServerSettings ifc={ifc} onClose={() => setDialog(null)} />}
    </div>
  );
}

function NewPeer({ ifc, serverPub, onClose }: { ifc: Iface; serverPub: string; onClose: () => void }) {
  const { edit } = useConfig();
  const s = ifc.rozaneh_server!;
  const cidr = (ifc.addresses || [])[0] || "";
  const used = (s.peers || []).map((p) => p.ip);
  const [name, setName] = useState("");
  const [ip, setIp] = useState(() => nextFree(cidr, used));
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ name: string; link: string } | null>(null);
  const names = new Set((s.peers || []).map((p) => p.name));
  const label = name.trim() || `device-${ip.split(".").pop()}`;
  const valid = !!ip && !used.includes(ip) && !names.has(label);
  const create = async () => {
    setBusy(true);
    try {
      const kp = await keygen();
      const ok = await edit((c) => {
        const srv = c.interfaces.find((i) => i.name === ifc.name)!.rozaneh_server!;
        srv.peers = [...(srv.peers || []), { name: label, public_key: kp.public_key, ip }];
      });
      if (!ok) return;
      const port = s.public_port || 443;
      setResult({ name: label, link: encodeLink({ server: `${s.domain}:${port}`, sni: s.domain, path: s.path, private_key: kp.private_key, server_public_key: serverPub, full_tunnel: true, cover_traffic: s.cover_traffic ?? true }) });
    } catch (e) { alert((e as Error).message); } finally { setBusy(false); }
  };
  if (result) {
    const file = (result.name.replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "") || `rozaneh-${ip.split(".").pop()}`) + ".txt";
    return <ClientResult name={result.name} file={file} conf={result.link} onClose={onClose} steps={
      <ol className="list-decimal space-y-1 ps-5 text-sm text-ink-2">
        <li>{t("در گوشی یا لپ‌تاپ اپ روزنه را باز کنید و این QR را اسکن کنید، یا لینک را کپی و وارد کنید.", "Open the Rozaneh app on the phone or laptop and scan this QR, or copy the link into it.")}</li>
        <li>{t("در صفحه‌ی «تغییرات» این تغییر را اعمال و تأیید کنید.", "Apply and confirm the change on the Changes page.")}</li>
      </ol>} />;
  }
  return (
    <Modal open onClose={onClose} title={t("کلاینت جدید روزنه", "New Rozaneh client")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid || busy} onClick={create}>{t("ساختن و نمایش QR", "Create and show QR")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("نام", "Name")}><TextInput ltr={false} value={name} placeholder={t("مثلاً گوشی علی", "e.g. Ali's phone")} onChange={setName} /></Field>
        <Field label={t("آدرس IP کلاینت", "Client IP address")}><TextInput value={ip} onChange={setIp} /></Field>
        {names.has(label) && <p className="text-sm text-talk sm:col-span-2">{t("این نام قبلاً استفاده شده", "This name is already used")}</p>}
      </div>
    </Modal>
  );
}

function ServerSettings({ ifc, onClose }: { ifc: Iface; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const s = ifc.rozaneh_server!;
  const [domain, setDomain] = useState(s.domain);
  const [email, setEmail] = useState(s.acme_email || "");
  const [cover, setCover] = useState(s.cover_url || "");
  const [coverTraffic, setCoverTraffic] = useState(s.cover_traffic ?? true);
  const [dns, setDns] = useState(s.client_dns || []);
  const [disabled, setDisabled] = useState(!!ifc.disabled);
  const [asLan, setAsLan] = useState((cfg?.interface_lists?.LAN || []).includes(ifc.name));
  const [openFw, setOpenFw] = useState((cfg?.firewall?.filter || []).some((r) => r.comment === fwComment(ifc.name)));
  const save = async () => {
    const ok = await edit((c) => {
      const i = c.interfaces.find((x) => x.name === ifc.name)!;
      i.disabled = disabled || undefined;
      i.rozaneh_server = { ...i.rozaneh_server!, domain: domain.toLowerCase(), acme_email: email || undefined, cover_url: cover || undefined, cover_traffic: coverTraffic ? undefined : false, client_dns: dns.length ? dns : undefined };
      c.interface_lists = c.interface_lists || {};
      const L = (c.interface_lists.LAN || []).filter((x) => x !== ifc.name);
      c.interface_lists.LAN = asLan ? [...L, ifc.name] : L;
      if (c.dns) {
        const D = (c.dns.listen_on || []).filter((x) => x !== ifc.name);
        c.dns.listen_on = asLan && c.dns.enabled ? [...D, ifc.name] : D;
      }
      if (openFw) setServerFw(c, ifc.name, s.public_port || 443, s.listen_port || 8443);
      else {
        if (c.firewall?.filter) c.firewall.filter = c.firewall.filter.filter((r) => r.comment !== fwComment(ifc.name));
        if (c.firewall?.nat) c.firewall.nat = c.firewall.nat.filter((r) => r.comment !== fwComment(ifc.name));
      }
    }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
    if (ok) onClose();
  };
  return (
    <Modal open onClose={onClose} title={t("تنظیمات سرور روزنه", "Rozaneh server settings")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" onClick={save}>{t("ذخیره", "Save")}</button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("دامنه", "Domain")}><TextInput value={domain} onChange={setDomain} /></Field>
        {!s.cert_pem && <Field label={t("ایمیل Let's Encrypt", "Let's Encrypt email")}><TextInput value={email} onChange={setEmail} /></Field>}
        <Field label={t("سایت پوششی", "Cover website")} hint={t("خالی = صفحه‌ی پیش‌فرض یک وب‌سرور", "empty = a web server's default page")}><TextInput value={cover} placeholder="http://127.0.0.1:8080" onChange={setCover} /></Field>
        <Field label={t("DNS برای کلاینت‌ها", "DNS for clients")} hint={t("خالی = خود روتر", "empty = the router")}><ListInput rows={2} value={dns} onChange={setDns} placeholder="1.1.1.1" /></Field>
        <div className="space-y-3 sm:col-span-2">
          <Check label={t("ترافیک پوششی", "Cover traffic")} checked={coverTraffic} onChange={setCoverTraffic} hint={t("الگوی ترافیک را شبیه مرور وب می‌کند؛ کمی مصرف بیشتر.", "Makes the traffic pattern look like browsing; uses a little more data.")} />
          <Check label={t("پورت روی فایروال باز باشد (از WAN)", "Port open in the firewall (from WAN)")} checked={openFw} onChange={setOpenFw} />
          <Check label={t("کلاینت‌ها مثل LAN باشند", "Treat clients like the LAN")} checked={asLan} onChange={setAsLan} />
          <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />
        </div>
        <p className="text-xs text-ink-3 sm:col-span-2">{t("تغییر دامنه یعنی لینک کلاینت‌ها هم باید عوض شود.", "Changing the domain means the client links must change too.")}</p>
      </div>
    </Modal>
  );
}
