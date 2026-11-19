import { useState } from "react";
import { fmtBytes, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Config, Iface, L2TPv3, Rule } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, Ltr, Modal, Select, TextInput } from "../ui";
import { Info, parseCidr } from "./Vpn";
import { removeIface } from "./VpnRozaneh";
import type { RzLive } from "./VpnRozaneh";

// L2TPv3 tab: static Ethernet pseudowires to another router (like EoIP in
// MikroTik). The interface can get an IP address or join a bridge, which
// stretches one LAN over both sites.

const fwComment = (name: string) => `L2TPv3 ${name}`;
const ipRe = /^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;

export default function L2TPv3Tab() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ interfaces: RzLive[] }>("/api/v1/ppp/status", 5000);
  const [adding, setAdding] = useState(false);
  if (!cfg) return null;
  const tunnels = cfg.interfaces.filter((i) => i.type === "l2tpv3");
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="card-title">{t("تونل L2TPv3 (لایه ۲)", "L2TPv3 tunnels (layer 2)")}</h2>
          <p className="text-sm text-ink-3">{t("یک کابل شبکه‌ی مجازی بین دو روتر، مثل EoIP در میکروتیک. می‌تواند IP بگیرد یا عضو بریج شود تا LAN دو شعبه یکی شود. رمزنگاری ندارد؛ روی اینترنت آن را داخل WireGuard یا IPsec بگذارید.", "A virtual network cable between two routers, like EoIP in MikroTik. It can get an IP or join a bridge so two sites share one LAN. It is not encrypted; over the internet, run it inside WireGuard or IPsec.")}</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setAdding(true)}><Icon name="plus" className="size-4" />{t("تونل جدید", "New tunnel")}</button>
      </div>
      {!tunnels.length && <div className="card"><Empty icon="link" title={t("هنوز تونلی ساخته نشده", "No tunnel yet")}>{t("هر دو طرف باید IDهای قرینه داشته باشند: Tunnel ID این طرف = Peer tunnel ID آن طرف.", "Both ends need mirrored IDs: this side's tunnel ID = the other side's peer tunnel ID.")}</Empty></div>}
      {tunnels.map((x) => <TunnelCard key={x.name} ifc={x} cfg={cfg} live={(live?.interfaces || []).find((l) => l.name === x.name)} />)}
      {adding && <TunnelDialog onClose={() => setAdding(false)} />}
    </div>
  );
}

function setFw(c: Config, name: string, l: L2TPv3, open: boolean) {
  c.firewall = c.firewall || {};
  const filter = (c.firewall.filter = (c.firewall.filter || []).filter((r) => r.comment !== fwComment(name)));
  if (!open) return;
  const r: Rule = l.encapsulation === "ip"
    ? { chain: "input", action: "accept", protocol: "115", src_address: l.remote, comment: fwComment(name) }
    : { chain: "input", action: "accept", protocol: "udp", dst_port: String(l.port || 1701), src_address: l.remote, comment: fwComment(name) };
  let pos = filter.findIndex((x) => x.chain === "input" && (x.action === "drop" || x.action === "reject") && !x.connection_state);
  if (pos < 0) pos = filter.length;
  filter.splice(pos, 0, r);
}

function TunnelDialog({ ifc, onClose }: { ifc?: Iface; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const used = new Set((cfg?.interfaces || []).map((i) => i.name));
  let n = 1;
  while (used.has(`l2tpv3-${n}`)) n++;
  const l = ifc?.l2tpv3;
  const bridges = (cfg?.interfaces || []).filter((i) => i.type === "bridge");
  const inBridge = ifc ? bridges.find((b) => (b.members || []).includes(ifc.name))?.name || "" : "";
  const [name, setName] = useState(ifc?.name || `l2tpv3-${n}`);
  const [remote, setRemote] = useState(l?.remote || "");
  const [local, setLocal] = useState(l?.local || "");
  const [encap, setEncap] = useState<"udp" | "ip">(l?.encapsulation || "udp");
  const [port, setPort] = useState(l?.port || 1701);
  const [ids, setIds] = useState({ tunnel_id: l?.tunnel_id || n, peer_tunnel_id: l?.peer_tunnel_id || n, session_id: l?.session_id || n, peer_session_id: l?.peer_session_id || n });
  const [mode, setMode] = useState<"ip" | "bridge">(inBridge ? "bridge" : "ip");
  const [addr, setAddr] = useState(ifc?.addresses?.[0] || "");
  const [bridge, setBridge] = useState(inBridge || bridges[0]?.name || "");
  const [openFw, setOpenFw] = useState(ifc ? (cfg?.firewall?.filter || []).some((r) => r.comment === fwComment(ifc.name)) : true);
  const [disabled, setDisabled] = useState(!!ifc?.disabled);
  const idOK = (v: number) => Number.isInteger(v) && v >= 1 && v <= 4294967295;
  const valid = (!!ifc || (/^[a-z][a-z0-9-]{0,14}$/.test(name) && !used.has(name) && !name.startsWith("ppps")))
    && ipRe.test(remote) && (!local || ipRe.test(local)) && (encap === "ip" || (port > 0 && port < 65536))
    && Object.values(ids).every(idOK) && (mode === "bridge" ? !!bridge : !addr || !!parseCidr(addr) || addr.includes(":"));
  const save = async () => {
    const lv: L2TPv3 = { remote: remote.trim(), local: local.trim() || undefined, encapsulation: encap === "ip" ? "ip" : undefined, port: encap === "udp" && port !== 1701 ? port : undefined, ...ids };
    const nm = ifc?.name || name;
    const ok = await edit((c) => {
      let i = c.interfaces.find((x) => x.name === nm);
      if (!i) { i = { name: nm, type: "l2tpv3" }; c.interfaces.push(i); }
      i.l2tpv3 = lv;
      i.comment = `L2TPv3 ${lv.remote}`;
      i.disabled = disabled || undefined;
      for (const b of c.interfaces) if (b.type === "bridge") b.members = (b.members || []).filter((m) => m !== nm);
      if (mode === "bridge") {
        const b = c.interfaces.find((x) => x.name === bridge)!;
        b.members = [...(b.members || []), nm];
        i.addressing = undefined; i.addresses = undefined;
      } else {
        i.addressing = addr ? "static" : undefined;
        i.addresses = addr ? [addr.trim()] : undefined;
      }
      setFw(c, nm, lv, openFw);
    }, ifc ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("تونل ساخته شد (هنوز اعمال نشده)", "Tunnel created (not applied yet)"));
    if (ok) onClose();
  };
  const idField = (k: keyof typeof ids, label: string) => (
    <Field label={label}><TextInput type="number" value={ids[k]} onChange={(v) => setIds({ ...ids, [k]: Number(v) || 0 })} /></Field>
  );
  return (
    <Modal open wide onClose={onClose} title={ifc ? `${t("تنظیمات", "Settings")} ${ifc.name}` : t("تونل L2TPv3 جدید", "New L2TPv3 tunnel")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{ifc ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          {!ifc && <Field label={t("نام اینترفیس", "Interface name")}><TextInput value={name} onChange={(v) => setName(v.toLowerCase())} /></Field>}
          <Field label={t("IP روتر آن طرف", "Other router's IP")}><TextInput value={remote} placeholder="203.0.113.10" onChange={setRemote} /></Field>
          <Field label={t("IP این روتر (اختیاری)", "This router's IP (optional)")} hint={t("خالی = خودکار، آدرسی که به آن طرف می‌رسد", "empty = automatic, the address that reaches the other side")}><TextInput value={local} onChange={setLocal} /></Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("بسته‌بندی", "Encapsulation")}>
              <Select value={encap} onChange={(v) => setEncap(v as "udp")} options={[{ value: "udp", label: "UDP" }, { value: "ip", label: t("IP (پروتکل 115)", "IP (protocol 115)") }]} />
            </Field>
            {encap === "udp" && <Field label={t("پورت UDP", "UDP port")} hint={t("هر دو طرف یکسان", "same on both ends")}><TextInput type="number" value={port} onChange={(v) => setPort(Number(v) || 0)} /></Field>}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {idField("tunnel_id", "Tunnel ID")}{idField("peer_tunnel_id", "Peer tunnel ID")}
            {idField("session_id", "Session ID")}{idField("peer_session_id", "Peer session ID")}
          </div>
        </div>
        <div className="space-y-4">
          <Field label={t("کاربرد", "Use")}>
            <Select value={mode} onChange={(v) => setMode(v as "ip")} options={[
              { value: "ip", label: t("IP روی خود تونل", "An IP on the tunnel itself") },
              { value: "bridge", label: t("عضو بریج (LAN مشترک)", "Bridge member (shared LAN)") },
            ]} />
          </Field>
          {mode === "ip" ? <Field label={t("آدرس IP", "IP address")} hint={t("مثلاً 172.30.0.1/30؛ آن طرف 172.30.0.2/30", "e.g. 172.30.0.1/30; the other side 172.30.0.2/30")}><TextInput value={addr} placeholder="172.30.0.1/30" onChange={setAddr} /></Field>
            : <Field label={t("بریج", "Bridge")} hint={t("مراقب باشید هر دو LAN یک DHCP سرور نداشته باشند.", "Make sure the two LANs do not both run a DHCP server.")}><Select value={bridge} onChange={setBridge} options={bridges.map((b) => b.name)} /></Field>}
          <Check label={t("پورت روی فایروال باز شود (فقط از IP آن طرف)", "Open it in the firewall (only from the other side's IP)")} checked={openFw} onChange={setOpenFw} />
          {ifc && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("روی روتر آن طرف (اگر Mahan Router است) همین تونل را با IDهای قرینه بسازید:", "On the other router (if it is a Mahan Router) create the same tunnel with mirrored IDs:")}
            <div className="mono ltr mt-1 text-left">Tunnel ID {ids.peer_tunnel_id} · Peer tunnel ID {ids.tunnel_id} · Session ID {ids.peer_session_id} · Peer session ID {ids.session_id}</div>
            {t("روی لینوکس:", "On Linux:")}
            <pre className="mono ltr mt-1 whitespace-pre-wrap text-left">{`ip l2tp add tunnel tunnel_id ${ids.peer_tunnel_id} peer_tunnel_id ${ids.tunnel_id} encap ${encap}${encap === "udp" ? ` udp_sport ${port} udp_dport ${port}` : ""} local <IP> remote <THIS-ROUTER>\nip l2tp add session tunnel_id ${ids.peer_tunnel_id} session_id ${ids.peer_session_id} peer_session_id ${ids.session_id}`}</pre>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function TunnelCard({ ifc, cfg, live }: { ifc: Iface; cfg: Config; live?: RzLive }) {
  const { edit } = useConfig();
  const [editing, setEditing] = useState(false);
  const l = ifc.l2tpv3!;
  const br = cfg.interfaces.find((b) => b.type === "bridge" && (b.members || []).includes(ifc.name));
  const chip = ifc.disabled ? <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip> : live?.up ? <Chip tone="idle">{t("ساخته شده", "created")}</Chip> : <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>;
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="link" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        {chip}
        <div className="ms-auto flex gap-2">
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`تونل ${ifc.name} حذف شود؟`, `Delete tunnel ${ifc.name}?`)} onConfirm={() => edit((c) => {
            removeIface(c, ifc.name);
            for (const b of c.interfaces) if (b.type === "bridge") b.members = (b.members || []).filter((m) => m !== ifc.name);
            if (c.firewall?.filter) c.firewall.filter = c.firewall.filter.filter((r) => r.comment !== fwComment(ifc.name));
          }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آن طرف", "Remote")}><Ltr className="mono">{l.remote}</Ltr></Info>
        <Info label={t("بسته‌بندی", "Encapsulation")}><Ltr className="mono">{l.encapsulation === "ip" ? "IP/115" : `UDP ${l.port || 1701}`}</Ltr></Info>
        <Info label="Tunnel / Session ID"><Ltr className="mono">{l.tunnel_id}→{l.peer_tunnel_id} · {l.session_id}→{l.peer_session_id}</Ltr></Info>
        <Info label={br ? t("عضو بریج", "Bridge member of") : t("آدرس", "Address")}><Ltr className="mono">{br ? br.name : ifc.addresses?.join(", ") || "—"}</Ltr></Info>
        {live?.up && <Info label={t("دریافت / ارسال", "Received / sent")}><Ltr className="mono">{fmtBytes(live.rx_bytes)} / {fmtBytes(live.tx_bytes)}</Ltr></Info>}
      </div>
      {editing && <TunnelDialog ifc={ifc} onClose={() => setEditing(false)} />}
    </div>
  );
}
