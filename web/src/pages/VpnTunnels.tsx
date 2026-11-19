import { useState } from "react";
import { fmtBytes, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Config, Iface, Tunnel, TunnelType } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, Ltr, Modal, Select, TextInput } from "../ui";
import { Info } from "./Vpn";
import { removeIface } from "./VpnRozaneh";
import type { RzLive } from "./VpnRozaneh";

// GRE / IPIP / EoIP / 6to4 / EoIPv6 / GRE6 tab: plain point-to-point
// tunnels like RouterOS /interface gre, ipip, eoip, 6to4, eoipv6, gre6.
// The agent opens the firewall for packets from the remote address.

interface Kind { id: TunnelType; label: string; v6: boolean; l2: boolean; desc: [string, string] }
const KINDS: Kind[] = [
  { id: "eoip", label: "EoIP", v6: false, l2: true, desc: ["لایه ۲ روی IPv4، سازگار با EoIP میکروتیک. می‌تواند عضو بریج شود.", "Layer 2 over IPv4, compatible with MikroTik EoIP. Can join a bridge."] },
  { id: "gre", label: "GRE", v6: false, l2: false, desc: ["تونل IP روی IPv4 (لایه ۳)، با سیسکو، میکروتیک و لینوکس کار می‌کند.", "IP tunnel over IPv4 (layer 3); works with Cisco, MikroTik and Linux."] },
  { id: "ipip", label: "IPIP", v6: false, l2: false, desc: ["ساده‌ترین تونل IPv4 در IPv4 (لایه ۳).", "The simplest IPv4-in-IPv4 tunnel (layer 3)."] },
  { id: "6to4", label: "6to4", v6: false, l2: false, desc: ["IPv6 روی IPv4 (SIT)، مثلاً برای Hurricane Electric tunnelbroker.", "IPv6 over IPv4 (SIT), e.g. for a Hurricane Electric tunnel broker."] },
  { id: "eoipv6", label: "EoIPv6", v6: true, l2: true, desc: ["لایه ۲ روی IPv6، سازگار با EoIPv6 میکروتیک.", "Layer 2 over IPv6, compatible with MikroTik EoIPv6."] },
  { id: "gre6", label: "GREv6", v6: true, l2: false, desc: ["GRE روی IPv6 (لایه ۳).", "GRE over IPv6 (layer 3)."] },
];
const kindOf = (id: string) => KINDS.find((k) => k.id === id)!;
const v4Re = /^\d{1,3}(\.\d{1,3}){3}$/;
const v6Re = /^[0-9a-fA-F:]+:[0-9a-fA-F:.]*$/;
const cidrRe = /^(\d{1,3}(\.\d{1,3}){3}\/\d{1,2}|[0-9a-fA-F:]+:[0-9a-fA-F:.]*\/\d{1,3})$/;
const macRe = /^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/;

export default function TunnelsTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ interfaces: RzLive[] }>("/api/v1/ppp/status", 5000);
  const [adding, setAdding] = useState(false);
  if (!cfg) return null;
  const tunnels = cfg.interfaces.filter((i) => KINDS.some((k) => k.id === i.type));
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="card-title">{t("تونل‌های GRE، IPIP، EoIP، 6to4، EoIPv6 و GREv6", "GRE, IPIP, EoIP, 6to4, EoIPv6 and GREv6 tunnels")}</h2>
          <p className="text-sm text-ink-3">{t("تونل نقطه‌به‌نقطه به روتر دیگر. هیچ‌کدام رمزنگاری ندارند؛ روی اینترنت آن‌ها را داخل WireGuard یا IPsec بگذارید. بیشتر مودم‌ها و NATها این پروتکل‌ها را عبور نمی‌دهند، پس هر دو طرف IP عمومی لازم دارند.", "Point-to-point tunnels to another router. None of them is encrypted; over the internet, run them inside WireGuard or IPsec. Most modems and NATs do not pass these protocols, so both ends need a public IP.")}</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setAdding(true)}><Icon name="plus" className="size-4" />{t("تونل جدید", "New tunnel")}</button>
      </div>
      {!tunnels.length && <div className="card"><Empty icon="link" title={t("هنوز تونلی ساخته نشده", "No tunnel yet")}>{t("برای EoIP، روی هر دو طرف Tunnel ID یکسان بگذارید.", "For EoIP, use the same tunnel ID on both ends.")}</Empty></div>}
      {tunnels.map((x) => <TunnelCard key={x.name} ifc={x} cfg={cfg} live={(live?.interfaces || []).find((l) => l.name === x.name)} />)}
      {adding && <TunnelDialog onClose={() => setAdding(false)} />}
    </div>
  );
}

// mikrotikCmd is the matching command for a MikroTik on the other end.
function mikrotikCmd(k: Kind, name: string, tn: Tunnel, keepalive: number) {
  const self = tn.local || "<THIS-ROUTER-IP>";
  const parts = [`/interface ${k.id} add name=${name} remote-address=${self}`];
  if (tn.remote) parts.push(`local-address=${tn.remote}`);
  if (k.l2) parts.push(`tunnel-id=${tn.tunnel_id || 0}`, keepalive ? `keepalive=${keepalive}s,10` : "!keepalive");
  if (k.id === "gre" || k.id === "gre6" || k.id === "ipip") parts.push("!keepalive");
  return parts.join(" ");
}

function TunnelDialog({ ifc, onClose }: { ifc?: Iface; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const used = new Set((cfg?.interfaces || []).map((i) => i.name));
  const tn = ifc?.tunnel;
  const [kind, setKind] = useState<TunnelType>((ifc?.type as TunnelType) || "eoip");
  const k = kindOf(kind);
  const free = (base: string) => { let n = 1; while (used.has(`${base}-${n}`)) n++; return `${base}-${n}`; };
  const [name, setName] = useState(ifc?.name || "");
  const nm = ifc?.name || name || free(kind);
  const bridges = (cfg?.interfaces || []).filter((i) => i.type === "bridge");
  const inBridge = ifc ? bridges.find((b) => (b.members || []).includes(ifc.name))?.name || "" : "";
  const [remote, setRemote] = useState(tn?.remote || "");
  const [local, setLocal] = useState(tn?.local || "");
  const [tid, setTid] = useState(tn?.tunnel_id ?? 0);
  const [key, setKey] = useState(tn?.key ?? 0);
  const [ttl, setTtl] = useState(tn?.ttl ?? 0);
  const [keepalive, setKeepalive] = useState(tn?.keepalive ?? 10);
  const [mac, setMac] = useState(tn?.mac || "");
  const [mtu, setMtu] = useState(ifc?.mtu || 0);
  const [mode, setMode] = useState<"ip" | "bridge">(inBridge ? "bridge" : "ip");
  const [addrs, setAddrs] = useState((ifc?.addresses || []).join(", "));
  const [bridge, setBridge] = useState(inBridge || bridges[0]?.name || "");
  const [disabled, setDisabled] = useState(!!ifc?.disabled);
  const ipOK = (s: string) => (k.v6 ? v6Re : v4Re).test(s.trim());
  const addrList = addrs.split(/[\s,]+/).filter(Boolean);
  const bridged = k.l2 && mode === "bridge";
  const valid = (!!ifc || (/^[a-z][a-z0-9-]{0,14}$/.test(nm) && !used.has(nm) && !nm.startsWith("ppps")))
    && (remote ? ipOK(remote) : kind === "6to4") && (local ? ipOK(local) : kind !== "gre6")
    && (!k.l2 || (Number.isInteger(tid) && tid >= 0 && tid <= (kind === "eoip" ? 65535 : 4095)))
    && key >= 0 && ttl >= 0 && ttl <= 255 && keepalive >= 0 && keepalive <= 3600 && (!mac || macRe.test(mac))
    && (mtu === 0 || (mtu >= 576 && mtu <= 9000))
    && (bridged ? !!bridge : addrList.every((a) => cidrRe.test(a)));
  const save = async () => {
    const tv: Tunnel = { remote: remote.trim() || undefined, local: local.trim() || undefined };
    if (k.l2) {
      tv.tunnel_id = tid || undefined;
      tv.keepalive = keepalive === 10 ? undefined : keepalive;
      tv.mac = mac.trim() || undefined;
    }
    if (kind === "gre" || kind === "gre6") tv.key = key || undefined;
    tv.ttl = ttl || undefined;
    const ok = await edit((c) => {
      let i = c.interfaces.find((x) => x.name === nm);
      if (!i) { i = { name: nm, type: kind }; c.interfaces.push(i); }
      i.type = kind;
      i.tunnel = tv;
      i.comment = `${k.label} ${tv.remote || "relay"}`;
      i.disabled = disabled || undefined;
      i.mtu = mtu || undefined;
      for (const b of c.interfaces) if (b.type === "bridge") b.members = (b.members || []).filter((m) => m !== nm);
      if (bridged) {
        const b = c.interfaces.find((x) => x.name === bridge)!;
        b.members = [...(b.members || []), nm];
        i.addressing = undefined; i.addresses = undefined;
      } else {
        i.addressing = addrList.length ? "static" : undefined;
        i.addresses = addrList.length ? addrList : undefined;
      }
    }, ifc ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("تونل ساخته شد (هنوز اعمال نشده)", "Tunnel created (not applied yet)"));
    if (ok) onClose();
  };
  const fam = k.v6 ? "IPv6" : "IPv4";
  return (
    <Modal open wide onClose={onClose} title={ifc ? `${t("تنظیمات", "Settings")} ${ifc.name}` : t("تونل جدید", "New tunnel")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={!valid} onClick={save}>{ifc ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          {!ifc && <Field label={t("نوع تونل", "Tunnel type")} hint={t(...k.desc)}>
            <Select value={kind} onChange={(v) => setKind(v as TunnelType)} options={KINDS.map((x) => ({ value: x.id, label: x.label }))} />
          </Field>}
          {!ifc && <Field label={t("نام اینترفیس", "Interface name")}><TextInput value={name || free(kind)} onChange={(v) => setName(v.toLowerCase())} /></Field>}
          <Field label={`${t("IP روتر آن طرف", "Other router's IP")} (${fam})`} hint={kind === "6to4" ? t("خالی = رله‌ی عمومی 6to4 (2002::/16)", "empty = public 6to4 relay (2002::/16)") : undefined}>
            <TextInput value={remote} placeholder={k.v6 ? "2001:db8::2" : "203.0.113.10"} onChange={setRemote} />
          </Field>
          <Field label={kind === "gre6" ? t("IP این روتر", "This router's IP") : `${t("IP این روتر", "This router's IP")} (${t("اختیاری", "optional")})`} hint={kind === "gre6" ? t("برای GREv6 لازم است.", "Required for GREv6.") : t("خالی = هر آدرسی؛ اگر روتر چند IP عمومی دارد آن را بنویسید.", "empty = any address; set it when the router has several public IPs.")}>
            <TextInput value={local} onChange={setLocal} />
          </Field>
          {k.l2 && <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Tunnel ID" hint={t("هر دو طرف یکسان", "same on both ends")}><TextInput type="number" value={tid} onChange={(v) => setTid(Number(v) || 0)} /></Field>
            <Field label={t("Keepalive (ثانیه)", "Keepalive (seconds)")} hint={t("0 = خاموش. با keepalive، اگر ۱۰ بار پاسخی نیاید لینک قطع نشان داده می‌شود.", "0 = off. With keepalive the link shows down after 10 missed intervals.")}><TextInput type="number" value={keepalive} onChange={(v) => setKeepalive(Number(v) || 0)} /></Field>
          </div>}
          {(kind === "gre" || kind === "gre6") && <Field label={t("کلید GRE (اختیاری)", "GRE key (optional)")} hint={t("0 = بدون کلید؛ باید با آن طرف یکی باشد.", "0 = no key; must match the other end.")}><TextInput type="number" value={key} onChange={(v) => setKey(Number(v) || 0)} /></Field>}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="TTL" hint={t("0 = از بسته‌ی داخلی", "0 = inherit")}><TextInput type="number" value={ttl} onChange={(v) => setTtl(Number(v) || 0)} /></Field>
            <Field label="MTU" hint={t("0 = پیش‌فرض", "0 = default")}><TextInput type="number" value={mtu} onChange={(v) => setMtu(Number(v) || 0)} /></Field>
          </div>
          {k.l2 && <Field label={t("MAC (اختیاری)", "MAC (optional)")} hint={t("خالی = یک MAC ثابت از روی نام", "empty = a fixed MAC derived from the name")}><TextInput value={mac} placeholder="02:00:00:00:00:01" onChange={setMac} /></Field>}
        </div>
        <div className="space-y-4">
          {k.l2 && <Field label={t("کاربرد", "Use")}>
            <Select value={mode} onChange={(v) => setMode(v as "ip")} options={[
              { value: "ip", label: t("IP روی خود تونل", "An IP on the tunnel itself") },
              { value: "bridge", label: t("عضو بریج (LAN مشترک)", "Bridge member (shared LAN)") },
            ]} />
          </Field>}
          {bridged ? <Field label={t("بریج", "Bridge")} hint={t("مراقب باشید هر دو LAN یک DHCP سرور نداشته باشند.", "Make sure the two LANs do not both run a DHCP server.")}><Select value={bridge} onChange={setBridge} options={bridges.map((b) => b.name)} /></Field>
            : <Field label={t("آدرس‌های IP", "IP addresses")} hint={kind === "6to4" ? t("آدرس IPv6 این طرف، مثلاً 2001:db8:1::2/64", "This side's IPv6 address, e.g. 2001:db8:1::2/64") : t("با کاما جدا کنید؛ مثلاً 172.31.0.1/30 و آن طرف 172.31.0.2/30", "comma separated; e.g. 172.31.0.1/30 and the other side 172.31.0.2/30")}>
              <TextInput value={addrs} placeholder={kind === "6to4" ? "2001:db8:1::2/64" : "172.31.0.1/30"} onChange={setAddrs} />
            </Field>}
          {ifc && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("بسته‌های این تونل از IP آن طرف خودکار در فایروال پذیرفته می‌شوند. روی میکروتیک آن طرف:", "Packets of this tunnel from the other side's IP are accepted by the firewall automatically. On a MikroTik at the other end:")}
            <pre className="mono ltr mt-1 whitespace-pre-wrap text-left">{mikrotikCmd(k, nm, { remote, local, tunnel_id: tid }, keepalive)}</pre>
            {k.l2 && keepalive > 0 && <div>{t("اگر آن طرف keepalive ندارد (مثلاً لینوکس)، این‌جا keepalive را 0 کنید؛ وگرنه لینک بالا نمی‌آید.", "If the other end sends no keepalives (e.g. Linux), set keepalive to 0 here, or the link stays down.")}</div>}
          </div>
        </div>
      </div>
    </Modal>
  );
}

function TunnelCard({ ifc, cfg, live }: { ifc: Iface; cfg: Config; live?: RzLive }) {
  const { edit } = useConfig();
  const [editing, setEditing] = useState(false);
  const tn = ifc.tunnel || {};
  const k = kindOf(ifc.type);
  const br = cfg.interfaces.find((b) => b.type === "bridge" && (b.members || []).includes(ifc.name));
  let chip;
  if (ifc.disabled) chip = <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>;
  else if (!live?.up) chip = <Chip tone="off">{k.l2 && live?.active === "failed" ? t("خطا", "failed") : t("اعمال نشده", "not applied")}</Chip>;
  else if (k.l2 && live.oper === "down") chip = <Chip tone="talk">{t("بدون پاسخ از آن طرف", "no reply from the other end")}</Chip>;
  else chip = <Chip tone="idle">{k.l2 ? t("وصل", "up") : t("ساخته شده", "created")}</Chip>;
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="link" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{ifc.name}</Ltr></h2>
        <Chip tone="off">{k.label}</Chip>
        {chip}
        <div className="ms-auto flex gap-2">
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`تونل ${ifc.name} حذف شود؟`, `Delete tunnel ${ifc.name}?`)} onConfirm={() => edit((c) => {
            removeIface(c, ifc.name);
            for (const b of c.interfaces) if (b.type === "bridge") b.members = (b.members || []).filter((m) => m !== ifc.name);
          }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آن طرف", "Remote")}><Ltr className="mono">{tn.remote || t("هر جا (رله)", "any (relay)")}</Ltr></Info>
        {k.l2 && <Info label="Tunnel ID"><Ltr className="mono">{tn.tunnel_id || 0}</Ltr></Info>}
        {!!tn.key && <Info label={t("کلید", "Key")}><Ltr className="mono">{tn.key}</Ltr></Info>}
        <Info label={br ? t("عضو بریج", "Bridge member of") : t("آدرس", "Address")}><Ltr className="mono">{br ? br.name : ifc.addresses?.join(", ") || "—"}</Ltr></Info>
        {live?.up && <Info label={t("دریافت / ارسال", "Received / sent")}><Ltr className="mono">{fmtBytes(live.rx_bytes)} / {fmtBytes(live.tx_bytes)}</Ltr></Info>}
      </div>
      {editing && <TunnelDialog ifc={ifc} onClose={() => setEditing(false)} />}
    </div>
  );
}
