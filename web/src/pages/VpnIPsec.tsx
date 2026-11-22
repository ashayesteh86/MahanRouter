import { useState } from "react";
import { api, fmtBytes, fmtDuration, t } from "../lib";
import { useConfig, usePoll } from "../store";
import type { Config, IPsecTunnel } from "../types";
import { Check, Chip, ConfirmButton, Empty, Field, Icon, ListInput, Ltr, Modal, Select, TextInput, useToast } from "../ui";
import { Info, n2ip, parseCidr } from "./Vpn";

// IPsec tab: site-to-site tunnels (strongSwan). A tunnel joins this
// router's subnets to another site's subnets; there is no interface. The
// firewall rules it needs (IKE, ESP, traffic between the sites, no NAT)
// are made by the router itself.

interface Child { name: string; state: string; local_ts: string; remote_ts: string; bytes_in: number; bytes_out: number; esp?: string }
interface Live { name: string; state: "up" | "connecting" | "down"; ike_state?: string; remote_host?: string; established?: number; ike?: string; nat?: boolean; children: Child[] }

const PFS = ["", "none", "modp1024", "modp1536", "modp2048", "modp3072", "modp4096", "ecp256", "ecp384"];
const ipRe = /^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;
const nameRe = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
const idRe = /^[A-Za-z0-9@._:-]{1,128}$/;
const propRe = /^[a-z0-9]+(-[a-z0-9]+)*(,[a-z0-9]+(-[a-z0-9]+)*)*$/;
const isNet = (s: string) => { const p = parseCidr(s); return (!!p && p.len > 0 && n2ip(p.net) === p.ip) || /^[0-9a-fA-F:]+::?\/\d{1,3}$/.test(s); };

function lanSubnets(c: Config): string[] {
  const out: string[] = [];
  for (const n of c.interface_lists?.LAN || []) {
    for (const a of c.interfaces.find((i) => i.name === n)?.addresses || []) {
      const p = parseCidr(a);
      if (p) out.push(`${n2ip(p.net)}/${p.len}`);
    }
  }
  return [...new Set(out)];
}

function randomKey(): string {
  const b = new Uint8Array(24);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/[+/=]/g, (ch) => ({ "+": "A", "/": "b", "=": "" }[ch] as string));
}

export default function IPsecTab() {
  const { cfg } = useConfig();
  const [live] = usePoll<{ tunnels: Live[]; log: string[] }>("/api/v1/ipsec/status", 4000);
  const [adding, setAdding] = useState(false);
  const [showLog, setShowLog] = useState(false);
  if (!cfg) return null;
  const tunnels = cfg.ipsec?.tunnels || [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="card-title">{t("IPsec بین دو شعبه (site-to-site)", "IPsec site-to-site")}</h2>
          <p className="text-sm text-ink-3">{t("شبکه‌ی این روتر را با IPsec به شبکه‌ی یک روتر یا فایروال دیگر وصل می‌کند: میکروتیک، فورتی‌گیت، سیسکو، pfSense یا یک Mahan Router دیگر. قوانین فایروال لازم را خود روتر می‌سازد.", "Joins this router's network to the network behind another router or firewall with IPsec: MikroTik, FortiGate, Cisco, pfSense or another Mahan Router. The router makes the firewall rules it needs itself.")}</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setAdding(true)}><Icon name="plus" className="size-4" />{t("تونل جدید", "New tunnel")}</button>
      </div>
      {!tunnels.length && <div className="card"><Empty icon="lock" title={t("هنوز تونلی ساخته نشده", "No tunnel yet")}>{t("دو طرف باید کلید مشترک یکسان و شبکه‌های قرینه داشته باشند: «شبکه‌های این طرف» اینجا = «شبکه‌های آن طرف» روی روتر مقابل.", "Both ends need the same shared key and mirrored subnets: the local subnets here are the remote subnets on the other router.")}</Empty></div>}
      {tunnels.map((x) => <TunnelCard key={x.name} tun={x} live={(live?.tunnels || []).find((l) => l.name === x.name)} />)}
      {tunnels.length > 0 && (
        <div className="card p-4">
          <button className="btn btn-sm" onClick={() => setShowLog(!showLog)}><Icon name="list" className="size-4" />{showLog ? t("بستن گزارش", "Hide log") : t("گزارش IPsec", "IPsec log")}</button>
          {showLog && <pre className="mono ltr mt-3 max-h-72 overflow-auto whitespace-pre-wrap text-left text-xs text-ink-2" dir="ltr">{(live?.log || []).join("\n") || "—"}</pre>}
        </div>
      )}
      {adding && <TunnelDialog onClose={() => setAdding(false)} />}
    </div>
  );
}

function TunnelDialog({ tun, onClose }: { tun?: IPsecTunnel; onClose: () => void }) {
  const { cfg, edit } = useConfig();
  const all = cfg?.ipsec?.tunnels || [];
  const [name, setName] = useState(tun?.name || "");
  const [remote, setRemote] = useState(tun?.remote || "");
  const [ver, setVer] = useState(String(tun?.ike_version || 2));
  const [psk, setPsk] = useState(tun?.psk || "");
  const [loc, setLoc] = useState<string[]>(tun?.local_subnets || (cfg ? lanSubnets(cfg) : []));
  const [rem, setRem] = useState<string[]>(tun?.remote_subnets || []);
  const [localID, setLocalID] = useState(tun?.local_id || "");
  const [remoteID, setRemoteID] = useState(tun?.remote_id || "");
  const [local, setLocal] = useState(tun?.local || "");
  const [pfs, setPfs] = useState(tun?.pfs || "");
  const [ike, setIke] = useState(tun?.ike_proposals || "");
  const [esp, setEsp] = useState(tun?.esp_proposals || "");
  const [passive, setPassive] = useState(!!tun?.passive);
  const [aggr, setAggr] = useState(!!tun?.aggressive);
  const [allowRouter, setAllowRouter] = useState(!!tun?.allow_router);
  const [disabled, setDisabled] = useState(!!tun?.disabled);
  const [adv, setAdv] = useState(!!(tun && (tun.local_id || tun.remote_id || tun.local || tun.pfs || tun.ike_proposals || tun.esp_proposals || tun.passive || tun.aggressive)));
  const [showKey, setShowKey] = useState(!tun);
  const r = remote.trim();
  const remoteIsIP = ipRe.test(r);
  const needID = !!r && !remoteIsIP;
  const problems: string[] = [];
  if (!tun && (!/^[a-z][a-z0-9-]{0,23}$/.test(name) || all.some((x) => x.name === name))) problems.push(t("نام: حروف کوچک انگلیسی، عدد و خط تیره؛ تکراری نباشد", "Name: lower-case letters, digits and -; not already used"));
  if (r && !remoteIsIP && !nameRe.test(r)) problems.push(t("آدرس آن طرف باید IP یا نام دامنه باشد", "The remote must be an IP address or a DNS name"));
  if (needID && !remoteID) problems.push(t("وقتی آدرس آن طرف نام دامنه است، شناسه‌ی آن طرف لازم است", "With a DNS name as remote, the remote ID is required"));
  if (psk.length < 8 || /["\\]/.test(psk)) problems.push(t("کلید مشترک حداقل ۸ حرف، بدون \" و \\", "Shared key: at least 8 characters, no \" or \\"));
  if (!loc.length || !loc.every(isNet)) problems.push(t("شبکه‌های این طرف: آدرس شبکه مثل 192.168.88.0/24", "Local subnets: network addresses such as 192.168.88.0/24"));
  if (!rem.length || !rem.every(isNet)) problems.push(t("شبکه‌های آن طرف: آدرس شبکه مثل 10.10.0.0/24", "Remote subnets: network addresses such as 10.10.0.0/24"));
  if ((localID && !idRe.test(localID)) || (remoteID && !idRe.test(remoteID))) problems.push(t("شناسه فقط حرف، عدد و @ . _ : -", "IDs may hold letters, digits and @ . _ : - only"));
  if (local && !ipRe.test(local)) problems.push(t("IP این روتر درست نیست", "This router's IP is not valid"));
  if ((ike && !propRe.test(ike)) || (esp && !propRe.test(esp))) problems.push(t("الگوریتم‌ها به شکل aes256-sha256-modp2048", "Proposals look like aes256-sha256-modp2048"));
  const save = async () => {
    const v: IPsecTunnel = {
      name: tun?.name || name, remote: r || undefined, ike_version: ver === "1" ? 1 : undefined, psk,
      local_subnets: loc, remote_subnets: rem, local_id: localID || undefined, remote_id: remoteID || undefined, local: local || undefined,
      pfs: pfs || undefined, ike_proposals: ike || undefined, esp_proposals: esp || undefined,
      passive: passive && r ? true : undefined, aggressive: aggr && ver === "1" ? true : undefined,
      allow_router: allowRouter || undefined, disabled: disabled || undefined, comment: tun?.comment,
    };
    const ok = await edit((c) => {
      c.ipsec = c.ipsec || {};
      const list = (c.ipsec.tunnels = c.ipsec.tunnels || []);
      const i = list.findIndex((x) => x.name === v.name);
      if (i >= 0) list[i] = v; else list.push(v);
    }, tun ? t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)") : t("تونل ساخته شد (هنوز اعمال نشده)", "Tunnel created (not applied yet)"));
    if (ok) onClose();
  };
  const mt = `/ip ipsec peer add name=mahan address=<THIS-ROUTER>/32 exchange-mode=${ver === "1" ? (aggr ? "aggressive" : "main") : "ike2"}
/ip ipsec identity add peer=mahan secret="${psk ? "********" : "<KEY>"}"
${rem.flatMap((rs) => loc.map((ls) => `/ip ipsec policy add peer=mahan tunnel=yes src-address=${rs} dst-address=${ls}`)).join("\n") || "/ip ipsec policy add peer=mahan tunnel=yes src-address=<REMOTE-NET> dst-address=<LOCAL-NET>"}
/ip firewall nat add chain=srcnat action=accept src-address=${rem[0] || "<REMOTE-NET>"} dst-address=${loc[0] || "<LOCAL-NET>"} place-before=0`;
  return (
    <Modal open wide onClose={onClose} title={tun ? `${t("تنظیمات تونل", "Tunnel settings")} ${tun.name}` : t("تونل IPsec جدید", "New IPsec tunnel")}
      footer={<><button className="btn" onClick={onClose}>{t("انصراف", "Cancel")}</button><button className="btn btn-primary" disabled={problems.length > 0} onClick={save}>{tun ? t("ذخیره", "Save") : t("ساختن", "Create")}</button></>}>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          {!tun && <Field label={t("نام تونل", "Tunnel name")} hint="hq, branch-dubai"><TextInput value={name} onChange={(v) => setName(v.toLowerCase())} /></Field>}
          <Field label={t("آدرس روتر آن طرف", "Other router's address")} hint={t("IP یا نام دامنه. خالی = آن طرف IP ثابت ندارد و فقط خودش وصل می‌شود.", "IP or DNS name. Empty = the other side has no fixed address and only it connects.")}><TextInput value={remote} placeholder="203.0.113.10" onChange={setRemote} /></Field>
          <Field label={t("نسخه‌ی IKE", "IKE version")}>
            <Select value={ver} onChange={setVer} options={[{ value: "2", label: t("IKEv2 (پیشنهادی)", "IKEv2 (recommended)") }, { value: "1", label: t("IKEv1 (دستگاه‌های قدیمی)", "IKEv1 (old devices)") }]} />
          </Field>
          <div>
            <span className="label">{t("کلید مشترک (PSK)", "Shared key (PSK)")}</span>
            <div className="flex gap-2">
              <input className="input ltr flex-1 text-left" dir="ltr" type={showKey ? "text" : "password"} value={psk} onChange={(e) => setPsk(e.target.value)} />
              <button type="button" className="btn btn-sm" onClick={() => setShowKey(!showKey)}>{showKey ? t("پنهان", "Hide") : t("نمایش", "Show")}</button>
              <button type="button" className="btn btn-sm" onClick={() => { setPsk(randomKey()); setShowKey(true); }}><Icon name="refresh" className="size-4" />{t("ساختن", "Make")}</button>
            </div>
            <p className="mt-1 text-xs text-ink-3">{t("همین کلید باید روی روتر آن طرف هم باشد.", "The same key must be set on the other router.")}</p>
          </div>
          <Field label={t("شبکه‌های این طرف", "Local subnets")} hint={t("هر خط یک شبکه", "one network per line")}><ListInput value={loc} onChange={setLoc} placeholder="192.168.88.0/24" rows={2} /></Field>
          <Field label={t("شبکه‌های آن طرف", "Remote subnets")} hint={t("هر خط یک شبکه؛ نباید با شبکه‌های این طرف هم‌پوشانی داشته باشد", "one network per line; must not overlap the local subnets")}><ListInput value={rem} onChange={setRem} placeholder="10.10.0.0/24" rows={2} /></Field>
        </div>
        <div className="space-y-4">
          <Check label={t("شبکه‌ی آن طرف به خود روتر هم دسترسی داشته باشد", "The remote site may reach the router itself")} checked={allowRouter} onChange={setAllowRouter} hint={t("پنل، DNS و ping روتر. دسترسی به دستگاه‌های شبکه‌ی این طرف همیشه باز است.", "The router's panel, DNS and ping. Devices in the local subnets are always reachable.")} />
          {tun && <Check label={t("موقتاً غیرفعال", "Temporarily disabled")} checked={disabled} onChange={setDisabled} />}
          <button type="button" className="btn btn-sm" onClick={() => setAdv(!adv)}><Icon name="settings" className="size-4" />{adv ? t("بستن تنظیمات پیشرفته", "Hide advanced settings") : t("تنظیمات پیشرفته", "Advanced settings")}</button>
          {adv && (
            <div className="space-y-4 rounded-lg border border-line p-3">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("شناسه‌ی این طرف", "Local ID")} hint={t("خالی = IP", "empty = the IP")}><TextInput value={localID} placeholder="branch.example.com" onChange={setLocalID} /></Field>
                <Field label={t("شناسه‌ی آن طرف", "Remote ID")} hint={t("خالی = IP آن طرف", "empty = its IP")}><TextInput value={remoteID} placeholder="hq.example.com" onChange={setRemoteID} /></Field>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="PFS" hint={t("در میکروتیک پیش‌فرض modp1024 است. در IKEv1 باید همان گروهِ آن طرف انتخاب شود.", "MikroTik's default is modp1024. With IKEv1 pick the same group as the other side.")}>
                  <Select value={pfs} onChange={setPfs} ltr options={PFS.map((g) => ({ value: g, label: g === "" ? t("هر دو حالت پذیرفته شود", "accept either") : g === "none" ? t("بدون PFS", "no PFS") : g }))} />
                </Field>
                <Field label={t("IP این روتر", "This router's IP")} hint={t("خالی = خودکار", "empty = automatic")}><TextInput value={local} onChange={setLocal} /></Field>
              </div>
              <Field label={t("الگوریتم‌های IKE (فاز ۱)", "IKE proposals (phase 1)")} hint={t("خالی = فهرست گسترده‌ی پیش‌فرض", "empty = the wide built-in list")}><TextInput value={ike} placeholder="aes256-sha256-modp2048" onChange={(v) => setIke(v.toLowerCase().replace(/\s+/g, ""))} /></Field>
              <Field label={t("الگوریتم‌های ESP (فاز ۲)", "ESP proposals (phase 2)")} hint={t("اگر پر شود، PFS هم از همین‌جا خوانده می‌شود", "when set, PFS comes from here too")}><TextInput value={esp} placeholder="aes256-sha256-modp2048" onChange={(v) => setEsp(v.toLowerCase().replace(/\s+/g, ""))} /></Field>
              {!!r && <Check label={t("این روتر شروع نکند، فقط جواب بدهد", "Do not start the tunnel, only answer")} checked={passive} onChange={setPassive} />}
              {ver === "1" && <Check label={t("حالت Aggressive", "Aggressive mode")} checked={aggr} onChange={setAggr} hint={t("ضعیف‌تر از Main است؛ فقط اگر آن طرف لازم دارد.", "Weaker than main mode; only when the other side needs it.")} />}
            </div>
          )}
          <div className="rounded-md bg-surface-2 p-3 text-xs leading-6 text-ink-2">
            {t("روی میکروتیکِ آن طرف (شبکه‌ها قرینه‌ی اینجا):", "On a MikroTik at the other end (subnets mirrored):")}
            <pre className="mono ltr mt-1 whitespace-pre-wrap text-left" dir="ltr">{mt}</pre>
            {t("روی یک Mahan Router دیگر همین فرم را با شبکه‌های جابه‌جا و همین کلید پر کنید.", "On another Mahan Router fill this form with the subnets swapped and the same key.")}
          </div>
          {problems.length > 0 && <ul className="list-disc ps-5 text-xs text-talk">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
        </div>
      </div>
    </Modal>
  );
}

function TunnelCard({ tun, live }: { tun: IPsecTunnel; live?: Live }) {
  const { edit } = useConfig();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const chip = tun.disabled ? <Chip tone="talk">{t("غیرفعال", "disabled")}</Chip>
    : !live ? <Chip tone="off">{t("اعمال نشده", "not applied")}</Chip>
      : live.state === "up" ? <Chip tone="idle">{t("وصل", "connected")}</Chip>
        : live.state === "connecting" ? <Chip tone="ring">{t("در حال اتصال…", "connecting…")}</Chip>
          : <Chip tone="off">{tun.remote && !tun.passive ? t("قطع", "down") : t("منتظر آن طرف", "waiting for the other side")}</Chip>;
  const restart = async () => {
    try { await api("/api/v1/ipsec/restart", { method: "POST", body: { name: tun.name } }); toast(t("تونل دوباره شروع شد", "Tunnel restarted")); }
    catch (x) { toast((x as Error).message, "error"); }
  };
  const pairs = tun.local_subnets.flatMap((l) => tun.remote_subnets.map((r) => ({ l, r })));
  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        <Icon name="lock" className="size-5 text-accent" />
        <h2 className="card-title"><Ltr>{tun.name}</Ltr></h2>
        {chip}
        <div className="ms-auto flex gap-2">
          {live && !tun.disabled && <button className="icon-btn" title={t("قطع و وصل دوباره", "Reconnect")} onClick={restart}><Icon name="refresh" className="size-4" /></button>}
          <button className="icon-btn" title={t("تنظیمات", "Settings")} onClick={() => setEditing(true)}><Icon name="settings" className="size-4" /></button>
          <ConfirmButton className="icon-btn text-talk" question={t(`تونل ${tun.name} حذف شود؟`, `Delete tunnel ${tun.name}?`)} onConfirm={() => edit((c) => {
            if (!c.ipsec) return;
            c.ipsec.tunnels = (c.ipsec.tunnels || []).filter((x) => x.name !== tun.name);
            if (!c.ipsec.tunnels.length) c.ipsec = undefined;
          }, t("حذف شد (هنوز اعمال نشده)", "Deleted (not applied yet)"))}><Icon name="trash" className="size-4" /></ConfirmButton>
        </div>
      </div>
      <div className="grid gap-x-6 gap-y-2 px-5 py-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
        <Info label={t("آن طرف", "Remote")}><Ltr className="mono">{tun.remote || live?.remote_host || t("هر آدرسی", "any address")}</Ltr></Info>
        <Info label="IKE"><Ltr className="mono">IKEv{tun.ike_version || 2}{tun.aggressive ? " aggressive" : ""}{live?.nat ? " · NAT-T" : ""}</Ltr></Info>
        <Info label={t("نقش", "Role")}>{tun.remote && !tun.passive ? t("شروع‌کننده", "starts the tunnel") : t("فقط جواب می‌دهد", "answers only")}</Info>
        {live?.state === "up" && <Info label={t("مدت اتصال", "Connected for")}>{fmtDuration(live.established)}</Info>}
        {live?.ike && <Info label={t("رمزنگاری IKE", "IKE encryption")}><Ltr className="mono text-xs">{live.ike}</Ltr></Info>}
      </div>
      {live?.state === "connecting" && live.ike_state === "ESTABLISHED" && (
        <p className="border-t border-line px-5 py-2 text-xs text-ring">{t("دو روتر همدیگر را شناختند ولی روی شبکه‌ها یا رمزنگاری فاز ۲ توافق نشد. شبکه‌های دو طرف باید قرینه باشند و PFS یکسان باشد (تنظیمات پیشرفته).", "The routers accepted each other but did not agree on the subnets or phase 2 encryption. The subnets must mirror each other and PFS must be the same on both ends (advanced settings).")}</p>
      )}
      <div className="overflow-x-auto border-t border-line">
        <table className="w-full text-sm">
          <thead className="text-xs text-ink-3"><tr>{[t("شبکه‌ی این طرف", "Local subnet"), t("شبکه‌ی آن طرف", "Remote subnet"), t("وضعیت", "State"), t("دریافت / ارسال", "Received / sent")].map((h) => <th key={h} className="px-4 py-2 text-start font-normal">{h}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">
            {pairs.map((p) => {
              const ch = live?.children.find((c) => c.local_ts === p.l && c.remote_ts === p.r && c.state === "INSTALLED") || live?.children.find((c) => c.local_ts === p.l && c.remote_ts === p.r);
              return (
                <tr key={p.l + p.r}>
                  <td className="px-4 py-2"><Ltr className="mono">{p.l}</Ltr></td>
                  <td className="px-4 py-2"><Ltr className="mono">{p.r}</Ltr></td>
                  <td className="px-4 py-2">{ch?.state === "INSTALLED" ? <Chip tone="idle">{t("کلید دارد", "keys installed")}</Chip> : ch ? <Chip tone="ring"><Ltr>{ch.state.toLowerCase()}</Ltr></Chip> : <Chip tone="off">—</Chip>}</td>
                  <td className="px-4 py-2"><Ltr className="mono">{ch ? `${fmtBytes(ch.bytes_in)} / ${fmtBytes(ch.bytes_out)}` : "—"}</Ltr></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {editing && <TunnelDialog tun={tun} onClose={() => setEditing(false)} />}
    </div>
  );
}
