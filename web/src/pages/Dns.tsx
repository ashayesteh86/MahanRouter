import { useEffect, useState } from "react";
import { clone, t } from "../lib";
import { useConfig, useNames } from "../store";
import type { DNS } from "../types";
import { Check, Field, Icon, ListInput, Ltr, PageHead, TextInput } from "../ui";

export default function Dns() {
  const { cfg, edit } = useConfig();
  const { ifaces } = useNames();
  const [d, setD] = useState<DNS>({});
  const [hosts, setHosts] = useState<[string, string][]>([]);
  useEffect(() => {
    if (!cfg) return;
    setD(clone(cfg.dns || {}));
    setHosts(Object.entries(cfg.dns?.static_hosts || {}));
  }, [cfg]);
  if (!cfg) return null;
  const set = (p: Partial<DNS>) => setD((x) => ({ ...x, ...p }));
  const save = () => edit((c) => {
    const sh = Object.fromEntries(hosts.filter(([k, v]) => k && v));
    c.dns = JSON.parse(JSON.stringify({ ...d, static_hosts: Object.keys(sh).length ? sh : undefined }, (_, v) => (v === "" ? undefined : v)));
  }, t("ذخیره شد (هنوز اعمال نشده)", "Saved (not applied yet)"));
  return (
    <div className="space-y-5">
      <PageHead title="DNS" sub={t("Unbound: کش و فوروارد DNS برای شبکه‌ی داخلی", "Unbound: caching DNS forwarder for the LAN")}>
        <button className="btn btn-primary btn-sm" onClick={save}><Icon name="check" className="size-4" />{t("ذخیره", "Save")}</button>
      </PageHead>
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="card space-y-4 p-5">
          <Check label={t("DNS سرور روتر فعال باشد", "Run the DNS server on the router")} checked={!!d.enabled} onChange={(v) => set({ enabled: v })} />
          <Field label={t("سرورهای بالادست (forwarders)", "Upstream servers (forwarders)")} hint={t("خالی = پرس‌وجوی مستقیم از root سرورها", "Empty = resolve from the root servers")}><ListInput value={d.forwarders} onChange={(v) => set({ forwarders: v })} /></Field>
          <Field label={t("گوش دادن روی اینترفیس‌ها", "Listen on interfaces")}>
            <div className="flex flex-wrap gap-2">
              {ifaces.map((n) => (
                <label key={n} className="flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-1 text-sm">
                  <input type="checkbox" className="accent-[var(--accent)]" checked={!!d.listen_on?.includes(n)} onChange={(e) => set({ listen_on: e.target.checked ? [...(d.listen_on || []), n] : (d.listen_on || []).filter((x) => x !== n) })} /><Ltr>{n}</Ltr>
                </label>
              ))}
            </div>
          </Field>
          <Field label={t("اجازه به شبکه‌ها", "Allow from networks")} hint="192.168.88.0/24"><ListInput value={d.allow_from} onChange={(v) => set({ allow_from: v })} /></Field>
          <Field label={t("حجم کش (مگابایت)", "Cache size (MB)")}><TextInput type="number" value={d.cache_size_mb} onChange={(v) => set({ cache_size_mb: v ? Number(v) : undefined })} /></Field>
        </div>
        <div className="card p-5">
          <h2 className="card-title mb-1">{t("رکوردهای ثابت", "Static records")}</h2>
          <p className="mb-3 text-xs text-ink-3">{t("نام → آدرس، مثل /ip dns static در میکروتیک", "Name → address, like /ip dns static in RouterOS")}</p>
          <div className="space-y-2">
            {hosts.map(([k, v], i) => (
              <div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-2">
                <TextInput value={k} placeholder="nas.lan" onChange={(x) => setHosts(hosts.map((h, j) => (j === i ? [x, h[1]] : h)))} />
                <TextInput value={v} placeholder="192.168.88.20" onChange={(x) => setHosts(hosts.map((h, j) => (j === i ? [h[0], x] : h)))} />
                <button className="icon-btn text-talk" onClick={() => setHosts(hosts.filter((_, j) => j !== i))}><Icon name="trash" className="size-4" /></button>
              </div>
            ))}
            <button className="btn btn-sm" onClick={() => setHosts([...hosts, ["", ""]])}><Icon name="plus" className="size-4" />{t("رکورد جدید", "Add record")}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
