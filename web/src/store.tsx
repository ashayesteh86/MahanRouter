import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, ApiError, clone, t } from "./lib";
import type { Config, Status } from "./types";
import { useToast } from "./ui";

// The panel edits the candidate configuration. Every edit is saved to the
// router at once (PUT candidate.json); nothing changes on the device until
// the user commits on the Changes page. This is the same model as mrctl.

interface Ctx {
  cfg: Config | null;
  problems: string[];
  status: Status | null;
  loading: boolean;
  reload: () => Promise<void>;
  /** Apply fn to a copy of the candidate and save it. Returns false if saving failed. */
  edit: (fn: (c: Config) => void, okText?: string) => Promise<boolean>;
  refreshStatus: () => Promise<void>;
}

const ConfigCtx = createContext<Ctx>(null as unknown as Ctx);
export const useConfig = () => useContext(ConfigCtx);

export function ConfigProvider({ children }: { children: ReactNode }) {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const toast = useToast();
  const saving = useRef(Promise.resolve(true));
  const cfgRef = useRef<Config | null>(null);
  const put = (c: Config | null) => { cfgRef.current = c; setCfg(c); };

  const reload = useCallback(async () => {
    try {
      const r = await api<{ config: Config; problems?: string[] }>("/api/v1/config/candidate.json");
      put(r.config);
      setProblems(r.problems || []);
    } catch (e) {
      toast(t("خواندن کانفیگ ناموفق بود: ", "Could not read the configuration: ") + (e as Error).message, "error");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const refreshStatus = useCallback(async () => {
    try { setStatus(await api<Status>("/api/v1/status")); } catch { /* shown elsewhere */ }
  }, []);

  useEffect(() => {
    reload();
    refreshStatus();
    const id = setInterval(() => { if (!document.hidden) refreshStatus(); }, 4000);
    return () => clearInterval(id);
  }, [reload, refreshStatus]);

  const edit = useCallback(async (fn: (c: Config) => void, okText?: string) => {
    // edits are serialised so two quick clicks cannot overwrite each other
    const run = async () => {
      if (!cfgRef.current) return false;
      const next = clone(cfgRef.current);
      fn(next);
      try {
        const r = await api<{ valid: boolean; problems?: string[] }>("/api/v1/config/candidate.json", { method: "PUT", body: next });
        put(next);
        setProblems(r.problems || []);
        refreshStatus();
        if (okText) toast(okText);
        return true;
      } catch (e) {
        const err = e as ApiError;
        toast(t("ذخیره نشد: ", "Not saved: ") + err.message, "error");
        return false;
      }
    };
    saving.current = saving.current.then(run, run);
    return saving.current;
  }, [toast, refreshStatus]);

  return <ConfigCtx.Provider value={{ cfg, problems, status, loading, reload, edit, refreshStatus }}>{children}</ConfigCtx.Provider>;
}

/** Polls a GET endpoint every `ms` while the page is visible. */
export function usePoll<T>(path: string, ms: number): [T | null, () => void, string | null] {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const tick = useCallback(async () => {
    try { setData(await api<T>(path)); setErr(null); } catch (e) { setErr((e as Error).message); }
  }, [path]);
  useEffect(() => {
    tick();
    if (!ms) return;
    const id = setInterval(() => { if (!document.hidden) tick(); }, ms);
    return () => clearInterval(id);
  }, [tick, ms]);
  return [data, tick, err];
}

/** Interface names defined in the candidate, plus list names, for pickers. */
export function useNames() {
  const { cfg } = useConfig();
  const ifaces = (cfg?.interfaces || []).map((i) => i.name);
  const lists = Object.keys(cfg?.interface_lists || {});
  const addrLists = Object.keys(cfg?.firewall?.address_lists || {});
  const dynLists = [...new Set([...(cfg?.firewall?.filter || []), ...(cfg?.firewall?.nat || [])].map((r) => r.address_list).filter(Boolean) as string[])];
  return { ifaces, lists, addrLists: [...new Set([...addrLists, ...dynLists])] };
}
