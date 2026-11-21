<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import Treemap from "../components/Treemap.svelte";
  import UsageBar from "../components/UsageBar.svelte";
  import * as api from "../lib/api";
  import { num, pct, size, when } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
  import { act, report } from "../lib/report.svelte";
  import type { CleanupTarget, SpaceNode, SpaceScan, Volume } from "../lib/types";

  let { elevated }: { elevated: boolean } = $props();

  let tab = $state<"clean" | "space">("clean");
  let drives = $state<Volume[]>([]);
  let targets = $state<CleanupTarget[]>([]);
  let checked = $state<Record<string, boolean>>({});
  let measuring = $state(false);
  let status = $state(t("storage.looking"));
  let focusKey = $state<string | null>(null);

  let root = $state("");
  let scan = $state<SpaceScan | null>(null);
  let path = $state<SpaceNode[]>([]);
  let scanning = $state(false);
  let scanStatus = $state(t("storage.chooseHint"));
  let chosenFiles = $state<Record<string, boolean>>({});
  const unlisten: (() => void)[] = [];

  async function loadDrives(): Promise<void> {
    drives = await api.volumes();
    if (!root && drives.length) root = drives[0].mount;
  }

  async function measure(): Promise<void> {
    if (measuring) return;
    measuring = true;
    status = t("storage.looking");
    try {
      targets = await api.cleanupMeasure();
      checked = Object.fromEntries(targets.map((t) => [t.key, t.selected && t.size > 0 && (!t.admin || elevated)]));
      const total = targets.filter((t) => !t.admin || elevated).reduce((a, t) => a + t.size, 0);
      status = t("storage.measured", { size: size(total), count: targets.length });
    } catch (e) {
      status = t("storage.measureFailed", { error: String(e) });
    } finally {
      measuring = false;
    }
  }

  onMount(async () => {
    unlisten.push(await api.onEvent<{ text: string }>("cleanup", (p) => (status = p.text)));
    unlisten.push(await api.onEvent<{ text: string }>("space", (p) => (scanStatus = p.text)));
    await loadDrives();
    await measure();
  });
  onDestroy(() => {
    for (const stop of unlisten) stop();
    if (scanning) void api.spaceCancel();
  });

  // Groups in the order the backend lists them (their names arrive translated).
  const grouped = $derived([...new Set(targets.map((x) => x.group))]
    .map((g) => [g, targets.filter((x) => x.group === g).sort((a, b) => b.size - a.size)] as const));
  const usable = (t: CleanupTarget) => t.size > 0 && (!t.admin || elevated);
  const chosen = $derived(targets.filter((t) => checked[t.key] && usable(t)));
  const chosenTotal = $derived(chosen.reduce((a, t) => a + t.size, 0));
  const focused = $derived(targets.find((t) => t.key === focusKey) ?? null);

  async function clean(): Promise<void> {
    if (!chosen.length) return;
    const outcome = await act({ kind: "cleanup", keys: chosen.map((t) => t.key) });
    if (outcome && !outcome.cancelled) {
      await loadDrives();
      await measure();
    }
  }

  async function analyze(target = root): Promise<void> {
    if (!target || scanning) return;
    scanning = true;
    scanStatus = t("storage.reading", { target });
    try {
      scan = await api.spaceScan(target);
      path = [scan.root];
      chosenFiles = {};
      scanStatus = [
        t("storage.scanSummary", { files: scan.files, folders: scan.folders, size: size(scan.root.size), seconds: num(scan.seconds, 1) }),
        scan.cancelled ? t("storage.stoppedEarly") : "",
        scan.errors ? t("storage.unreadable", { count: scan.errors }) : "",
        scan.mergedBelow ? t("storage.grouped", { size: size(scan.mergedBelow, 0) }) : "",
      ].filter(Boolean).join(" · ");
    } catch (e) {
      scanStatus = t("storage.analyzeFailed", { error: String(e) });
    } finally {
      scanning = false;
    }
  }

  async function chooseFolder(): Promise<void> {
    const folder = await api.chooseFolder();
    if (folder) {
      root = folder;
      await analyze(folder);
    }
  }

  const node = $derived(path[path.length - 1] ?? null);
  const children = $derived(node ? [...node.children].sort((a, b) => b.size - a.size) : []);
  const selectedFiles = $derived(Object.keys(chosenFiles).filter((p) => chosenFiles[p]));

  async function recycle(): Promise<void> {
    if (!selectedFiles.length) return;
    const outcome = await act({ kind: "recycle", paths: selectedFiles });
    if (outcome && !outcome.cancelled && scan) {
      const gone = new Set(selectedFiles);
      scan = { ...scan, largestFiles: scan.largestFiles.filter((f) => !gone.has(f.path)) };
      chosenFiles = {};
      await loadDrives();
    }
  }
</script>

<div class="page">
  <div class="page-head"><h1>{t("page.storage")}</h1></div>
  <div class="drives">
    {#each drives.slice(0, 6) as drive (drive.mount)}
      <button class="drive" title={t("storage.analyzeDrive", { drive: drive.mount })} onclick={() => { tab = "space"; root = drive.mount; void analyze(drive.mount); }}>
        <div class="drive-head"><b>{drive.mount.replace(/\\$/, "")}</b> <span>{drive.label}</span><span class="grow"></span><span class="faint">{t("overview.free", { size: size(drive.free) })}</span></div>
        <UsageBar fraction={drive.total ? drive.used / drive.total : 0} />
        <div class="faint">{t("storage.used", { used: size(drive.used), total: size(drive.total) })} · {drive.fs}</div>
      </button>
    {/each}
  </div>

  <div class="tabs">
    <button class="chip" class:on={tab === "clean"} onclick={() => (tab = "clean")}>{t("storage.tabClean")}</button>
    <button class="chip" class:on={tab === "space"} onclick={() => (tab = "space")}>{t("storage.tabSpace")}</button>
  </div>

  {#if tab === "clean"}
    <div class="clean">
      <section class="panel junk">
        <div class="row-head"><h2>{t("storage.junk")}</h2><span class="grow"></span><button onclick={measure} disabled={measuring}>{t("storage.scanAgain")}</button></div>
        <p class="muted status">{status}</p>
        <div class="list">
          {#each grouped as [group, list] (group)}
            {@const total = list.reduce((a, t) => a + t.size, 0)}
            <div class="group"><b>{group}</b><span class="r num">{size(total)}</span><span></span></div>
            {#each list as target (target.key)}
              <label class="target" class:disabled={!usable(target)} class:focus={focusKey === target.key}
                     title="{target.description}{target.note ? `\n${target.note}` : ''}{target.admin && !elevated ? `\n${t('storage.needsAdmin')}` : ''}">
                <span class="name"><input type="checkbox" bind:checked={checked[target.key]} disabled={!usable(target)}
                       onfocus={() => (focusKey = target.key)} onclick={() => (focusKey = target.key)} /> {target.label}</span>
                <span class="r num">{size(target.size)}</span>
                <span class="r num faint">{target.files ? num(target.files) : ""}</span>
              </label>
            {/each}
          {/each}
        </div>
        {#if focused}
          <p class="muted detail selectable">{focused.description}{focused.note ? ` ${focused.note}` : ""}{focused.minAgeHours ? ` ${t("storage.minAge", { count: focused.minAgeHours })}` : ""}
            {#if focused.roots.length}<br /><span class="faint">{t("storage.location", { paths: focused.roots.slice(0, 4).join("; ") })}{focused.roots.length > 4 ? " …" : ""}</span>{/if}</p>
        {/if}
        <div class="row-head foot"><b>{chosen.length ? t("storage.selected", { size: size(chosenTotal) }) : t("storage.nothingSelected")}</b><span class="grow"></span>
          <button class="primary" disabled={!chosen.length || measuring || report.busy} onclick={clean}>{t("storage.clean")}</button></div>
      </section>

      <section class="panel deep">
        <h2>{t("storage.deeper")}</h2>
        <h3>{t("storage.componentStore")}</h3>
        <p class="muted">{t("storage.componentStoreNote")}</p>
        <div><button disabled={!elevated || report.busy} onclick={() => act({ kind: "tuning", op: "disk.component_cleanup", params: {} })}>{t("storage.componentStoreClean")}</button></div>
        <h3>{t("storage.diskCleanup")}</h3>
        <p class="muted">{t("storage.diskCleanupNote")}</p>
        <div><button onclick={() => act({ kind: "shell", op: "tool", name: "cleanmgr.exe" })}>{t("storage.diskCleanupOpen")}</button></div>
        <h3>{t("storage.settings")}</h3>
        <p class="muted">{t("storage.settingsNote")}</p>
        <div><button onclick={() => act({ kind: "shell", op: "url", url: "ms-settings:storagesense" })}>{t("storage.settingsOpen")}</button></div>
        <p class="faint">{t("storage.hibernationHint")}</p>
      </section>
    </div>
  {:else}
    <div class="space">
      <div class="controls">
        <select bind:value={root} aria-label={t("storage.driveOrFolder")}>
          {#each drives.filter((d) => !d.network) as drive (drive.mount)}<option value={drive.mount}>{drive.mount.replace(/\\$/, "")} {drive.label}</option>{/each}
          {#if root && !drives.some((d) => d.mount === root)}<option value={root}>{root}</option>{/if}
        </select>
        <button onclick={chooseFolder}>{t("storage.chooseFolder")}</button>
        <button class="primary" onclick={() => analyze()} disabled={scanning}>{t("storage.analyze")}</button>
        <button onclick={() => api.spaceCancel()} disabled={!scanning}>{t("storage.stop")}</button>
        <span class="faint scan-status" title={scanStatus}>{scanStatus}</span>
      </div>
      <div class="controls">
        <button disabled={path.length < 2} onclick={() => (path = path.slice(0, -1))}>{t("storage.up")}</button>
        <span class="muted crumbs selectable">{node?.path ?? ""}</span>
      </div>
      <div class="space-top">
        <Treemap {node} onopen={(child) => (path = [...path, child])} />
        <div class="children">
          <div class="crow head"><span>{t("storage.name")}</span><span class="r">{t("storage.size")}</span><span class="r">{t("storage.share")}</span><span class="r">{t("storage.files")}</span></div>
          {#each children as child (child.path)}
            <button class="crow" ondblclick={() => child.isDir && child.children.length && (path = [...path, child])} title={child.path}>
              <span class="ellipsis">{child.name}{child.isDir ? "\\" : ""}</span><span class="r num">{size(child.size)}</span>
              <span class="r num">{pct(node && node.size ? (child.size / node.size) * 100 : 0, 1)}</span>
              <span class="r num">{child.isDir ? num(child.files) : ""}</span>
            </button>
          {/each}
          {#if node && node.other}
            <div class="crow"><span>{t("treemap.other")}</span><span class="r num">{size(node.other)}</span><span class="r num">{pct((node.other / node.size) * 100, 1)}</span><span></span></div>
          {/if}
        </div>
      </div>
      <section class="panel files">
        <div class="row-head"><h3>{t("storage.largest")}</h3><span class="grow"></span>
          <button disabled={selectedFiles.length !== 1} onclick={() => act({ kind: "shell", op: "location", path: selectedFiles[0] })}>{t("proc.location")}</button>
          <button class="danger-outline" disabled={!selectedFiles.length || report.busy} onclick={recycle}>{t("storage.recycle")}</button></div>
        <div class="file-list">
          {#each scan?.largestFiles ?? [] as file (file.path)}
            {@const slash = file.path.lastIndexOf("\\")}
            <label class="frow"><input type="checkbox" bind:checked={chosenFiles[file.path]} />
              <span class="r num">{size(file.size)}</span><span class="ellipsis">{file.path.slice(slash + 1)}</span>
              <span class="ellipsis faint" title={file.path.slice(0, slash)}>{file.path.slice(0, slash)}</span>
              <span class="faint">{file.modifiedMs ? when(new Date(file.modifiedMs - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)) : ""}</span></label>
          {/each}
        </div>
      </section>
    </div>
  {/if}
</div>

<style>
  .drives { display: flex; gap: 10px; flex-wrap: wrap; }
  .drive { width: 280px; display: flex; flex-direction: column; gap: 6px; text-align: left; padding: 12px 14px; border-radius: 9px; border-color: var(--rule); }
  .drive:hover:not(:disabled) { border-color: var(--chart); }
  .drive-head { display: flex; gap: 6px; align-items: baseline; }
  .grow { flex: 1; }
  .tabs { display: flex; gap: 6px; }
  .clean { flex: 1; min-height: 0; display: grid; grid-template-columns: minmax(0, 3fr) minmax(320px, 2fr); gap: 12px; }
  .junk, .deep { display: flex; flex-direction: column; gap: 8px; min-height: 0; }
  .deep { overflow-y: auto; }
  .deep p { margin: 0; }
  .row-head { display: flex; align-items: center; gap: 8px; }
  .status { margin: 0; }
  .list { flex: 1; min-height: 0; overflow-y: auto; border: 1px solid var(--rule); border-radius: 7px; }
  .group, .target { display: grid; grid-template-columns: minmax(0, 1fr) 110px 90px; gap: 8px; align-items: center; padding: 0 12px; height: 28px; font-size: 13px; }
  .group { background: var(--surface2); }
  .target { padding-left: 26px; cursor: pointer; }
  .target.disabled { color: var(--ink3); }
  .target.focus { background: var(--select); }
  .name { display: flex; align-items: center; gap: 8px; }
  .name input { accent-color: var(--chart); }
  .r { text-align: right; }
  .detail { margin: 0; font-size: 13px; }
  .space { flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 10px; }
  .controls { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .scan-status { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  select { font: inherit; color: var(--ink); background: var(--surface); border: 1px solid var(--rule-strong); border-radius: 5px; padding: 4px 8px; min-width: 200px; }
  .crumbs { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .space-top { flex: 3; min-height: 0; display: grid; grid-template-columns: minmax(0, 3fr) minmax(280px, 2fr); gap: 12px; }
  .children { overflow-y: auto; background: var(--surface); border: 1px solid var(--rule); border-radius: 7px; }
  .crow { display: grid; grid-template-columns: minmax(0, 1fr) 90px 64px 80px; gap: 8px; align-items: center; width: 100%; padding: 0 10px;
          height: 26px; border: 0; border-radius: 0; background: transparent; text-align: left; font-size: 13px; }
  .crow:nth-child(even) { background: var(--surface2); }
  .crow.head { position: sticky; top: 0; background: var(--surface); font-weight: 600; font-size: 12px; color: var(--ink2); border-bottom: 1px solid var(--rule); }
  .files { flex: 2; min-height: 0; display: flex; flex-direction: column; gap: 8px; padding: 12px; }
  .file-list { flex: 1; min-height: 0; overflow-y: auto; }
  .frow { display: grid; grid-template-columns: 22px 90px minmax(160px, 1fr) minmax(0, 2fr) 130px; gap: 8px; align-items: center; height: 26px; font-size: 13px; }
  .frow input { accent-color: var(--chart); }
  .ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
