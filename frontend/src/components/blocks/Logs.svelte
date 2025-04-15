<script lang="ts">
  import { tick, onDestroy } from "svelte";
  import Tooltip from "../common/Tooltip.svelte";
  import Select from "../common/Select.svelte";
  import Button from "../common/Button.svelte";
  import { API_BASE } from "../../utils/fetcher";
  import { Clear, Filter, ScrollToBottom, Save, CircleCheck } from "../common/icons";

  const LOGS_BUFFER_LIMIT = 10000 as const;

  // Auto-refresh intervals in seconds
  const AUTOREFRESH_INTERVALS = [1, 5, 10, 30, 60];
  let autoRefresh = $state(0); // 0 means off
  let autoRefreshTimer: ReturnType<typeof setInterval> | null = null;

  // Manual polling fallback (for refresh/auto-refresh)
  async function fetchLogs() {
    try {
      const resp = await fetch(`${API_BASE}/logs`);
      if (!resp.ok) throw new Error("Failed to fetch logs");
      const data = await resp.json();
      if (Array.isArray(data)) {
        items = data;
      }
    } catch (e) {
      console.error("Failed to fetch logs via polling:", e);
    }
  }

  function onManualRefresh() {
    fetchLogs();
  }

  $effect(() => {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
      autoRefreshTimer = null;
    }
    if (autoRefresh > 0) {
      autoRefreshTimer = setInterval(fetchLogs, autoRefresh * 1000);
    }
  });

  onDestroy(() => {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  });
  const SCROLL_TO_BOTTOM_DELTA = 40 as const;
  const LINE_HEIGHT = 16 as const;
  const OVERSCAN = 20 as const;

  type LogEntry = {
    time: string;
    level: string;
    message: string;
    error?: string;
    fields?: Record<string, any>;
  };

  // Backend log level state
  let backendLogLevel: string = $state('info');
  let logLevelLoading: boolean = $state(false);
  let logLevelError: string = $state("");
  let lastBackendLogLevel: string = '';
  let logLevelInitialized: boolean = false;


  async function fetchBackendLogLevel() {
    try {
      logLevelLoading = true;
      logLevelError = "";
      const resp = await fetch(`${API_BASE}/loglevel`);
      if (resp.ok) {
        const data = await resp.json();
        if (data.level) {
          backendLogLevel = data.level;
          lastBackendLogLevel = data.level; // keep in sync
        }
      } else {
        logLevelError = "Failed to fetch log level from backend.";
      }
    } catch (e) {
      logLevelError = "Failed to fetch log level: " + (e?.message || e);
    } finally {
      logLevelLoading = false;
      logLevelInitialized = true; // Mark as initialized after first fetch
    }
  }

  async function setBackendLogLevel(level: string) {
    try {
      logLevelLoading = true;
      logLevelError = "";
      const resp = await fetch(`${API_BASE}/loglevel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ level })
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.level) {
          backendLogLevel = data.level;
          lastBackendLogLevel = data.level; // keep in sync
        }
      } else {
        logLevelError = `Failed to set log level (${resp.status})`;
        await fetchBackendLogLevel();
      }
    } catch (e) {
      logLevelError = "Failed to set log level: " + (e?.message || e);
      await fetchBackendLogLevel();
    } finally {
      logLevelLoading = false;
    }
  }

  // Fetch backend log level on mount
  $effect(() => {
    fetchBackendLogLevel();
  });

  const levels: Record<string, number> = {
    trace: -1,
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    fatal: 4,
    panic: 5,
  };

  let items: LogEntry[] = $state([]);
  let level: string = $state("trace");
  let filter: string = $state("");
  let items_filtered: LogEntry[] = $derived.by(() => {
    const f = filter?.toLowerCase() ?? "";
    return items.filter((item) => {
      if (levels[item.level] < levels[level]) return false;
      if (!f || f.length === 0) return true;
      // Check message and error (case-insensitive)
      if (item.message?.toLowerCase().includes(f) || item.error?.toLowerCase().includes(f)) return true;
      // Check fields (args), keys and all value types
      if (item.fields) {
        for (const [k, v] of Object.entries(item.fields)) {
          const keyMatch = k.toLowerCase().includes(f);
          let valStr = "";
          if (typeof v === 'string') valStr = v.toLowerCase();
          else if (typeof v === 'number' || typeof v === 'boolean') valStr = String(v).toLowerCase();
          else valStr = JSON.stringify(v).toLowerCase();
          if (keyMatch || valStr.includes(f)) return true;
        }
      }
      return false;
    });
  });

  let spacer_height = $derived(items_filtered.length * LINE_HEIGHT);
  let container: HTMLDivElement = $state(document.createElement("div"));
  let container_height = $state(0);
  let scroll_top = $state(LINE_HEIGHT / 2);
  let start = $derived(Math.max(0, Math.floor(scroll_top / LINE_HEIGHT) - OVERSCAN));
  let end = $derived(
    Math.min(
      items_filtered.length,
      Math.ceil((scroll_top + container_height) / LINE_HEIGHT) + OVERSCAN,
    ),
  );
  let visible_items = $derived(items_filtered.slice(start, end));

  function scrollTopChanges() {
    scroll_top = container?.scrollTop ?? 0;
  }

  function stickToBottom() {
    if (
      container.scrollHeight - container.offsetHeight - container.scrollTop <
      SCROLL_TO_BOTTOM_DELTA
    ) {
      scrollToBottom();
    }
  }

  function scrollToBottom() {
    container.scrollTop = container.scrollHeight;
  }

  async function clearLinesBuf() {
    try {
      await fetch(`${API_BASE}/logs/clear`, { method: 'POST' });
    } catch (e) {
      // Optionally show an error
    }
    items = [];
  }

  function saveLogs() {
    const lines = items_filtered.map(({ time, level, message, error, fields }) => {
      let line = `${time} ${level} ${message}`;
      if (error) line += `, ${error}`;
      if (fields && Object.keys(fields).length) {
        const fieldsStr = Object.entries(fields)
          .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
          .join(', ');
        line += ` | ${fieldsStr}`;
      }
      return line;
    });
    const blob = new Blob([
      lines.join("\n")
    ], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${new Date().getTime()}-mtrickle.log`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  let connect = false;
  $effect(() => {
    if (!connect && container_height > 0) {
      connect = true;
      connectToEndpoint();
    }
  });

  function connectToEndpoint() {
    console.debug("connect to logs endpoint");
    const es = new EventSource(`${API_BASE}/logs`);

    es.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      items.push(data);
      if (items.length > LOGS_BUFFER_LIMIT) {
        items.shift();
      }
      await tick();
      stickToBottom();
    };
    es.onerror = (event) => {
      console.error("Failed to fetch logs:", event);
    };
    return () => {
      es.close();
    };
  }
</script>

<div class="logs-controls">
  <div class="filter">
    <Filter size={22} opacity={0.5} />
    <input type="text" class="filter-input" placeholder="filter logs..." bind:value={filter} />
    <Select
      options={Object.keys(levels).map((item) => ({
        label: `filter: ${item}`,
        value: item,
      }))}
      bind:selected={level}
      style="width: 260px"
    />
    <Select
      options={Object.keys(levels).map((item) => ({
        label: `level: ${item}`,
        value: item,
      }))}
      bind:selected={backendLogLevel}
      disabled={logLevelLoading}
      style="width: 250px; margin-left: 1rem;"
      onValueChange={(val) => {
        if (logLevelInitialized && val && val !== lastBackendLogLevel) {
          setBackendLogLevel(val);
        }
      }}
    />
    {#if logLevelLoading}
      <span class="loglevel-spinner">⏳</span>
    {/if}
    {#if logLevelError}
      <span class="loglevel-error">{logLevelError}</span>
    {/if}
  </div>

  <div class="logs-controls-actions">
    <Tooltip value="Refresh">
      <Button onclick={onManualRefresh}>
        <CircleCheck size={22} />
      </Button>
    </Tooltip>
    <Tooltip value="Auto-refresh">
      <Select
        options={[{label: 'off', value: 0}, ...AUTOREFRESH_INTERVALS.map(i => ({label: `${i}s`, value: i}))]}
        bind:selected={autoRefresh}
        style="width: 90px"
      />
    </Tooltip>
    <Tooltip value="Save Logs">
      <Button onclick={saveLogs}>
        <Save size={22} />
      </Button>
    </Tooltip>
    <Tooltip value="Clear">
      <Button onclick={clearLinesBuf}><Clear size={22} /></Button>
    </Tooltip>
    <Tooltip value="Scroll to bottom">
      <Button onclick={scrollToBottom}><ScrollToBottom size={22} /></Button>
    </Tooltip>
  </div>
</div>

<div
  bind:this={container}
  bind:clientHeight={container_height}
  onscroll={scrollTopChanges}
  class="container"
>
  <div class="spacer" style="height: {spacer_height}px;"></div>

  {#each visible_items as item, index (index)}
    <div class="line" style="top: {(start + index) * LINE_HEIGHT + 5}px; height: {LINE_HEIGHT}px;">
      <span class="time">{item.time}</span>
      <span class={item.level}>{item.level.toLocaleUpperCase()}</span>
      {item.message}{item.error ? ", " + item.error : ""}
      {#if item.fields && Object.keys(item.fields).length}
        <span class="fields">
          {#each Object.entries(item.fields) as [k, v]}
            <span class="field"><b>{k}:</b> {typeof v === 'object' ? JSON.stringify(v) : String(v)} </span>
          {/each}
        </span>
      {/if}
    </div>
  {/each}
</div>

<style>
  .selector-caption {
    font-size: 0.8rem;
    color: var(--text-2);
    margin-bottom: 0.1rem;
    margin-left: 0.2rem;
  }
  .container {
    position: relative;
    height: 600px;
    overflow: auto;
    padding: 0.3rem 0.5rem;
    border-radius: 0.5rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
  }

  .spacer {
    position: relative;
  }

  .logs-controls {
    display: flex;
    align-items: end;
    justify-items: end;
    gap: 0.5rem;
    padding: 0.5rem 0 0.5rem 0;
    margin-bottom: 0.5rem;
  }

  .logs-controls-actions {
    display: flex;
    align-items: end;
    justify-content: end;
    gap: 0.5rem;
    width: 100%;
  }

  .filter {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background-color: var(--bg-dark-extra);
    padding: 0.5rem;
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
    width: 100%;
  }

  .filter-input {
    & {
      border: none;
      background-color: transparent;
      font-size: 1rem;
      font-weight: 400;
      font-family: var(--font);
      color: var(--text);
      top: 0.1rem;
      border-bottom: 1px solid transparent;
      width: 100%;
      position: relative;
    }

    &:focus-visible {
      outline: none;
      border-bottom: 1px solid var(--accent);
    }
  }

  .line {
    position: absolute;
    font-family: var(--font-mono);
    font-size: 0.8rem;
    white-space: nowrap;
  }
  .fields {
    margin-left: 0.5em;
    color: var(--text-2);
    font-size: 0.8em;
  }
  .field {
    margin-right: 0.5em;
  }

  .time {
    color: var(--text-2);
  }

  .trace {
    color: #e0e0e0;
  }
  .debug {
    color: #00aaff;
  }
  .info {
    color: #66bb6a;
  }
  .warn {
    color: #ffd600;
  }
  .error {
    color: #ff3d3d;
  }
  .fatal {
    color: #ff1493;
  }
  .panic {
    color: #ff4500;
  }
</style>
