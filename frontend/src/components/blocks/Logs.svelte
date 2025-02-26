<script lang="ts">
  import { onMount, tick } from "svelte";
  import { API_BASE } from "../../utils/fetcher";
  import { ScrollArea } from "bits-ui";

  import { Clear, Filter, ScrollToBottom } from "../common/icons";
  import Tooltip from "../common/Tooltip.svelte";
  import Select from "../common/Select.svelte";

  const LOGS_BUFFER_LIMIT = 1000 as const;
  const SCROLL_TO_BOTTOM_DELTA = 40 as const;

  type LogEntry = {
    time: string;
    level: string;
    message: string;
    error?: string;
  };

  const levels: Record<string, number> = {
    trace: -1,
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    fatal: 4,
    panic: 5,
  };

  let lines: LogEntry[] = $state([]);
  let filter: string = $state("");
  // TODO: save picked level in local storage
  let level: string = $state("trace");
  let filtered_lines: LogEntry[] = $state([]);
  let viewport: HTMLDivElement | undefined = $state();

  function stickToBottom() {
    if (!viewport) return;
    if (
      viewport.scrollHeight - viewport.offsetHeight - viewport.scrollTop <
      SCROLL_TO_BOTTOM_DELTA
    ) {
      scrollToBottom();
    }
  }

  function scrollToBottom() {
    if (!viewport) return;
    viewport.scrollTop = viewport.scrollHeight;
  }

  function clearLinesBuf() {
    lines = [];
    filtered_lines = [];
  }

  function applyFilter() {
    filtered_lines = lines.filter(
      (line) =>
        levels[line.level] >= levels[level] &&
        (!filter ||
          filter.length === 0 ||
          line.message.includes(filter) ||
          line.error?.includes(filter)),
    );
  }

  // TODO: should connect on tab open, not on mount
  onMount(() => {
    const es = new EventSource(`${API_BASE}/log`);

    es.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      lines.push(data);
      if (lines.length > LOGS_BUFFER_LIMIT) {
        lines.shift();
      }
      if (
        levels[data.level] >= levels[level] &&
        (filter.length === 0 || data.message.includes(filter) || data.error?.includes(filter))
      ) {
        filtered_lines.push(data);
      }
      await tick();
      stickToBottom();
    };

    es.onerror = (event) => {
      console.error("Error fetching logs:", event);
    };

    return () => {
      es.close();
    };
  });
</script>

<div class="logs-controls">
  <div class="filter">
    <Filter size={22} opacity={0.5} />
    <input
      type="text"
      class="filter-input"
      placeholder="filter logs..."
      bind:value={filter}
      oninput={applyFilter}
    />
    <Select
      options={Object.keys(levels).map((item) => ({
        label: item,
        value: item,
      }))}
      bind:selected={level}
      onSelectedChange={applyFilter}
      style="width: 100px"
    />
  </div>

  <div class="logs-controls-actions">
    <Tooltip value="Clear">
      <button class="action main" onclick={clearLinesBuf}><Clear size={22} /></button>
    </Tooltip>
    <Tooltip value="Scroll to bottom">
      <button class="action main" onclick={scrollToBottom}><ScrollToBottom size={22} /></button>
    </Tooltip>
  </div>
</div>

<ScrollArea.Root>
  <ScrollArea.Viewport bind:ref={viewport}>
    {#each filtered_lines as { time, level, message, error }, index (index)}
      <div class="line" data-level={level} data-time={time}>
        <span class="time">{time}</span>
        <span class={level}>{level.toLocaleUpperCase()}</span>
        {message}{error ? ", " + error : ""}
      </div>
    {/each}
  </ScrollArea.Viewport>
  <ScrollArea.Scrollbar orientation="vertical">
    <ScrollArea.Thumb />
  </ScrollArea.Scrollbar>
  <ScrollArea.Corner />
</ScrollArea.Root>

<style>
  .logs-controls {
    display: flex;
    align-items: end;
    justify-items: end;
    gap: 0.5rem;
    padding: 0.5rem 0 0.5rem 0;
  }

  .logs-controls-actions {
    display: flex;
    align-items: end;
    justify-content: end;
    gap: 0.5rem;
    width: 100%;
  }

  /* TODO: reuse this styles through all pages */
  .action {
    & {
      color: var(--text-2);
      background-color: transparent;
      border: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.4rem;
      border-radius: 0.5rem;
      cursor: pointer;
    }

    &:hover {
      background-color: var(--bg-dark);
      outline: 1px solid var(--bg-light-extra);
      color: var(--text);
    }

    &.main {
      & {
        background-color: var(--bg-light);
        padding: 0.6rem;
        transition: background-color 0.3s ease-in-out;
      }

      &:hover {
        background-color: var(--bg-light-extra);
      }
    }
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

  :global {
    [data-scroll-area-root] {
      position: relative;
      height: 600px;
      padding: 0.5rem;
      border-radius: 0.5rem;
      background-color: var(--bg-dark-extra);
      border: 1px solid var(--bg-light-extra);
    }

    [data-scroll-area-viewport] {
      height: 100%;
      width: 100%;
      position: relative;
    }

    [data-scroll-area-scrollbar-x],
    [data-scroll-area-scrollbar-y] {
      user-select: none;
      touch-action: none;
      display: flex;
      height: calc(100% - 1.4rem);
      background-color: transparent;
      width: 0.4rem;
      margin: 0.2rem;
      padding: 0.2rem;
    }

    [data-scroll-area-thumb-x],
    [data-scroll-area-thumb-y] {
      & {
        flex: 1;
        position: relative;
        opacity: 0.6;
        background-color: var(--bg-light-extra);
        border-radius: 0.5rem;
        width: 0.4rem;
        padding: 0.3rem;
        transition: all 0.3 ease-in-out;
      }

      &:hover {
        opacity: 1;
      }
    }
  }

  .line {
    font-family: var(--font-mono);
    font-size: 0.8rem;
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
