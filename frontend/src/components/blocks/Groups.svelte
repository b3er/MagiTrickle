<script lang="ts">
  import { Collapsible } from "bits-ui";
  import { scale, slide } from "svelte/transition";
  import { onDestroy, onMount, untrack, tick } from "svelte";
  import { InfiniteLoader, loaderState } from "svelte-infinite";

  import { parseConfig, type Group, type Rule } from "../../types";
  import { defaultGroup, defaultRule } from "../../utils/defaults";
  import { fetcher } from "../../utils/fetcher";
  import { INTERFACES } from "../../data/interfaces.svelte";
  import {
    Delete,
    Add,
    GroupCollapse,
    Upload,
    Download,
    Save,
    MoveUp,
    MoveDown,
    Dots,
    Check,
    Toggle,
    CircleX,
  } from "../common/icons";
  import Switch from "../common/Switch.svelte";
  import Tooltip from "../common/Tooltip.svelte";
  import RuleComponent from "../features/Rule.svelte";
  import Button from "../common/Button.svelte";
  import Select from "../common/Select.svelte";
  import { overlay, toast } from "../../utils/events";
  import DropdownMenu from "../common/DropdownMenu.svelte";

  const showLimit = 30;
  const showBump = 40;

  let data: Group[] = $state([]);
  let showed_limit: number[] = $state([]);
  let searchQuery = $state("");
  let selectedRuleName = $state("");
  let comboboxOpen = $state(false);
  let comboboxEl = $state<HTMLDivElement | null>(null);
  let groupExpanded = $state<boolean[]>([]);

  // Auto-expand groups with filtered items when searchQuery changes, but never collapse
  $effect(() => {
    if (!data) return;
    if (!searchQuery.trim()) return; // do not collapse on empty
    const newExpanded = groupExpanded.length === data.length
      ? groupExpanded.map((open, i) => open || showed_data[i].rules.length > 0)
      : showed_data.map(g => g.rules.length > 0);
    // Only update if changed, to avoid infinite loop
    if (groupExpanded.length !== newExpanded.length || groupExpanded.some((v, i) => v !== newExpanded[i])) {
      groupExpanded = newExpanded;
    }
  });

  // Compute grouped rule name options for dropdown
  let groupedRuleNameOptions: {label: string, value: string}[] = $derived.by(() => {
    let options: {label: string, value: string}[] = [];
    data.forEach(group => {
      const uniqueNames = Array.from(new Set(group.rules.map(r => r.name).filter(Boolean)));
      if (uniqueNames.length > 0) {
        options.push({ label: `--- ${group.name} ---`, value: "" });
        const sortedNames = uniqueNames.slice().sort((a, b) => a.localeCompare(b, undefined, {sensitivity: 'base'}));
        options = options.concat(sortedNames.map(name => ({ label: name, value: name })));
      }
    });
    return options;
  });

  // Derived variable for filtered and paginated groups
  let showed_data: Group[] = $derived.by(() =>
    data.map((group, index) => {
      let filteredRules = group.rules;
      const hasSearch = searchQuery.trim() !== "";
      if (hasSearch) {
        const q = searchQuery.trim().toLowerCase();
        filteredRules = group.rules.filter(
          (rule: Rule) =>
            (rule.name && rule.name.toLowerCase().includes(q)) ||
            (rule.rule && rule.rule.toLowerCase().includes(q))
        );
        // When searching, show all matches, ignore pagination
        return {
          ...group,
          rules: filteredRules,
        };
      } else {
        // No search: paginate as before
        return {
          ...group,
          rules: group.rules.slice(0, showed_limit[index]),
        };
      }
    })
  );

  // When the user types in the input, reset selectedRuleName if it doesn't match
  $effect(() => {
    if (selectedRuleName && searchQuery !== selectedRuleName) {
      selectedRuleName = "";
    }
  });

  let counter = $state(-2); // skip first update on init
  let valid_rules = $state(true);
  let container_width = $state<number>(Infinity);
  let is_desktop = $derived(container_width > 668);

  function onRuleDrop(event: CustomEvent) {
    const { from_group_index, from_rule_index, to_group_index, to_rule_index } = event.detail;
    changeRuleIndex(from_group_index, from_rule_index, to_group_index, to_rule_index);
  }

  function unsavedChanges(event: BeforeUnloadEvent) {
    if (counter < 1) return;
    event.preventDefault();
  }

  function saveChanges() {
    if (counter === 0) return;

    overlay.show("saving changes...");

    const el = document.getElementById("save-changes")!;
    fetcher
      .put("/groups?save=true", { groups: data })
      .then(() => {
        counter = 0;
        overlay.hide();
        toast.success("Saved");
      })
      .catch(() => {
        overlay.hide();
      });
  }

  onMount(async () => {
    data = (await fetcher.get<{ groups: Group[] }>("/groups?with_rules=true"))?.groups ?? [];
    showed_limit = data.map((group) => (group.rules.length > showLimit ? showLimit : group.rules.length));
    window.addEventListener("rule_drop", onRuleDrop);
    window.addEventListener("beforeunload", unsavedChanges);
  });

  onDestroy(() => {
    window.removeEventListener("rule_drop", onRuleDrop);
    window.removeEventListener("beforeunload", unsavedChanges);
  });

  $effect(() => {
    const value = $state.snapshot(data);
    const new_count = untrack(() => counter) + 1;
    counter = new_count;
    if (new_count == 0) return;
    console.debug("config state", value, new_count);
    setTimeout(checkRulesValidityState, 10);
  });

  function checkRulesValidityState() {
    valid_rules = !document.querySelector(".rule input.invalid");
  }

  function deleteGroup(index: number) {
    data.splice(index, 1);
    showed_limit.splice(index, 1);
  }

  async function addRuleToGroup(group_index: number, rule: Rule, focus = false) {
    data[group_index].rules.unshift(rule);
    showed_limit[group_index]++;
    if (!focus) return;
    await tick();
    const el = document.querySelector(`.rule[data-group-index="${group_index}"][data-index="0"]`);
    el?.querySelector<HTMLInputElement>("div.name input")?.focus();
  }

  function deleteRuleFromGroup(group_index: number, rule_id: string) {
    const idx = data[group_index].rules.findIndex(r => r.id === rule_id);
    if (idx !== -1) data[group_index].rules.splice(idx, 1);
  }

  function changeRuleIndex(
    from_group_index: number,
    from_rule_index: number,
    to_group_index: number,
    to_rule_index: number,
  ) {
    const rule = data[from_group_index].rules[from_rule_index];
    data[from_group_index].rules.splice(from_rule_index, 1);
    data[to_group_index].rules.splice(to_rule_index, 0, rule);
    showed_limit[from_group_index]--;
    showed_limit[to_group_index]++;
  }

  function addGroup() {
    data.push(defaultGroup());
    showed_limit.push(showLimit);
  }

  function groupMoveUp(index: number) {
    if (index === 0) return;
    data = [...data.slice(0, index - 1), data[index], data[index - 1], ...data.slice(index + 1)];
    showed_limit = [
      ...showed_limit.slice(0, index - 1),
      showed_limit[index],
      showed_limit[index - 1],
      ...showed_limit.slice(index + 1),
    ];
  }

  function groupMoveDown(index: number) {
    if (index === data.length - 1) return;
    data = [...data.slice(0, index), data[index + 1], data[index], ...data.slice(index + 2)];
    showed_limit = [
      ...showed_limit.slice(0, index),
      showed_limit[index + 1],
      showed_limit[index],
      ...showed_limit.slice(index + 2),
    ];
  }

  function exportConfig() {
    const blob = new Blob([JSON.stringify({ groups: data })], {
      type: "application/json",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "config.mtrickle";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function importConfig() {
    const input = document.getElementById("import-config") as HTMLInputElement;
    const file = input.files?.[0];

    console.debug("importing config", file?.name);
    if (file) {
      const reader = new FileReader();
      reader.onload = function (event) {
        try {
          let { groups } = parseConfig(event.target?.result as string);
          for (let i = 0; i < groups.length; i++) {
            if (!INTERFACES.includes(groups[i].interface)) {
              groups[i].interface = INTERFACES.at(0) ?? ""; // fallback to first interface
            }
          }
          data = groups;
          showed_limit = data.map((group) => (group.rules.length > showLimit ? showLimit : group.rules.length));
          toast.success("Config imported");
        } catch (error) {
          console.error("Error parsing CONFIG:", error); // why is this not writing to console?
          toast.error("Invalid config file");
        }
      };
      reader.onerror = function (event) {
        console.error("Error reading file:", event.target?.error);
        toast.error("Invalid config file");
      };
      reader.readAsText(file);
      input.value = "";
    } else {
      alert("Please select a CONFIG file to load.");
    }
  }
  // FIXME: make group header droppable
  // function handleDrop(state: DragDropState) {
  //   const { sourceContainer, targetContainer } = state;

  //   if (!targetContainer || sourceContainer === targetContainer) return;
  //   const [, , from_group_index, from_rule_index] = sourceContainer.split(",");
  //   const [, , to_group_index] = targetContainer.split(",");
  //   window.dispatchEvent(
  //     new CustomEvent("rule_drop", {
  //       detail: {
  //         from_group_index: +from_group_index,
  //         from_rule_index: +from_rule_index,
  //         to_group_index: +to_group_index,
  //         to_rule_index: +data[+to_group_index].rules.length,
  //       },
  //     }),
  //   );
  // }

  async function loadMore(group_index: number): Promise<void> {
    if (showed_limit[group_index] >= data[group_index].rules.length) return;
    showed_limit[group_index] += showBump;
    if (showed_limit[group_index] > data[group_index].rules.length) {
      showed_limit[group_index] = data[group_index].rules.length;
      return;
    }
    loaderState.loaded();
  }
  // Close combobox on outside click
  $effect(() => {
    if (comboboxOpen) {
      const handler = (e: MouseEvent) => {
        if (comboboxEl && !comboboxEl.contains(e.target as Node)) {
          comboboxOpen = false;
        }
      };
      window.addEventListener('mousedown', handler, true);
      onDestroy(() => window.removeEventListener('mousedown', handler, true));
    }
  });

  // Add a function to filter dropdown options based on input
  function filterDropdownOptions(query: string) {
    if (query.trim() !== "") {
      comboboxOpen = true;
    }
  }

  // Add a function to clear the search query
  function clearSearchQuery() {
    searchQuery = "";
    comboboxOpen = false;
  }
</script>

<div class="group-controls">
  <div class="group-controls-search combobox" bind:this={comboboxEl} style="position: relative; display: flex; align-items: center; gap: 0.5rem;">
    <div class="search-input-container">
      <input
        type="text"
        placeholder="Search rules..."
        bind:value={searchQuery}
        class="group-search-input"
        autocomplete="off"
        oninput={() => filterDropdownOptions(searchQuery)}
        onblur={(e) => {
          // Only close if focus moves outside the combobox
          const related = e.relatedTarget as HTMLElement | null;
          if (!related || !related.closest('.combobox')) {
            comboboxOpen = false;
          }
        }}
      />
      {#if searchQuery}
        <button type="button" class="clear-btn" aria-label="Clear search" onclick={clearSearchQuery}>
          <CircleX size={16} />
        </button>
      {/if}
    </div>
    <button type="button" class="combobox-dropdown-btn" aria-label="Show rule names" onclick={() => comboboxOpen = !comboboxOpen} tabindex="-1">
      <svg width="18" height="18" viewBox="0 0 20 20" fill="none"><path d="M5 8l5 5 5-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>
    {#if comboboxOpen}
      <div class="combobox-dropdown" tabindex="-1">
        {#each groupedRuleNameOptions as option}
          {#if option.value === ""}
            <div class="combobox-group-label">{option.label}</div>
          {:else}
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <!-- svelte-ignore a11y_no_static_element_interactions -->
            <div 
              class="combobox-item" 
              onclick={() => { searchQuery = option.value; selectedRuleName = option.value; comboboxOpen = false; }}
              style="display: {!searchQuery || option.label.toLowerCase().includes(searchQuery.toLowerCase()) ? 'block' : 'none'}"
            >
              {option.label}
            </div>
          {/if}
        {/each}
      </div>
    {/if}
  </div>

  <style>
    .combobox {
      position: relative;
      width: 100%;
      max-width: 320px;
    }
    .search-input-container {
      position: relative;
      width: 100%;
    }
    .clear-btn {
      position: absolute;
      right: 2.5rem;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      z-index: 2;
      padding: 0;
      width: 1.8rem;
      height: 1.8rem;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-2);
      border-radius: 0.3rem;
      transition: background 0.1s;
    }
    .clear-btn:hover {
      background: var(--bg-light-extra);
      color: var(--accent);
    }
    .combobox-dropdown-btn {
      position: absolute;
      right: 0.6rem;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      z-index: 2;
      padding: 0;
      width: 2rem;
      height: 2rem;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-2);
      border-radius: 0.3rem;
      transition: background 0.1s;
    }
    .combobox-dropdown-btn svg {
      width: 1.2rem;
      height: 1.2rem;
      pointer-events: none;
      display: block;
    }
    .combobox-dropdown-btn:hover {
      background: var(--bg-light-extra);
    }
    .combobox-dropdown {
      position: absolute;
      left: 0;
      top: 110%;
      width: 100%;
      background: var(--bg-light);
      border: 1px solid var(--bg-light-extra);
      border-radius: 0.4rem;
      box-shadow: var(--shadow-popover);
      z-index: 10;
      max-height: 260px;
      overflow-y: auto;
      margin-top: 0.2rem;
    }
    .combobox-group-label {
      font-size: 0.9em;
      color: var(--text-2);
      padding: 0.4em 0.8em 0.2em 0.8em;
      font-weight: 600;
      background: var(--bg-light-extra);
    }
    .combobox-item {
      padding: 0.4em 0.8em;
      cursor: pointer;
      font-size: 1em;
      color: var(--text);
      transition: background 0.1s;
    }
    .combobox-item:hover {
      background: var(--bg-dark-extra);
      color: var(--accent);
    }
  </style>
  <div class="group-controls-actions">
    {#if counter > 0 && valid_rules}
      <div transition:scale>
        <Tooltip value="Save Changes">
          <Button onclick={saveChanges} id="save-changes">
            <Save size={22} />
          </Button>
        </Tooltip>
      </div>
    {/if}
    <Tooltip value="Export Config">
      <Button onclick={exportConfig}>
        <Upload size={22} />
      </Button>
    </Tooltip>
    <Tooltip value="Import Config">
      <input type="file" id="import-config" hidden accept=".mtrickle" onchange={importConfig} />
      <Button onclick={() => document.getElementById("import-config")!.click()}>
        <Download size={22} />
      </Button>
    </Tooltip>
    <Tooltip value="Add Group">
      <Button onclick={addGroup}><Add size={22} /></Button>
    </Tooltip>
  </div>
</div>

<!-- FIXME: make group header droppable -->
<!-- use:droppable={{
  container: `${group.id},-,${group_index},-`,
  callbacks: { onDrop: handleDrop },
  }} -->

<div bind:clientWidth={container_width}>
  {#each showed_data as group, group_index (group.id)}
    <div class="group" data-uuid={group.id}>
      <Collapsible.Root open={groupExpanded[group_index]}>
        <div class="group-header" data-group-index={group_index}>
          <div class="group-left">
            <label class="group-color" style="background: {group.color}">
              <input type="color" bind:value={data[group_index].color} />
            </label>
            <input
              type="text"
              placeholder="group name..."
              class="group-name"
              bind:value={data[group_index].name}
            />
          </div>
          <div class="group-actions">
            <Select
              options={INTERFACES.map((item) => ({ value: item, label: item }))}
              bind:selected={data[group_index].interface}
            />

            {#if is_desktop}
              <Tooltip value="Enable Group">
                <Switch class="enable-group" bind:checked={data[group_index].enable} />
              </Tooltip>
              <Tooltip value="Delete Group">
                <Button small onclick={() => deleteGroup(group_index)}>
                  <Delete size={20} />
                </Button>
              </Tooltip>
              <Tooltip value="Add Rule">
                <Button small onclick={() => addRuleToGroup(group_index, defaultRule(), true)}>
                  <Add size={20} />
                </Button>
              </Tooltip>
              <Tooltip value="Move Up">
                <Button small inactive={group_index === 0} onclick={() => groupMoveUp(group_index)}>
                  <MoveUp size={20} />
                </Button>
              </Tooltip>
              <Tooltip value="Move Down">
                <Button
                  small
                  inactive={group_index === data.length - 1}
                  onclick={() => groupMoveDown(group_index)}
                >
                  <MoveDown size={20} />
                </Button>
              </Tooltip>
            {:else}
              <DropdownMenu>
                {#snippet trigger()}
                  <Dots size={20} />
                {/snippet}
                {#snippet item1()}
                  <Button
                    general
                    onclick={() => (data[group_index].enable = !data[group_index].enable)}
                  >
                    <div class="dd-icon"><Toggle size={20} /></div>
                    <div class="dd-label">Enable Group</div>
                    <div class="dd-check">
                      {#if data[group_index].enable}
                        <Check size={16} />
                      {/if}
                    </div>
                  </Button>
                {/snippet}
                {#snippet item2()}
                  <Button general onclick={() => deleteGroup(group_index)}>
                    <div class="dd-icon"><Delete size={20} /></div>
                    <div class="dd-label">Delete Group</div>
                  </Button>
                {/snippet}
                {#snippet item3()}
                  <Button general onclick={() => addRuleToGroup(group_index, defaultRule(), true)}>
                    <div class="dd-icon"><Add size={20} /></div>
                    <div class="dd-label">Add Rule</div>
                  </Button>
                {/snippet}
                {#snippet item4()}
                  <Button
                    general
                    inactive={group_index === 0}
                    onclick={() => groupMoveUp(group_index)}
                  >
                    <div class="dd-icon"><MoveUp size={20} /></div>
                    <div class="dd-label">Move Up</div>
                  </Button>
                {/snippet}
                {#snippet item5()}
                  <Button
                    general
                    inactive={group_index === data.length - 1}
                    onclick={() => groupMoveDown(group_index)}
                  >
                    <div class="dd-icon"><MoveDown size={20} /></div>
                    <div class="dd-label">Move Down</div>
                  </Button>
                {/snippet}
              </DropdownMenu>
            {/if}

            <Tooltip value="Collapse Group">
              <Collapsible.Trigger>
                <GroupCollapse />
              </Collapsible.Trigger>
            </Tooltip>
          </div>
        </div>

        <Collapsible.Content>
          <div transition:slide>
            {#if group.rules.length > 0}
              <div class="group-rules-header">
                <div class="group-rules-header-column total">
                  #{data[group_index].rules.length}
                </div>
                <div class="group-rules-header-column">Name</div>
                <div class="group-rules-header-column">Type</div>
                <div class="group-rules-header-column">Pattern</div>
              </div>
            {/if}
            <div class="group-rules">
  {#if !searchQuery.trim()}
    <InfiniteLoader triggerLoad={() => loadMore(group_index)} loopDetectionTimeout={10}>
      {#each group.rules as rule, rule_index (rule.id)}
        <RuleComponent
          key={rule.id}
          rule={rule}
          {rule_index}
          {group_index}
          rule_id={rule.id}
          group_id={group.id}
          onChangeIndex={changeRuleIndex}
          onDelete={(group_index, rule_index) => {
  const rules = searchQuery.trim() ? showed_data[group_index].rules : data[group_index].rules;
  const rule = rules[rule_index];
  if (rule) deleteRuleFromGroup(group_index, rule.id);
}}
          onRuleDrop={(fromIndex: number, toIndex: number) => {
            const rules = data[group_index].rules;
            const [moved] = rules.splice(fromIndex, 1);
            rules.splice(toIndex, 0, moved);
          }}
          style={rule_index % 2 ? "" : "background-color: var(--bg-light)"}
        />
      {/each}
    </InfiniteLoader>
  {:else}
    {#each showed_data[group_index].rules as rule, rule_index (rule.id)}
      <RuleComponent
        key={rule.id}
        rule={rule}
        {rule_index}
        {group_index}
        rule_id={rule.id}
        group_id={group.id}
        onChangeIndex={changeRuleIndex}
        onDelete={(group_index, rule_index) => {
  const rules = searchQuery.trim() ? showed_data[group_index].rules : data[group_index].rules;
  const rule = rules[rule_index];
  if (rule) deleteRuleFromGroup(group_index, rule.id);
}}
        onRuleDrop={(fromIndex: number, toIndex: number) => {
          const fromRule = showed_data[group_index].rules[fromIndex];
          const toRule = showed_data[group_index].rules[toIndex];
          const rules = data[group_index].rules;
          const fromIndexInFull = rules.indexOf(fromRule);
          const toIndexInFull = rules.indexOf(toRule);
          if (fromIndexInFull !== -1 && toIndexInFull !== -1) {
            const [moved] = rules.splice(fromIndexInFull, 1);
            rules.splice(toIndexInFull, 0, moved);
          }
        }}
        style={rule_index % 2 ? "" : "background-color: var(--bg-light)"}
      />
    {/each}
  {/if}
</div>
          </div>
        </Collapsible.Content>
      </Collapsible.Root>
    </div>
  {/each}
</div>

<style>
  .group {
    margin-bottom: 1rem;
    background-color: var(--bg-medium);
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
  }
  .group:last-child {
    margin-bottom: 0;
  }

  .group-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem;
    border-radius: 0.5rem;
    background-color: var(--bg-light);
    position: relative;
  }

  .group-left {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .group-color {
    display: inline-block;
    width: 2rem;
    height: calc(100% + 1px);
    border-top-left-radius: 0.5rem;
    border-bottom-left-radius: 0.5rem;
    position: absolute;
    left: 0px;
    top: -1px;
    overflow: hidden;
    cursor: pointer;
  }

  .group-color input {
    margin-left: 0.5rem;
  }

  .group-name {
    & {
      border: none;
      background-color: transparent;
      font-size: 1.3rem;
      font-weight: 600;
      font-family: var(--font);
      color: var(--text);
      border-bottom: 1px solid transparent;
      position: relative;
      top: 0.1rem;
      margin-left: 2rem;
    }

    &:focus-visible {
      outline: none;
      border-bottom: 1px solid var(--accent);
    }
  }

  .group-actions {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.2rem;
  }

  .group-actions :global([data-switch-root]) {
    margin: 0 0.3rem;
  }

  .group-rules-header {
    display: grid;
    grid-template-columns: 4rem 2.1fr 1fr 3fr 1fr;
    justify-content: center;
    align-items: center;

    font-size: 0.9rem;
    color: var(--text-2);
    padding-top: 0.6rem;
    padding-bottom: 0.2rem;
    border-bottom: 1px solid var(--bg-light-extra);
  }

  .group-rules-header-column {
    & {
      display: flex;
      align-items: center;
      justify-content: center;
    }

    &.total {
      justify-content: start;
      margin-left: 0.5rem;
    }

    &.total :global(svg) {
      position: relative;
      top: -1px;
    }
  }

  :global {
    [data-collapsible-trigger] {
      & {
        color: var(--text-2);
        background-color: transparent;
        border: none;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0.2rem;
        border-radius: 0.5rem;
        cursor: pointer;
      }

      &:hover {
        background-color: var(--bg-dark);
        outline: 1px solid var(--bg-light-extra);
        color: var(--text);
      }
    }
    .infinite-intersection-target {
      padding-block: 0 !important;
    }
  }

  .group-controls {
    display: flex;
    align-items: end;
    justify-items: end;
    gap: 0.5rem;
    padding: 0.5rem 0 0.5rem 0;
    margin-bottom: 0.5rem;
  }

  .group-controls-actions {
    display: flex;
    align-items: end;
    justify-content: end;
    gap: 0.5rem;
    width: 100%;
  }

  input[type="color"] {
    -webkit-appearance: none;
    -moz-appearance: none;
    appearance: none;
    background: transparent;
    width: auto;
    height: 0;
    padding: 0;
    border: none;
    cursor: pointer;
  }

  @media (max-width: 700px) {
    .group-header {
      display: flex;
      flex-direction: column;
      align-items: start;
      justify-content: center;
    }

    .group-left {
      & {
        width: 100%;
      }
      & input[type="text"] {
        width: calc(100% - 2rem);
        margin-left: 2.5rem;
      }
      & label {
        height: calc(100% + 1px);
      }
    }

    .group-actions {
      width: calc(100% - 2rem);
      justify-content: end;
      margin-left: 2rem;
    }

    :global(.group-actions > *:nth-child(1)) {
      margin-right: auto;
      width: 150px;
    }
    :global(.group-actions > *:nth-child(2)) {
      margin-left: auto;
    }

    .group-rules-header {
      height: 1px;
      & .group-rules-header-column {
        display: none;
      }
    }
  }
.group-controls-search {
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
}
.group-search-input {
  width: 100%;
  max-width: 300px;
  padding: 0.4rem 0.8rem;
  border-radius: 0.4rem;
  border: 1px solid var(--bg-light-extra);
  font-size: 1rem;
  background: var(--bg-light);
  color: var(--text);
  outline: none;
  margin-right: 1rem;
}
.group-search-input:focus {
  border-color: var(--accent);
}
</style>
