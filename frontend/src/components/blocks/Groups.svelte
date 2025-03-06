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
  } from "../common/icons";
  import Switch from "../common/Switch.svelte";
  import Tooltip from "../common/Tooltip.svelte";
  import RuleComponent from "../features/Rule.svelte";
  import Button from "../common/Button.svelte";
  import Select from "../common/Select.svelte";
  import { overlay, toast } from "../../utils/events";
  import DropdownMenu from "../common/DropdownMenu.svelte";

  let data: Group[] = $state([]);
  let showed_limit: number[] = $state([]);
  let showed_data: Group[] = $derived.by(() =>
    data.map((group, index) => ({
      ...group,
      rules: group.rules.slice(0, showed_limit[index]),
    })),
  );
  let counter = $state(-2); // skip first update on init
  let valid_rules = $state(true);
  let container_width = $state<number>(Infinity);

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
    showed_limit = data.map((group) => (group.rules.length > 20 ? 20 : group.rules.length));
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
  }

  async function addRuleToGroup(group_index: number, rule: Rule, focus = false) {
    data[group_index].rules.unshift(rule);
    if (!focus) return;
    await tick();
    const el = document.querySelector(`.rule[data-group-index="${group_index}"][data-index="0"]`);
    el?.querySelector<HTMLInputElement>("div.name input")?.focus();
  }

  function deleteRuleFromGroup(group_index: number, rule_index: number) {
    data[group_index].rules.splice(rule_index, 1);
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
  }

  function addGroup() {
    data.push(defaultGroup());
  }

  function groupMoveUp(index: number) {
    if (index === 0) return;
    data = [...data.slice(0, index - 1), data[index], data[index - 1], ...data.slice(index + 1)];
  }

  function groupMoveDown(index: number) {
    if (index === data.length - 1) return;
    data = [...data.slice(0, index), data[index + 1], data[index], ...data.slice(index + 2)];
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
    if ((showed_limit[group_index] = data[group_index].rules.length)) return;
    showed_limit[group_index] += 20;
    if (showed_limit[group_index] > data[group_index].rules.length) {
      showed_limit[group_index] = data[group_index].rules.length;
      return;
    }
    loaderState.loaded();
  }
</script>

<div class="group-controls">
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
      <Collapsible.Root open={false}>
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

            {#if container_width > 668}
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
                <div class="group-rules-header-column">Enabled</div>
                <div></div>
              </div>
            {/if}
            <div class="group-rules">
              <InfiniteLoader triggerLoad={() => loadMore(group_index)} loopDetectionTimeout={10}>
                {#each group.rules as rule, rule_index (rule.id)}
                  <RuleComponent
                    key={rule.id}
                    bind:rule={data[group_index].rules[rule_index]}
                    {rule_index}
                    {group_index}
                    rule_id={rule.id}
                    group_id={group.id}
                    onChangeIndex={changeRuleIndex}
                    onDelete={deleteRuleFromGroup}
                    style={rule_index % 2 ? "" : "background-color: var(--bg-light)"}
                  />
                {/each}
              </InfiniteLoader>
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
</style>
