<script lang="ts">
  import { DropdownMenu } from "bits-ui";
  import type { Snippet } from "svelte";

  type Props = {
    trigger: Snippet;
    [key: string]: Snippet;
  };
  let { trigger, ...rest }: Props = $props();

  const childs = $derived(Object.values(rest).filter((f) => typeof f === "function"));
</script>

<DropdownMenu.Root>
  <DropdownMenu.Trigger>{@render trigger()}</DropdownMenu.Trigger>
  <DropdownMenu.Content align={"center"}>
    {#each childs as child, index}
      <DropdownMenu.Item>
        {@render child()}
      </DropdownMenu.Item>
    {/each}
  </DropdownMenu.Content>
</DropdownMenu.Root>

<style>
  :global {
    [data-dropdown-menu-trigger] {
      & {
        color: var(--text-2);
        background-color: transparent;
        border: 1px solid transparent;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0.4rem;
        border-radius: 0.5rem;
        cursor: pointer;
      }

      &:hover {
        background-color: var(--bg-dark);
        color: var(--text);
        border: 1px solid var(--bg-light-extra);
      }
    }

    [data-dropdown-menu-content] {
      padding: 0.2rem;
      background-color: var(--bg-dark-extra);
      border-radius: 0.5rem;
      border: 1px solid var(--bg-light-extra);
      box-shadow: var(--shadow-popover);
      z-index: 100;
      position: relative;
      right: 1.5rem;
    }

    [data-dropdown-menu-item] {
      & {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 0.1rem;

        border-radius: 0.2rem;
        cursor: default;
      }
    }

    .dd-icon {
      width: 40px;
      color: var(--text-2);
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .dd-label {
      position: relative;
      top: 2px;
    }
  }
</style>
