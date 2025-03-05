<script lang="ts">
  import type { Snippet } from "svelte";

  type Props = {
    children: Snippet;
    small?: boolean;
    inactive?: boolean;
    onclick?: () => void;
    [key: string]: any;
  };
  let { children, onclick, small, inactive, ...rest }: Props = $props();
</script>

<button class:main={!small} class:inactive onclick={inactive ? () => ({}) : onclick} {...rest}>
  {@render children()}
</button>

<style>
  button {
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

    :global(&.fail) {
      color: var(--red);
      box-shadow: 0 0 5px var(--red);
    }

    :global(&.success) {
      color: var(--green);
      box-shadow: 0 0 5px var(--green);
    }

    &.main {
      & {
        background-color: var(--bg-light);
        padding: 0.6rem;
        transition: all 0.1s ease-in-out;
        border: 1px solid var(--bg-light-extra);
      }

      &:hover {
        background-color: var(--bg-light-extra);
      }
    }
  }

  button.inactive {
    & {
      cursor: default;
      opacity: 0.3;
    }
    &:hover {
      background-color: transparent;
      color: var(--text-2);
      border: 1px solid transparent;
    }
  }
</style>
