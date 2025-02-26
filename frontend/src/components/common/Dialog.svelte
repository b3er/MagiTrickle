<script lang="ts">
  import { Dialog, Label, Separator } from "bits-ui";
  import type { Snippet } from "svelte";
  import { fade, fly } from "svelte/transition";
  import { Add, Close } from "./icons";

  type Props = {
    title: string;
    description?: string;
    trigger: Snippet;
    children: Snippet;
    onOk?: (...args: any[]) => void;
  };

  let { title, description, trigger, children, onOk }: Props = $props();
</script>

<Dialog.Root>
  <Dialog.Trigger>
    {@render trigger()}
  </Dialog.Trigger>
  <Dialog.Portal>
    <Dialog.Overlay />
    <Dialog.Content>
      <Dialog.Title>{title}</Dialog.Title>
      {#if description}
        <Dialog.Description class="text-sm text-foreground-alt">
          {description}
        </Dialog.Description>
      {/if}
      {@render children()}
      <div class="buttons">
        <Dialog.Close class="ok" onclick={() => onOk?.()}>
          <div class="close-icon"><Add size={20} /></div>
          Add
        </Dialog.Close>
        <Dialog.Close>
          <div class="close-icon"><Close size={20} /></div>
          Close
        </Dialog.Close>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>

<style>
  :global {
    [data-dialog-trigger] {
      background: transparent;
      border: none;
      padding: 0;
      margin: 0;
    }

    [data-dialog-overlay] {
      position: fixed;
      top: 0;
      right: 0;
      bottom: 0;
      left: 0;
      z-index: 50;
      background-color: rgba(0, 0, 0, 0.8);
    }

    [data-dialog-content] {
      position: fixed;
      left: 50%;
      top: 50%;
      z-index: 50;
      width: auto;
      max-width: 80%;
      transform: translate(-50%, -50%);
      border-radius: 0.5rem;
      border: 1px solid var(--bg-light-extra);
      background-color: var(--bg-dark-extra);
      padding: 1.2rem;
      padding-top: 0;
      box-shadow: var(--shadow-popover);
      outline: none;
    }

    [data-dialog-title] {
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.2rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }

    .buttons {
      margin-top: 1rem;
      display: flex;
      justify-content: flex-end;
      align-items: center;
      width: 100%;
      gap: 0.5rem;
    }

    [data-dialog-description] {
      margin-bottom: 0.8rem;
    }

    [data-dialog-close] {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;

      background: var(--bg-light-extra);
      border: none;
      border-radius: 0.5rem;
      padding: 0.3rem 0.5rem 0.2rem 0.5rem;
      font-size: 1rem;
      font-weight: 400;
      font-family: var(--font);
      color: var(--text);
    }

    [data-dialog-close]:hover {
      background-color: var(--bg-medium);
    }
  }

  .close-icon {
    margin-right: 0.2rem;
    position: relative;
    top: 0.1rem;
  }
</style>
