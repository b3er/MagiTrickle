<script lang="ts">
  import type { Rule } from "../../types";
  import RuleTypeSelect from "./RuleTypeSelect.svelte";

  type Props = {
    value: Rule;
  };

  let { value = $bindable() }: Props = $props();
</script>

<div class="container">
  <div class="row">
    <div class="label">Name</div>
    <input type="text" placeholder="rule name..." class="table-input" bind:value={value.name} />
  </div>
  <div class="row">
    <div class="label">Type</div>
    <RuleTypeSelect bind:selected={value.type} />
  </div>
  <div class="row">
    <div class="label">Pattern</div>
    <input type="text" placeholder="rule pattern..." class="table-input" bind:value={value.rule} />
  </div>
</div>

<style>
  .row {
    display: grid;
    grid-template-columns: 1fr 4fr;
    gap: 0.5rem;
    align-items: center;
  }

  .label {
    text-align: right;
  }

  .table-input {
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
      width: 300px;
    }

    &:focus-visible {
      outline: none;
      border-bottom: 1px solid var(--accent);
    }
  }
</style>
