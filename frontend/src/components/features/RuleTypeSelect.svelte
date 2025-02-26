<script lang="ts">
  import Select from "../common/Select.svelte";
  import { RULE_TYPES } from "../../types";

  type Props = {
    selected: string;
    onSelectedChange?: (selected: string) => void;
  };

  let { selected = $bindable(), onSelectedChange }: Props = $props();
</script>

<Select options={RULE_TYPES} bind:selected {onSelectedChange} />
