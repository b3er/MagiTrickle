<script lang="ts">
  import Select from "../common/Select.svelte";

  import { INTERFACES } from "../../data/interfaces.svelte";

  type Props = {
    selected: string;
  };

  let { selected = $bindable() }: Props = $props();
</script>

<Select options={INTERFACES.map((item) => ({ value: item, label: item }))} bind:selected />
