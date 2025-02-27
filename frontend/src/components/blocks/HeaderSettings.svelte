<script lang="ts">
  import Select from "../common/Select.svelte";
  import { Locale, Github } from "../common/icons";
  import { t, getLocale, setLocale, locales } from "../../data/locale.svelte";
  const version = import.meta.env.VITE_UPSTREAM_VERSION || "0.0.0";
</script>

<div class="container">
  <div class="version">
    <span>build: {version}</span>
  </div>
  <!-- TODO: more links? -->
  <div class="links">
    <a target="_blank" rel="noopener noreferrer" href="https://github.com/Ponywka/MagiTrickle"
      ><Github size={22} /></a
    >
  </div>
  <!-- <div class="locale">
    <Locale size={22} />
    <Select
      options={Object.keys(locales).map((item) => ({ label: item, value: item }))}
      selected={getLocale()}
      onSelectedChange={(value) => setLocale(value)}
      style="width:55px"
    />
  </div> -->
</div>

<style>
  .container {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 1.2rem;
  }

  /* .locale, */
  .links,
  .version {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 0.1rem;
  }

  .links a {
    & {
      color: var(--text);
      cursor: pointer;

      display: flex;
      align-items: center;
      justify-content: center;
    }

    &:hover {
      color: var(--accent);
    }
  }

  .version span {
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: smaller;
    color: var(--text-2);
  }
</style>
