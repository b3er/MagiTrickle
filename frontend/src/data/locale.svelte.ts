import en from "../locales/en.json";
import ru from "../locales/ru.json";

// const en = (await import("../locales/en.json")) as unknown as Record<string, string>;
// const ru = (await import("../locales/ru.json")) as unknown as Record<string, string>;
const locales: Record<string, Record<string, string>> = { en, ru };

let locale = $state<string>("en");
const translation = $derived(locales[locale]);
export function setLocale(key: string) {
  // localStorage.setItem("locale", locale);
  locale = key;
}
export function getLocale() {
  return locale;
}

export function t(key: string) {
  return translation[key] ?? key;
}
