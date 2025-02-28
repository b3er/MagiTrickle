import en from "../locales/en.json";
import ru from "../locales/ru.json";

export const locales: Record<string, Record<string, string>> = { en, ru };

let locale = $state<string>(localStorage.getItem("locale") ?? "en");
const translation = $derived(locales[locale]);

export function setLocale(value: string) {
  localStorage.setItem("locale", value);
  locale = value;
}

export function getLocale() {
  return locale;
}

export function t(key: string) {
  return translation[key] ?? key;
}
