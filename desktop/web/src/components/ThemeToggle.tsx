// Three-state theme toggle: light / dark / system. State persists
// in localStorage; "system" lets prefers-color-scheme drive things.
// We apply by toggling the `dark` class on <html> to match Tailwind's
// dark: variant.

import { useEffect, useState } from "react";

type Theme = "light" | "dark" | "system";

const KEY = "golantern.theme";

function apply(theme: Theme) {
  const root = document.documentElement;
  const wantDark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  root.classList.toggle("dark", wantDark);
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem(KEY) as Theme) || "system",
  );

  useEffect(() => {
    apply(theme);
    localStorage.setItem(KEY, theme);
  }, [theme]);

  // When system, keep in sync if the OS preference changes mid-session.
  useEffect(() => {
    if (theme !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => apply("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  function cycle() {
    setTheme((t) =>
      t === "system" ? "light" : t === "light" ? "dark" : "system",
    );
  }
  const label =
    theme === "system" ? "Auto" : theme === "light" ? "Light" : "Dark";
  const icon = theme === "system" ? "◐" : theme === "light" ? "☀" : "☾";

  return (
    <button
      onClick={cycle}
      title={`Theme: ${label}`}
      className="text-sm px-2 py-1 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
    >
      <span className="mr-1">{icon}</span>
      {label}
    </button>
  );
}
