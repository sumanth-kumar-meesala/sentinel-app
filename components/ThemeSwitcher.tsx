"use client";
import { useEffect, useState } from "react";

// Sentinel (custom) first, then all built-in daisyUI 5 themes.
const THEMES = [
  "sentinel",
  "light", "dark", "cupcake", "bumblebee", "emerald", "corporate", "synthwave", "retro",
  "cyberpunk", "valentine", "halloween", "garden", "forest", "aqua", "lofi", "pastel",
  "fantasy", "wireframe", "black", "luxury", "dracula", "cmyk", "autumn", "business",
  "acid", "lemonade", "night", "coffee", "winter", "dim", "nord", "sunset",
  "caramellatte", "abyss", "silk",
];

const KEY = "dxs-theme";

export default function ThemeSwitcher() {
  const [theme, setTheme] = useState("sentinel");
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem(KEY);
    if (saved && THEMES.includes(saved)) {
      setTheme(saved);
      document.documentElement.setAttribute("data-theme", saved);
    }
  }, []);

  // Close on Escape.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  function pick(t: string) {
    setTheme(t);
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem(KEY, t);
    setOpen(false);
  }

  return (
    <div className="relative no-print">
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="btn btn-sm border hairline bg-transparent hover:bg-base-content/5 font-mono text-xs gap-2"
      >
        <PaletteGlyph />
        <span className="hidden sm:inline">{theme}</span>
        <span className="opacity-50">▾</span>
      </button>

      {open && (
        <>
          {/* click-away backdrop — a single outside click just closes the menu */}
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} aria-hidden />
          <ul
            role="listbox"
            className="absolute right-0 z-50 mt-2 p-2 shadow-2xl bg-base-100 rounded-box border hairline w-56 max-h-[70vh] overflow-y-auto grid grid-cols-1 gap-0.5"
          >
            <li className="px-2 py-1 eyebrow">Theme</li>
            {THEMES.map((t) => (
              <li key={t}>
                <button
                  type="button"
                  onClick={() => pick(t)}
                  data-theme={t}
                  role="option"
                  aria-selected={theme === t}
                  className="w-full flex items-center justify-between gap-2 rounded-field px-2.5 py-1.5 text-sm bg-base-100 hover:outline hover:outline-1 hover:outline-base-content/20 transition"
                >
                  <span className="capitalize text-base-content">{t}</span>
                  <span className="flex gap-1 items-center">
                    <span className="w-2.5 h-2.5 rounded-full bg-primary" />
                    <span className="w-2.5 h-2.5 rounded-full bg-secondary" />
                    <span className="w-2.5 h-2.5 rounded-full bg-accent" />
                    {theme === t && <span className="ml-1 text-primary">✓</span>}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function PaletteGlyph() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 3a9 9 0 100 18c1 0 1.5-.8 1.5-1.5 0-.4-.2-.8-.5-1.1-.3-.3-.5-.7-.5-1.1 0-.8.7-1.5 1.5-1.5H16a5 5 0 005-5c0-4.4-4-8-9-8z" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="7.5" cy="11.5" r="1" fill="currentColor" />
      <circle cx="12" cy="8.5" r="1" fill="currentColor" />
      <circle cx="16" cy="11.5" r="1" fill="currentColor" />
    </svg>
  );
}
