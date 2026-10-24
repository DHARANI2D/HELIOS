// Shared by the root layout (a Server Component) and lib/theme (client), so
// it can't live in the "use client" module: exports from there are client
// references, not strings, when imported on the server.

export const THEME_STORAGE_KEY = "helios-theme";

export const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem("${THEME_STORAGE_KEY}")||"system";var d=t==="dark"||(t==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.classList.toggle("dark",d)}catch(e){}})()`;
