import type { MetadataRoute } from "next";

// Makes HELIOS installable as a desktop or mobile app (Chrome, Edge, Safari
// "Add to Dock / Home Screen") — the role desas's Electron shell played,
// without a second codebase. Opens in its own window with the shortcuts
// analysts reach for first.
export default function manifest(): MetadataRoute.Manifest {
  return {
    id: "/",
    name: "HELIOS — Managed detection & response",
    short_name: "HELIOS",
    description: "Cases, AI first response, investigations, forensics and client reporting for a managed SOC.",
    start_url: "/",
    scope: "/",
    display: "standalone",
    display_override: ["window-controls-overlay", "standalone"],
    background_color: "#0b1220",
    theme_color: "#2a5cda",
    categories: ["security", "business", "productivity"],
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
      { src: "/icons/maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
    shortcuts: [
      { name: "Cases & Alerts", url: "/cases", icons: [{ src: "/icons/icon-192.png", sizes: "192x192" }] },
      { name: "Investigations", url: "/investigations", icons: [{ src: "/icons/icon-192.png", sizes: "192x192" }] },
      { name: "Email & File Forensics", url: "/forensics", icons: [{ src: "/icons/icon-192.png", sizes: "192x192" }] },
      { name: "Reports", url: "/reports", icons: [{ src: "/icons/icon-192.png", sizes: "192x192" }] },
    ],
  };
}
