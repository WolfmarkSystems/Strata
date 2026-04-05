import type { SimpleIcon } from "simple-icons";
import {
  siDiscord,
  siDropbox,
  siFacebook,
  siFirefox,
  siGmail,
  siGooglechrome,
  siGoogledrive,
  siIcloud,
  siInstagram,
  siSignal,
  siSnapchat,
  siTelegram,
  siWhatsapp,
  siX,
  siZoom,
} from "simple-icons";

export type ArtifactCategory =
  | "Social Media"
  | "Messaging"
  | "Email"
  | "Browsing"
  | "Cloud Storage"
  | "Productivity"
  | "System Artifacts"
  | "Multimedia"
  | "Other";

export interface ArtifactProviderDefinition {
  id: string;
  label: string;
  category: ArtifactCategory;
  icon?: SimpleIcon;
  badgeText?: string;
  badgeHex?: string;
  keywords: readonly string[];
}

const PROVIDER_DEFINITIONS: readonly ArtifactProviderDefinition[] = [
  { id: "facebook", label: "Facebook", category: "Social Media", icon: siFacebook, keywords: ["facebook", "fb", "messenger", "meta", "fb.db"] },
  { id: "instagram", label: "Instagram", category: "Social Media", icon: siInstagram, keywords: ["instagram", "ig", "insta", "instagram.db"] },
  { id: "snapchat", label: "Snapchat", category: "Social Media", icon: siSnapchat, keywords: ["snapchat", "snap", "chat", "sc.db"] },
  { id: "twitter", label: "Twitter", category: "Social Media", icon: siX, keywords: ["twitter", " x "] },

  { id: "whatsapp", label: "WhatsApp", category: "Messaging", icon: siWhatsapp, keywords: ["whatsapp", "wa.db", "msgstore", "wa_db"] },
  { id: "telegram", label: "Telegram", category: "Messaging", icon: siTelegram, keywords: ["telegram", "tdata", "tg.db"] },
  { id: "signal", label: "Signal", category: "Messaging", icon: siSignal, keywords: ["signal", "signal-desktop", "signal.db"] },
  { id: "discord", label: "Discord", category: "Messaging", icon: siDiscord, keywords: ["discord", "discordapp"] },
  { id: "slack", label: "Slack", category: "Messaging", badgeText: "SL", badgeHex: "4A154B", keywords: ["slack"] },
  { id: "teams", label: "Teams", category: "Messaging", badgeText: "T", badgeHex: "6264A7", keywords: ["teams", "microsoft teams"] },

  { id: "gmail", label: "Gmail", category: "Email", icon: siGmail, keywords: ["gmail", "google mail"] },
  { id: "outlook", label: "Outlook / Hotmail", category: "Email", badgeText: "O", badgeHex: "0078D4", keywords: ["outlook", "hotmail", "live.com", "msn", "pst", "ost"] },

  { id: "chrome", label: "Google Chrome", category: "Browsing", icon: siGooglechrome, keywords: ["chrome", "google chrome", "chromium", "history", "places.sqlite"] },
  { id: "edge", label: "Microsoft Edge", category: "Browsing", badgeText: "E", badgeHex: "0A84FF", keywords: ["edge", "microsoft edge"] },
  { id: "firefox", label: "Firefox", category: "Browsing", icon: siFirefox, keywords: ["firefox", "mozilla firefox", "places.sqlite"] },

  { id: "google-drive", label: "Google Drive", category: "Cloud Storage", icon: siGoogledrive, keywords: ["google drive", "gdrive", "drive.google"] },
  { id: "dropbox", label: "Dropbox", category: "Cloud Storage", icon: siDropbox, keywords: ["dropbox"] },
  { id: "onedrive", label: "OneDrive", category: "Cloud Storage", badgeText: "1D", badgeHex: "0078D4", keywords: ["onedrive", "sky-drive"] },
  { id: "icloud", label: "iCloud", category: "Cloud Storage", icon: siIcloud, keywords: ["icloud", "apple cloud"] },

  { id: "zoom", label: "Zoom", category: "Productivity", icon: siZoom, keywords: ["zoom", "zoom.us"] },

  { id: "system", label: "Windows System", category: "System Artifacts", badgeText: "Win", badgeHex: "0078D7", keywords: ["windows", "system32", "registry", "sam", "security", "software", "userclass", "ntuser", "$mft", "prefetch"] },
];

const normalizeText = (value: string) =>
  value
    .toLowerCase()
    .replace(/[_\\/:.-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

export function detectArtifactProvider(text: string): ArtifactProviderDefinition | null {
  if (!text) return null;
  const normalized = normalizeText(text);
  if (!normalized) return null;

  for (const provider of PROVIDER_DEFINITIONS) {
    if (provider.keywords.some((keyword) => normalized.includes(normalizeText(keyword)))) {
      return provider;
    }
  }
  return null;
}

export function detectCategory(name: string, path: string): ArtifactCategory {
  const provider = detectArtifactProvider(name) || detectArtifactProvider(path);
  if (provider) return provider.category;

  const lowPath = path.toLowerCase();

  if (/\.(jpg|jpeg|png|gif|bmp|webp|heic|tiff|raw)$/.test(lowPath) || lowPath.includes("/photos/") || lowPath.includes("/dcim/")) {
    return "Multimedia";
  }
  if (/\.(mp4|mov|avi|mkv|wmv|flv|m4v|3gp)$/.test(lowPath) || lowPath.includes("/videos/")) {
    return "Multimedia";
  }

  if (lowPath.includes("windows") || lowPath.includes("system32") || lowPath.includes("config") || lowPath.includes("mft")) {
    return "System Artifacts";
  }

  if (lowPath.includes("chat") || lowPath.includes("message") || lowPath.includes("conversations")) {
    return "Messaging";
  }

  return "Other";
}