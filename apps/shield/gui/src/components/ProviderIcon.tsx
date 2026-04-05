import type { ReactNode } from "react";
import { detectArtifactProvider } from "@/lib/artifactProviders";
import { cn } from "@/lib/utils";

interface ProviderIconProps {
  text: string;
  className?: string;
  size?: number;
  fallback?: ReactNode;
}

export default function ProviderIcon({
  text,
  className,
  size = 14,
  fallback = null,
}: ProviderIconProps) {
  const provider = detectArtifactProvider(text);
  if (!provider) return <>{fallback}</>;

  if (!provider.icon) {
    return (
      <span
        className={cn("fs-provider-icon fs-provider-badge", className)}
        title={provider.label}
        aria-label={provider.label}
        style={{ backgroundColor: `#${provider.badgeHex || "3a3a3a"}` }}
      >
        {provider.badgeText || provider.label.charAt(0).toUpperCase()}
      </span>
    );
  }

  return (
    <span className={cn("fs-provider-icon", className)} title={provider.label} aria-label={provider.label}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        role="img"
        aria-hidden="true"
        focusable="false"
      >
        <path d={provider.icon.path} fill={`#${provider.icon.hex}`} />
      </svg>
    </span>
  );
}
