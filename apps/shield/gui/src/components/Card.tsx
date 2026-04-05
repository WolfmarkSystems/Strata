import type { ReactNode } from "react";

interface CardProps {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}

export default function Card({
  title,
  subtitle,
  actions,
  className,
  bodyClassName,
  children,
}: CardProps) {
  return (
    <section className={`fs-card ${className || ""}`}>
      {(title || subtitle || actions) && (
        <header className="fs-card-header">
          <div>
            {title && <h2 className="fs-card-title">{title}</h2>}
            {subtitle && <p className="fs-card-subtitle">{subtitle}</p>}
          </div>
          {actions && <div>{actions}</div>}
        </header>
      )}
      <div className={`fs-card-body ${bodyClassName || ""}`}>{children}</div>
    </section>
  );
}
