import React from "react";

type PanelProps = {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  className?: string;
};

export default function Panel({ title, subtitle, children, className }: PanelProps) {
  return (
    <section className={`panel ${className ?? ""}`.trim()}>
      <header className="panel__header">
        <div>
          <h3>{title}</h3>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
      </header>
      <div className="panel__body">{children}</div>
    </section>
  );
}
