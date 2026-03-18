import React from "react";

type StatCardProps = {
  label: string;
  value: string | number;
  trend?: string;
  tone?: "neutral" | "good" | "warn" | "bad";
};

export default function StatCard({ label, value, trend, tone = "neutral" }: StatCardProps) {
  return (
    <div className={`stat-card stat-card--${tone}`}>
      <p className="stat-card__label">{label}</p>
      <div className="stat-card__value">
        <span>{value}</span>
        {trend ? <small>{trend}</small> : null}
      </div>
    </div>
  );
}
