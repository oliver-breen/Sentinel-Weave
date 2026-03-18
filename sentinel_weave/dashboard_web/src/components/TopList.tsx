import React from "react";

type TopListItem = {
  label: string;
  value: number;
};

type TopListProps = {
  title: string;
  items: TopListItem[];
};

export default function TopList({ title, items }: TopListProps) {
  return (
    <div className="toplist">
      <h4>{title}</h4>
      <ul>
        {items.length === 0 ? (
          <li className="toplist__empty">No data yet</li>
        ) : (
          items.map((item) => (
            <li key={item.label}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}
