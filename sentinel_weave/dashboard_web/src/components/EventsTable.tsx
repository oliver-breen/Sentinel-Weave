import React from "react";
import { ThreatEvent } from "../lib/types";

const levelTone: Record<string, string> = {
  CRITICAL: "badge--critical",
  HIGH: "badge--high",
  MEDIUM: "badge--medium",
  LOW: "badge--low",
  BENIGN: "badge--benign",
};

type EventsTableProps = {
  events: ThreatEvent[];
};

export default function EventsTable({ events }: EventsTableProps) {
  return (
    <div className="table">
      <div className="table__header">
        <span>Time</span>
        <span>Source</span>
        <span>Type</span>
        <span>Threat</span>
        <span>Score</span>
      </div>
      {events.length === 0 ? (
        <div className="table__empty">No events received yet.</div>
      ) : (
        events.map((event, index) => (
          <div className="table__row" key={`${event.ts ?? ""}-${index}`}>
            <span>{event.ts ? new Date(event.ts).toLocaleTimeString() : "—"}</span>
            <span>{event.source_ip ?? "—"}</span>
            <span>{event.event_type ?? "—"}</span>
            <span className={`badge ${levelTone[event.threat_level] ?? "badge--low"}`}>
              {event.threat_level}
            </span>
            <span>{event.score.toFixed(2)}</span>
          </div>
        ))
      )}
    </div>
  );
}
