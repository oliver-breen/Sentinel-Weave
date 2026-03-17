const formatTime = (iso) => {
  if (!iso) return "--";
  const d = new Date(iso);
  return d.toLocaleTimeString();
};

const el = (id) => document.getElementById(id);

const renderSummary = (data) => {
  el("total-events").textContent = data.total_events ?? 0;
  const highThreats = (data.high ?? 0) + (data.critical ?? 0);
  el("high-threats").textContent = highThreats;
  el("avg-anomaly").textContent = (data.avg_anomaly_score ?? 0).toFixed(3);
  el("emails-scanned").textContent = data.emails_scanned ?? 0;

  const breakdown = el("threat-breakdown");
  breakdown.innerHTML = "";
  [
    ["Benign", data.benign ?? 0],
    ["Low", data.low ?? 0],
    ["Medium", data.medium ?? 0],
    ["High", data.high ?? 0],
    ["Critical", data.critical ?? 0],
  ].forEach(([label, count]) => {
    const row = document.createElement("div");
    row.className = "timeline-item";
    row.innerHTML = `<strong>${label}</strong><span>${count} events</span>`;
    breakdown.appendChild(row);
  });

  const sources = el("top-sources");
  sources.innerHTML = "";
  (data.top_sources ?? []).slice(0, 6).forEach(([src, count]) => {
    const row = document.createElement("div");
    row.className = "timeline-item";
    row.innerHTML = `<strong>${src}</strong><span>${count} hits</span>`;
    sources.appendChild(row);
  });
};

const renderEvents = (events) => {
  const tbody = el("event-table");
  tbody.innerHTML = "";
  events.forEach((evt) => {
    const tr = document.createElement("tr");
    const severity = evt.threat_level ?? "--";
    tr.innerHTML = `
      <td>${formatTime(evt.timestamp)}</td>
      <td>${evt.source_ip ?? "--"}</td>
      <td>${evt.event_type ?? "--"}</td>
      <td class="severity ${severity}">${severity}</td>
      <td>${(evt.anomaly_score ?? 0).toFixed(3)}</td>
    `;
    tbody.appendChild(tr);
  });
};

const refresh = async () => {
  const summary = await fetch("/api/summary").then((r) => r.json());
  renderSummary(summary);
  const events = await fetch("/api/events?n=30").then((r) => r.json());
  renderEvents(events);
};

const connectStream = () => {
  const source = new EventSource("/api/stream");
  source.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type === "metrics") {
        renderSummary(payload.data);
      }
    } catch (err) {
      console.warn("stream parse error", err);
    }
  };
  source.onerror = () => {
    el("status-dot").style.background = "#c26b6b";
    el("status-text").textContent = "Stream disconnected";
    source.close();
    setTimeout(connectStream, 3000);
  };
};

refresh();
connectStream();
setInterval(refresh, 15000);
