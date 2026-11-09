import { useState } from "react";
import { numberLabel, timeLabel } from "../utils/format";

const WINDOWS = [
  { id: "1h", label: "1 giờ", minutes: 60 },
  { id: "6h", label: "6 giờ", minutes: 360 },
  { id: "24h", label: "24 giờ", minutes: 1440 },
];

const WIDTH = 760,
  HEIGHT = 214,
  LEFT = 38,
  RIGHT = 12,
  TOP = 14,
  BOTTOM = 28;

export default function ActivityChart({
  activity,
  window,
  onWindowChange,
  busy,
}) {
  const [hovered, setHovered] = useState(null);
  const data = activity.chart;
  const peak = Math.max(...data.flatMap(point => [point.allowed, point.blocked]), 1);
  const step = peak <= 10 ? 1 : peak <= 50 ? 5 : 50;
  const max = Math.ceil(peak / step) * step;
  const plotWidth = WIDTH - LEFT - RIGHT;
  const plotHeight = HEIGHT - TOP - BOTTOM;
  const x = (index) => LEFT + (index * plotWidth) / Math.max(1, data.length - 1);
  const y = (value) => TOP + plotHeight - (value / max) * plotHeight;
  const path = (field) =>
    data
      .map(
        (point, index) =>
          `${index === 0 ? "M" : "L"} ${x(index)} ${y(point[field])}`,
      )
      .join(" ");
  const current = hovered === null ? null : data[hovered];

  return (
    <section className="panel activity-panel" aria-labelledby="activity-title">
      <div className="panel-heading">
        <div>
          <h2 id="activity-title">Hoạt động truy vấn</h2>
          <p>Lưu lượng SQL qua DB Firewall</p>
        </div>
        <div className="segmented" aria-label="Khoảng thời gian biểu đồ">
          {WINDOWS.map((period) => (
            <button
              key={period.id}
              aria-pressed={window === period.id}
              className={window === period.id ? "selected" : ""}
              onClick={() => onWindowChange(period.id)}
              disabled={busy}
            >
              {period.label}
            </button>
          ))}
        </div>
      </div>
      <div className="chart-summary">
        <div>
          <strong>{numberLabel(activity.total)}</strong>
          <span>truy vấn</span>
        </div>
        <div className="chart-legends">
          <span>
            <i className="legend-dot allowed" />
            Allowed <b>{numberLabel(activity.allowed)}</b>
          </span>
          <span>
            <i className="legend-dot blocked" />
            Blocked <b>{numberLabel(activity.blocked)}</b>
          </span>
        </div>
      </div>
      <div className="chart-wrap" onMouseLeave={() => setHovered(null)}>
        {current && (
          <div
            className="chart-tooltip"
            style={{
              left: `${Math.min(82, Math.max(16, (x(hovered) / WIDTH) * 100))}%`,
            }}
            role="status"
          >
            <strong>{timeLabel(current.time)}</strong>
            <span>Allowed: {numberLabel(current.allowed)}</span>
            <span>Blocked: {numberLabel(current.blocked)}</span>
          </div>
        )}
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          role="img"
          aria-label={`Biểu đồ ${WINDOWS.find((item) => item.id === window).label}: ${activity.allowed} truy vấn được phép, ${activity.blocked} bị chặn.`}
        >
          <defs>
            <linearGradient id="allowed-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#4b84f5" stopOpacity=".18" />
              <stop offset="100%" stopColor="#4b84f5" stopOpacity=".01" />
            </linearGradient>
          </defs>
          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => (
            <g key={ratio}>
              <line
                x1={LEFT}
                x2={WIDTH - RIGHT}
                y1={y(max * ratio)}
                y2={y(max * ratio)}
                stroke="#e9edf4"
                strokeDasharray="4 5"
              />
              <text
                x={LEFT - 12}
                y={y(max * ratio) + 4}
                textAnchor="end"
                className="chart-label"
              >
                {numberLabel(max * ratio)}
              </text>
            </g>
          ))}
          <path
            d={`${path("allowed")} L ${x(data.length - 1)} ${y(0)} L ${x(0)} ${y(0)} Z`}
            fill="url(#allowed-fill)"
          />
          <path
            d={path("allowed")}
            fill="none"
            stroke="#3978ed"
            strokeWidth="2.8"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
          <path
            d={path("blocked")}
            fill="none"
            stroke="#ef7768"
            strokeWidth="2.6"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
          {data.map((point, index) => (
            <g key={point.time}>
              {(index % 2 === 0 || index === data.length - 1) && (
                <text
                  x={x(index)}
                  y={HEIGHT - 6}
                  textAnchor="middle"
                  className="chart-label"
                >
                  {timeLabel(point.time)}
                </text>
              )}
              <rect
                x={x(index) - plotWidth / 22}
                y={TOP}
                width={plotWidth / 11}
                height={plotHeight}
                fill="transparent"
                onMouseEnter={() => setHovered(index)}
              />
            </g>
          ))}
          {hovered !== null && (
            <g pointerEvents="none">
              <line
                x1={x(hovered)}
                x2={x(hovered)}
                y1={TOP}
                y2={y(0)}
                stroke="#a6b9d8"
                strokeDasharray="3 4"
              />
              <circle
                cx={x(hovered)}
                cy={y(current.allowed)}
                r="4.5"
                stroke="white"
                strokeWidth="2"
                fill="#3978ed"
              />
              <circle
                cx={x(hovered)}
                cy={y(current.blocked)}
                r="4"
                stroke="white"
                strokeWidth="2"
                fill="#ef7768"
              />
            </g>
          )}
        </svg>
      </div>
      <div className="chart-footnote">
        <span className="status-dot blue" />
        {activity.bucketMinutes ?? WINDOWS.find((item) => item.id === window).minutes / 12} phút / điểm dữ
        liệu
        <span className="chart-rate">
          Tỷ lệ chặn <b>{activity.blockRate.toFixed(2).replace(".", ",")}%</b>
        </span>
      </div>
    </section>
  );
}
