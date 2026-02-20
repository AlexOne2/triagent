import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Legend,
  Line,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { DashboardOverview, fetchDashboardOverview } from "../lib/api";
import { useAuth } from "../lib/auth-context";

type RangePreset = "all" | "7d" | "30d" | "90d" | "custom";

function toDateInput(date: Date): string {
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function presetBounds(preset: Exclude<RangePreset, "custom">): { start: string; end: string } {
  const end = new Date();
  if (preset === "all") {
    return { start: "1970-01-01", end: toDateInput(end) };
  }
  const start = new Date();
  const days = preset === "7d" ? 7 : preset === "30d" ? 30 : 90;
  start.setDate(end.getDate() - days + 1);
  return { start: toDateInput(start), end: toDateInput(end) };
}

export default function Dashboard() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("dashboard.read");
  const canReadReports = hasPermission("reports.read");
  const [preset, setPreset] = useState<RangePreset>("90d");
  const [startDate, setStartDate] = useState<string>(presetBounds("90d").start);
  const [endDate, setEndDate] = useState<string>(presetBounds("90d").end);
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (preset === "custom") {
      return;
    }
    const next = presetBounds(preset);
    setStartDate(next.start);
    setEndDate(next.end);
  }, [preset]);

  useEffect(() => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    if (!startDate || !endDate) {
      return;
    }

    const start = new Date(`${startDate}T00:00:00.000Z`);
    const end = new Date(`${endDate}T23:59:59.999Z`);
    if (start > end) {
      setError("Start date must be before end date.");
      return;
    }

    let active = true;
    setLoading(true);
    setError(null);

    fetchDashboardOverview({
      start: start.toISOString(),
      end: end.toISOString(),
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    })
      .then((response) => {
        if (!active) return;
        setData(response);
      })
      .catch((err: Error) => {
        if (!active) return;
        setError(err.message || "Failed to load dashboard.");
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [startDate, endDate, canRead]);

  if (!canRead) {
    return (
      <main className="full">
        <h1>Overview</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  const donutData = useMemo(
    () => [
      { name: "Malicious", value: data?.malicious_safe.malicious || 0, color: "#ef476f" },
      { name: "Safe", value: data?.malicious_safe.safe || 0, color: "#2a9d8f" },
    ],
    [data]
  );

  return (
    <main className="full">
      <header className="dashboard-header">
        <div>
          <p className="dashboard-breadcrumb">Dashboard &gt; Overview</p>
          <h1>Overview</h1>
        </div>
        {canReadReports ? (
          <Link href="/reports" className="tab">
            Go to Uploads
          </Link>
        ) : null}
      </header>

      <section className="card dashboard-filter-card">
        <div className="dashboard-filter-row">
          <label className="dashboard-label" htmlFor="rangePreset">
            Date Range
          </label>
          <select
            id="rangePreset"
            className="select"
            value={preset}
            onChange={(event) => setPreset(event.target.value as RangePreset)}
          >
            <option value="all">All time</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="custom">Custom</option>
          </select>
          <input
            className="input"
            type="date"
            value={startDate}
            onChange={(event) => {
              setPreset("custom");
              setStartDate(event.target.value);
            }}
          />
          <input
            className="input"
            type="date"
            value={endDate}
            onChange={(event) => {
              setPreset("custom");
              setEndDate(event.target.value);
            }}
          />
        </div>
      </section>

      {error ? <p>{error}</p> : null}
      {loading ? <p>Loading dashboard...</p> : null}

      <section className="dashboard-kpi-row">
        <div className="dashboard-kpi-card">
          <h2>{data?.kpis.total_ingested ?? 0}</h2>
          <p>Total ingested</p>
        </div>
        <div className="dashboard-kpi-card">
          <h2>{data?.kpis.resolved_total ?? 0}</h2>
          <p>Resolved</p>
        </div>
        <div className="dashboard-kpi-card">
          <h2>{data?.kpis.resolved_malicious ?? 0}</h2>
          <p>Resolved malicious</p>
        </div>
        <div className="dashboard-kpi-card">
          <h2>{data?.kpis.resolved_safe ?? 0}</h2>
          <p>Resolved safe</p>
        </div>
      </section>

      <section className="dashboard-chart-grid">
        <div className="card">
          <h2>Resolutions</h2>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={280}>
              <ComposedChart data={data?.resolutions_timeseries || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Bar dataKey="resolved_total" fill="#ef476f" name="Resolved" />
                <Line type="monotone" dataKey="resolved_malicious" stroke="#d90429" name="Malicious" />
                <Line type="monotone" dataKey="resolved_safe" stroke="#2a9d8f" name="Safe" />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h2>Malicious/Safe</h2>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Tooltip />
                <Legend />
                <Pie
                  data={donutData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={65}
                  outerRadius={105}
                  paddingAngle={2}
                  cx="50%"
                  cy="50%"
                >
                  {donutData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h2>Classifications</h2>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={data?.classifications || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="code" interval={0} angle={-28} textAnchor="end" height={90} />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#7b61ff" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="dashboard-table-grid">
        <div className="card">
          <h2>Top 10 'To' addresses</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Email address</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {(data?.top_to_addresses || []).map((entry) => (
                <tr key={`to-${entry.rank}-${entry.email}`}>
                  <td>#{entry.rank}</td>
                  <td>{entry.email}</td>
                  <td>{entry.count}</td>
                </tr>
              ))}
              {(data?.top_to_addresses || []).length === 0 ? (
                <tr>
                  <td colSpan={3}>No data</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h2>Top 10 'From' addresses</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Email address</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {(data?.top_from_addresses || []).map((entry) => (
                <tr key={`from-${entry.rank}-${entry.email}`}>
                  <td>#{entry.rank}</td>
                  <td>{entry.email}</td>
                  <td>{entry.count}</td>
                </tr>
              ))}
              {(data?.top_from_addresses || []).length === 0 ? (
                <tr>
                  <td colSpan={3}>No data</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
