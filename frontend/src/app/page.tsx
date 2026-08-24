import Link from "next/link";

import {
  getScans,
  type ScanSummary,
} from "@/lib/api";


export const dynamic = "force-dynamic";


export default async function Dashboard() {
  let scans: ScanSummary[] = [];

  try {
    scans = await getScans();
  } catch {
    scans = [];
  }

  const totalFindings = scans.reduce(
    (sum, scan) => sum + scan.finding_count,
    0
  );

  const averageScore = scans.length
    ? Math.round(
        scans.reduce(
          (sum, scan) => sum + scan.security_score,
          0
        ) / scans.length
      )
    : 100;

  const latest = scans.slice(0, 8);

  return (
    <>
      <div className="eyebrow">
        // SECURITY OVERVIEW
      </div>

      <h1 className="page-title">
        Vulnerability Assessment Dashboard
      </h1>

      <p className="page-description">
        Local Black Box and White Box security assessment
        workspace for the isolated VulnLab environment.
      </p>

      <div className="cards-grid">
        <div className="card">
          <div className="stat-label">
            TOTAL SCANS
          </div>

          <div className="stat-value">
            {scans.length}
          </div>
        </div>

        <div className="card">
          <div className="stat-label">
            TOTAL FINDINGS
          </div>

          <div className="stat-value">
            {totalFindings}
          </div>
        </div>

        <div className="card">
          <div className="stat-label">
            AVERAGE SCORE
          </div>

          <div className="stat-value score-value">
            {averageScore}/100
          </div>
        </div>

        <div className="card">
          <div className="stat-label">
            SCANNER STATUS
          </div>

          <div
            className="stat-value"
            style={{
              color: "#34d399",
              fontSize: 18,
            }}
          >
            ● ONLINE
          </div>
        </div>
      </div>

      <div
        className="card"
        style={{
          marginTop: 25,
        }}
      >
        <div className="eyebrow">
          // RECENT ASSESSMENTS
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <h2>
            Recent Scans
          </h2>

          <Link
            href="/scan"
            className="link-button"
          >
            NEW SCAN
          </Link>
        </div>

        <table className="scan-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>TARGET</th>
              <th>MODE</th>
              <th>DIFFICULTY</th>
              <th>FINDINGS</th>
              <th>SCORE</th>
            </tr>
          </thead>

          <tbody>
            {latest.map((scan) => (
              <tr key={scan.id}>
                <td>
                  <Link
                    href={`/scans/${scan.id}`}
                  >
                    #{scan.id}
                  </Link>
                </td>

                <td>
                  {scan.target}
                </td>

                <td>
                  {scan.mode.toUpperCase()}
                </td>

                <td>
                  {scan.difficulty.toUpperCase()}
                </td>

                <td>
                  {scan.finding_count}
                </td>

                <td>
                  {scan.security_score}/100
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {latest.length === 0 && (
          <p className="page-description">
            No persisted scans yet.
          </p>
        )}
      </div>
    </>
  );
}
