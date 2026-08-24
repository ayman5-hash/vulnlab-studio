import Link from "next/link";

import {
  getScans,
  type ScanSummary,
} from "@/lib/api";


export const dynamic = "force-dynamic";


export default async function HistoryPage() {
  let scans: ScanSummary[] = [];

  try {
    scans = await getScans();
  } catch {
    scans = [];
  }

  return (
    <>
      <div className="eyebrow">
        // ASSESSMENT HISTORY
      </div>

      <h1 className="page-title">
        Scan History
      </h1>

      <p className="page-description">
        Persisted Black Box and White Box assessments
        stored by the VulnLab Scanner API.
      </p>

      <div className="card">
        <table className="scan-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>TARGET</th>
              <th>MODE</th>
              <th>DIFFICULTY</th>
              <th>FINDINGS</th>
              <th>SCORE</th>
              <th>DATE</th>
            </tr>
          </thead>

          <tbody>
            {scans.map((scan) => (
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

                <td>
                  {new Date(
                    scan.created_at
                  ).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {scans.length === 0 && (
          <p className="page-description">
            No scans stored yet.
          </p>
        )}
      </div>
    </>
  );
}
