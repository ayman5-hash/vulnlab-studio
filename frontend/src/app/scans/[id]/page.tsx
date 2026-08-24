import Link from "next/link";

import {
  getScan,
  reportUrl,
} from "@/lib/api";


export const dynamic = "force-dynamic";


function severityClass(
  severity: string
) {
  const value =
    severity.toLowerCase();

  if (
    value === "high" ||
    value === "critical"
  ) {
    return "badge badge-high";
  }

  if (value === "medium") {
    return "badge badge-medium";
  }

  return "badge badge-low";
}


export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{
    id: string;
  }>;
}) {
  const resolved =
    await params;

  const scan =
    await getScan(
      Number(resolved.id)
    );

  return (
    <>
      <div className="eyebrow">
        // SCAN #{scan.id}
      </div>

      <h1 className="page-title">
        Assessment Results
      </h1>

      <p className="page-description">
        {scan.target}
        {" · "}
        {scan.mode.toUpperCase()}
        {" · "}
        {scan.difficulty.toUpperCase()}
      </p>


      <div className="cards-grid">

        <div className="card">
          <div className="stat-label">
            SECURITY SCORE
          </div>

          <div className="stat-value score-value">
            {scan.security_score}/100
          </div>
        </div>


        <div className="card">
          <div className="stat-label">
            FINDINGS
          </div>

          <div className="stat-value">
            {scan.finding_count}
          </div>
        </div>


        <div className="card">
          <div className="stat-label">
            ENDPOINTS
          </div>

          <div className="stat-value">
            {
              scan.crawl
                ?.endpoints
                ?.length || 0
            }
          </div>
        </div>


        <div className="card">
          <div className="stat-label">
            PARAMETERS
          </div>

          <div className="stat-value">
            {
              scan.crawl
                ?.parameters
                ?.length || 0
            }
          </div>
        </div>

      </div>


      <div
        style={{
          display: "flex",
          gap: 10,
          marginTop: 20,
          marginBottom: 25,
        }}
      >

        <a
          href={reportUrl(scan.id)}
          className="primary-button"
          style={{
            display: "inline-flex",
            alignItems: "center",
            textDecoration: "none",
          }}
        >
          DOWNLOAD PDF REPORT
        </a>


        <Link
          href="/scan"
          className="link-button"
        >
          NEW SCAN
        </Link>

      </div>


      <div className="eyebrow">
        // SECURITY FINDINGS
      </div>


      {scan.findings.length === 0 && (
        <div className="card">
          No security findings recorded.
        </div>
      )}


      {scan.findings.map(
        (finding, index) => (
          <div
            className="card finding-card"
            key={
              finding.id ||
              index
            }
          >

            <div className="finding-header">

              <div>
                <div className="finding-title">
                  {
                    finding.vulnerability
                  }
                </div>

                <div
                  style={{
                    color: "#64748b",
                    fontSize: 11,
                    marginTop: 6,
                  }}
                >
                  {finding.cwe}
                  {" · "}
                  {finding.endpoint}

                  {finding.parameter
                    ? ` · ${finding.parameter}`
                    : ""}
                </div>
              </div>


              <span
                className={
                  severityClass(
                    finding.severity
                  )
                }
              >
                {finding.severity}
              </span>

            </div>


            <h4>
              Detection
            </h4>

            <p className="page-description">
              {
                finding
                  .detection_method
              }
            </p>


            <h4>
              Evidence
            </h4>

            <div className="code-box">
              {finding.evidence}
            </div>


            <h4>
              Recommendation
            </h4>

            <p className="page-description">
              {
                finding
                  .recommendation
              }
            </p>


            <div
              style={{
                color: "#64748b",
                fontSize: 10,
              }}
            >
              Confidence:{" "}
              {
                Math.round(
                  finding
                    .confidence *
                    100
                )
              }
              %
            </div>

          </div>
        )
      )}


      {
        scan.mode === "whitebox" &&
        scan.whitebox_hits.length > 0 &&
        (
          <>
            <div
              className="eyebrow"
              style={{
                marginTop: 35,
              }}
            >
              // WHITE BOX CORRELATION
            </div>

            <div className="card">

              {
                scan.whitebox_hits.map(
                  (hit, index) => (
                    <div
                      className="code-box"
                      style={{
                        marginBottom: 9,
                      }}
                      key={
                        hit.id ||
                        index
                      }
                    >
                      [{hit.category}]{" "}
                      {hit.pattern}

                      <br />

                      {hit.file}
                    </div>
                  )
                )
              }

            </div>
          </>
        )
      }

    </>
  );
}
