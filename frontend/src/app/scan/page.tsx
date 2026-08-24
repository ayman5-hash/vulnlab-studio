"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { startScan } from "@/lib/api";


const MODULES = [
  "xss",
  "sqli",
  "lfi",
  "traversal",
  "rfi",
  "auth",
];


export default function ScanPage() {
  const router = useRouter();

  const [target, setTarget] =
    useState("http://127.0.0.1:8080");

  const [mode, setMode] =
    useState<"blackbox" | "whitebox">("blackbox");

  const [difficulty, setDifficulty] =
    useState<"easy" | "medium" | "hard" | "expert">("easy");

  const [modules, setModules] =
    useState<string[]>(MODULES);

  const [sourcePath, setSourcePath] =
    useState("/opt/vulnlab/vulnerable-app");

  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");


  function toggleModule(module: string) {
    setModules((current) =>
      current.includes(module)
        ? current.filter((item) => item !== module)
        : [...current, module]
    );
  }


  async function launchScan() {
    setRunning(true);
    setError("");

    try {
      const result = await startScan({
        target,
        mode,
        difficulty,
        modules,
        ...(mode === "whitebox"
          ? { source_path: sourcePath }
          : {}),
      });

      router.push(`/scans/${result.scan_id}`);

    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Scan failed"
      );

    } finally {
      setRunning(false);
    }
  }


  return (
    <>
      <div className="eyebrow">
        // NEW SECURITY ASSESSMENT
      </div>

      <h1 className="page-title">
        Configure Scan
      </h1>

      <p className="page-description">
        Configure a controlled security assessment
        against an authorized VulnLab target.
      </p>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.2fr .8fr",
          gap: 20,
        }}
      >
        <div className="card">

          <div className="form-group">
            <label className="label">
              TARGET URL
            </label>

            <input
              className="input"
              value={target}
              onChange={(e) =>
                setTarget(e.target.value)
              }
            />
          </div>


          <div className="form-group">
            <label className="label">
              ASSESSMENT MODE
            </label>

            <select
              className="select"
              value={mode}
              onChange={(e) =>
                setMode(
                  e.target.value as
                    | "blackbox"
                    | "whitebox"
                )
              }
            >
              <option value="blackbox">
                Black Box
              </option>

              <option value="whitebox">
                White Box
              </option>
            </select>
          </div>


          {mode === "whitebox" && (
            <div className="form-group">
              <label className="label">
                AUTHORIZED SOURCE PATH
              </label>

              <input
                className="input"
                value={sourcePath}
                onChange={(e) =>
                  setSourcePath(e.target.value)
                }
              />
            </div>
          )}


          <div className="form-group">
            <label className="label">
              DIFFICULTY
            </label>

            <select
              className="select"
              value={difficulty}
              onChange={(e) =>
                setDifficulty(
                  e.target.value as
                    | "easy"
                    | "medium"
                    | "hard"
                    | "expert"
                )
              }
            >
              <option value="easy">Easy</option>
              <option value="medium">Medium</option>
              <option value="hard">Hard</option>
              <option value="expert">Expert</option>
            </select>
          </div>


          <div className="form-group">
            <label className="label">
              DETECTION MODULES
            </label>

            <div className="module-grid">
              {MODULES.map((module) => (
                <label
                  className="module-option"
                  key={module}
                >
                  <input
                    type="checkbox"
                    checked={modules.includes(module)}
                    onChange={() =>
                      toggleModule(module)
                    }
                  />

                  {module.toUpperCase()}
                </label>
              ))}
            </div>
          </div>


          <button
            className="primary-button"
            disabled={
              running ||
              modules.length === 0
            }
            onClick={launchScan}
          >
            {running
              ? "ASSESSMENT IN PROGRESS..."
              : "START ASSESSMENT"}
          </button>

        </div>


        <div className="card">
          <div className="eyebrow">
            // SCAN PROFILE
          </div>

          <h2>
            Assessment Configuration
          </h2>

          <div className="code-box">
            Target: {target}
            <br />
            Mode: {mode.toUpperCase()}
            <br />
            Difficulty: {difficulty.toUpperCase()}
            <br />
            Modules: {modules.join(", ")}
          </div>

          <p
            className="page-description"
            style={{
              fontSize: 12,
            }}
          >
            External targets are rejected by the
            scanner scope policy. RFI testing is
            restricted to the controlled loopback
            resource server.
          </p>
        </div>
      </div>
    </>
  );
}
