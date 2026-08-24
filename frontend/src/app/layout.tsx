import type { Metadata } from "next";
import Link from "next/link";

import {
  Activity,
  FileSearch,
  History,
  Radar,
  Shield,
} from "lucide-react";

import "./globals.css";

export const metadata: Metadata = {
  title: "VulnLab Studio",
  description: "Local Web Security Assessment Studio",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <div className="background-grid" />

        <div className="app-shell">
          <aside className="sidebar">
            <div className="brand">
              <div className="brand-logo">
                <Shield size={22} />
              </div>

              <div>
                <div className="brand-name">VULNLAB</div>
                <div className="brand-subtitle">SECURITY STUDIO</div>
              </div>
            </div>

            <nav>
              <Link href="/" className="nav-link">
                <Activity size={18} />
                Dashboard
              </Link>

              <Link href="/scan" className="nav-link">
                <Radar size={18} />
                New Scan
              </Link>

              <Link href="/history" className="nav-link">
                <History size={18} />
                Scan History
              </Link>
            </nav>

            <div className="sidebar-status">
              <div className="status-title">LAB ENVIRONMENT</div>

              <div className="status-line">
                <span className="online-dot" />
                Scanner API
              </div>
              <div className="endpoint">127.0.0.1:8000</div>

              <div className="status-line">
                <span className="online-dot" />
                Target
              </div>
              <div className="endpoint">127.0.0.1:8080</div>

              <div className="status-line">
                <span className="online-dot" />
                RFI Resource
              </div>
              <div className="endpoint">127.0.0.1:9000</div>
            </div>
          </aside>

          <main className="main-content">
            <header className="topbar">
              <div>
                <div className="breadcrumb">
                  VULNLAB / LOCAL SECURITY ASSESSMENT
                </div>

                <div className="top-title">
                  Web Security Research Studio
                </div>
              </div>

              <div className="lab-only">
                <FileSearch size={15} />
                ISOLATED LAB
              </div>
            </header>

            <div className="page-container">{children}</div>
          </main>
        </div>
      </body>
    </html>
  );
}
