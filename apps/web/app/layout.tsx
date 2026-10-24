import type { Metadata } from "next";
import "./globals.css";
import { TopBar } from "./TopBar";

export const metadata: Metadata = {
  title: "Sentinel — Security Checkpoints",
  description:
    "Onboarding, live scan status, and findings for the authenticated web-app security platform.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <TopBar />
        <main className="shell">{children}</main>
      </body>
    </html>
  );
}
