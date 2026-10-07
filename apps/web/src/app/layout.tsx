import type { Metadata } from "next";
import "./styles.css";

export const metadata: Metadata = {
  title: "TraceLens AI",
  description: "AI-powered trace analyzer for telecom and network protocol troubleshooting.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

