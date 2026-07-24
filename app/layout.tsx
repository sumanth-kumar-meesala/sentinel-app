import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

const plexSans = IBM_Plex_Sans({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});
const plexMono = IBM_Plex_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  title: "Sentinel — Domain Exposure Scanner",
  description: "Find out if a domain's passwords, keys, or tokens are exposed. Open-source OSINT, one console.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-theme="sentinel" className={`${plexSans.variable} ${plexMono.variable} h-full antialiased`}>
      <body className="min-h-full relative">
        <div className="atmosphere" aria-hidden />
        {children}
      </body>
    </html>
  );
}
