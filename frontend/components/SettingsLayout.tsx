import { ReactNode } from "react";
import SettingsNav from "./SettingsNav";

type SettingsLayoutProps = {
  title: string;
  description?: string;
  children: ReactNode;
};

export default function SettingsLayout({ title, description, children }: SettingsLayoutProps) {
  return (
    <main className="full settings-page">
      <div className="settings-shell">
        <SettingsNav />
        <section className="settings-content">
          <header className="settings-header">
            <div>
              <p className="settings-eyebrow">Settings</p>
              <h1>{title}</h1>
              {description ? <p>{description}</p> : null}
            </div>
          </header>
          {children}
        </section>
      </div>
    </main>
  );
}
