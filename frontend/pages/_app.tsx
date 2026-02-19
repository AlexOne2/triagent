import type { AppProps } from "next/app";
import AppHeader from "../components/AppHeader";
import "../styles/globals.css";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <>
      <AppHeader />
      <Component {...pageProps} />
    </>
  );
}
