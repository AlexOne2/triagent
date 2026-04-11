import type { GetServerSideProps } from "next";

export const getServerSideProps: GetServerSideProps = async () => ({
  redirect: {
    destination: "/settings/users",
    permanent: false,
  },
});

export default function SettingsRedirectPage() {
  return null;
}
