import type { GetServerSideProps } from "next";

export const getServerSideProps: GetServerSideProps = async () => ({
  redirect: {
    destination: "/settings/audit",
    permanent: false,
  },
});

export default function AdminAuditRedirect() {
  return null;
}
