import type { GetServerSideProps } from "next";

export const getServerSideProps: GetServerSideProps = async () => ({
  redirect: {
    destination: "/reports",
    permanent: false,
  },
});

export default function ClosedReportsRedirect() {
  return null;
}
