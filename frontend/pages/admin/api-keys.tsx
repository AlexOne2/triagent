import type { GetServerSideProps } from "next";

export const getServerSideProps: GetServerSideProps = async () => ({
  redirect: {
    destination: "/settings/api-keys",
    permanent: false,
  },
});

export default function AdminApiKeysRedirect() {
  return null;
}
