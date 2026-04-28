export async function getServerSideProps() {
  return {
    redirect: {
      destination: "/login",
      permanent: false,
    },
  };
}

export default function IndexRedirect() {
  return null;
}
