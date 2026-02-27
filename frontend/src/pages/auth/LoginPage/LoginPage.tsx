import { useEffect } from "react";
import { Helmet } from "react-helmet";
import { Link } from "@tanstack/react-router";

import { isLoggedIn } from "@app/hooks/api/reactQuery";
import { getBrand } from "@app/lib/branding";

import { CasdoorLoginStep } from "./components/CasdoorLoginStep";
import { useNavigateToSelectOrganization } from "./Login.utils";

export const LoginPage = (_props: { isAdmin?: boolean }) => {
  const { navigateToSelectOrganization } = useNavigateToSelectOrganization();
  const brand = getBrand();

  const queryParams = new URLSearchParams(window.location.search);

  useEffect(() => {
    const handleRedirects = async () => {
      try {
        const callbackPort = queryParams?.get("callback_port");
        if (callbackPort) {
          navigateToSelectOrganization(callbackPort);
        } else {
          navigateToSelectOrganization();
        }
      } catch {
        console.log("Error - Not logged in yet");
      }
    };

    if (isLoggedIn()) {
      handleRedirects();
    }
  }, []);

  const renderView = () => {
    return <CasdoorLoginStep />;
  };

  return (
    <div className="flex max-h-screen min-h-screen flex-col justify-center overflow-y-auto bg-gradient-to-tr from-mineshaft-600 via-mineshaft-800 to-bunker-700 px-6">
      <Helmet>
        <title>{brand.name}</title>
        <link rel="icon" href={brand.favicon} />
        <meta property="og:image" content="/images/message.png" />
        <meta property="og:title" content={`Log In to ${brand.name}`} />
        <meta name="og:description" content={`${brand.name} — secure secret management`} />
      </Helmet>
      <Link to="/">
        <div className="mb-4 mt-20 flex justify-center">
          <img
            src={brand.logo}
            style={{
              height: "90px",
              width: "90px"
            }}
            alt={`${brand.name} logo`}
          />
        </div>
      </Link>
      <div className="pb-28">{renderView()}</div>
    </div>
  );
};
