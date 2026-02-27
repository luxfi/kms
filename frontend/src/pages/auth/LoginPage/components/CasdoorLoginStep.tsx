import { useEffect } from "react";
import { faArrowRight } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import { Button } from "@app/components/v2";
import { getBrand } from "@app/lib/branding";

export const CasdoorLoginStep = () => {
  const brand = getBrand();

  const handleCasdoorLogin = () => {
    const callbackPort = new URLSearchParams(window.location.search).get("callback_port");
    const redirectUri = callbackPort ? `/dashboard?callback_port=${callbackPort}` : "/dashboard";
    window.location.href = `/api/v1/auth/casdoor/login?redirect_uri=${encodeURIComponent(redirectUri)}`;
  };

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get("error");
    if (error) {
      console.error("OAuth error:", error);
    }
  }, []);

  return (
    <div className="flex flex-col items-center space-y-8 mx-auto w-full">
      <div className="flex flex-col items-center space-y-2">
        <h1 className="text-3xl font-semibold text-gray-900 dark:text-gray-100">
          Welcome to {brand.name}
        </h1>
        <p className="text-gray-600 dark:text-gray-400 text-center">
          Sign in with your {brand.idName} to continue
        </p>
      </div>

      <div className="w-full max-w-md space-y-4">
        <Button
          colorSchema="primary"
          variant="solid"
          onClick={handleCasdoorLogin}
          isFullWidth
          size="lg"
          rightIcon={<FontAwesomeIcon icon={faArrowRight} />}
        >
          Continue with {brand.idName}
        </Button>
      </div>
    </div>
  );
};