import { useEffect, useState } from "react";
import { Helmet } from "react-helmet";
import { faArrowRight } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { AxiosError } from "axios";
import { addSeconds, formatISO } from "date-fns";

import { createNotification } from "@app/components/notifications";
import { SessionStorageKeys } from "@app/const";
import { ROUTE_PATHS } from "@app/const/routes";
import { useGetActiveSharedSecretById } from "@app/hooks/api/secretSharing";

import { PasswordContainer, SecretContainer, SecretErrorContainer } from "./components";
import { getBrand } from "@app/lib/branding";

const extractDetailsFromUrl = (urlEncodedKey: string) => {
  if (urlEncodedKey) {
    const [hashedHex, key] = urlEncodedKey ? urlEncodedKey.toString().split("-") : ["", ""];

    return {
      hashedHex,
      key
    };
  }

  return {
    hashedHex: null,
    key: null
  };
};

export const ViewSharedSecretByIDPage = () => {
  const id = useParams({
    from: ROUTE_PATHS.Public.ViewSharedSecretByIDPage.id,
    select: (el) => el.secretId
  });
  const urlEncodedKey = useSearch({
    from: ROUTE_PATHS.Public.ViewSharedSecretByIDPage.id,
    select: (el) => el.key
  });
  const [password, setPassword] = useState<string>();
  const { hashedHex, key } = extractDetailsFromUrl(urlEncodedKey);

  const {
    data: fetchSecret,
    error,
    isPending,
    isFetching
  } = useGetActiveSharedSecretById({
    sharedSecretId: id,
    hashedHex,
    password
  });

  const navigate = useNavigate();

  const isUnauthorized =
    ((error as AxiosError)?.response?.data as { statusCode: number })?.statusCode === 401;

  const isInvalidCredential =
    ((error as AxiosError)?.response?.data as { message: string })?.message ===
    "Invalid credentials";

  const isEmailUnauthorized =
    ((error as AxiosError)?.response?.data as { message: string })?.message ===
    "Email not authorized to view secret";

  useEffect(() => {
    if (isUnauthorized && !isInvalidCredential && !isEmailUnauthorized) {
      // persist current URL in session storage so that we can come back to this after successful login
      sessionStorage.setItem(
        SessionStorageKeys.ORG_LOGIN_SUCCESS_REDIRECT_URL,
        JSON.stringify({
          expiry: formatISO(addSeconds(new Date(), 60)),
          data: window.location.href
        })
      );

      createNotification({
        type: "info",
        text: "Login is required in order to access the shared secret."
      });

      navigate({
        to: "/login"
      });

      return;
    }

    if (error) {
      createNotification({
        type: "error",
        text: ((error as AxiosError)?.response?.data as { message: string })?.message
      });
    }
  }, [error]);

  const shouldShowPasswordPrompt =
    isInvalidCredential || (fetchSecret?.isPasswordProtected && !fetchSecret.secret);
  const isValidatingPassword = Boolean(password) && isFetching;

  return (
    <>
      <Helmet>
        <title>Securely Share Secrets | KMS</title>
        <link rel="icon" href={getBrand().favicon} />
        <meta property="og:image" content="/images/message.png" />
        <meta property="og:title" content="" />
        <meta name="og:description" content="" />
      </Helmet>
      <div className="flex h-screen flex-col justify-between overflow-auto bg-gradient-to-tr from-mineshaft-700 to-bunker-800 text-gray-200 dark:[color-scheme:dark]">
        <div />
        <div className="mx-auto w-full max-w-xl px-4 py-4 md:px-0">
          <div className="mb-8 text-center">
            <div className="mb-4 flex justify-center pt-8">
              <a target="_blank" rel="noopener noreferrer" href="https://lux.network">
                <img
                  src={getBrand().logo}
                  height={90}
                  width={120}
                  alt={`${getBrand().name} logo`}
                  className="cursor-pointer"
                />
              </a>
            </div>
            <h1 className="bg-gradient-to-b from-white to-bunker-200 bg-clip-text text-center text-4xl font-medium text-transparent">
              View shared secret
            </h1>
            <p className="text-md">
              Powered by{" "}
              <a
                href="https://github.com/kms/kms"
                target="_blank"
                rel="noopener noreferrer"
                className="text-bold bg-gradient-to-tr from-yellow-500 to-primary-500 bg-clip-text text-transparent"
              >
                KMS &rarr;
              </a>
            </p>
          </div>
          {(shouldShowPasswordPrompt || isValidatingPassword) && (
            <PasswordContainer
              isSubmitting={isValidatingPassword}
              onPasswordSubmit={(el) => {
                setPassword(el);
              }}
              isInvalidCredential={!isFetching && isInvalidCredential}
            />
          )}
          {!isPending && (
            <>
              {!error && fetchSecret?.secret && (
                <SecretContainer secret={fetchSecret.secret} secretKey={key} />
              )}
              {error && !isInvalidCredential && !isUnauthorized && <SecretErrorContainer />}
            </>
          )}
          <div className="m-auto my-8 flex w-full">
            <div className="w-full border-t border-mineshaft-600" />
          </div>
          <div className="m-auto flex w-full flex-col rounded-md border border-primary-500/30 bg-primary/5 p-6 pt-5">
            <p className="w-full pb-2 text-lg font-semibold text-mineshaft-100 md:pb-3 md:text-xl">
              Open source{" "}
              <span className="bg-gradient-to-tr from-yellow-500 to-primary-500 bg-clip-text text-transparent">
                secret management
              </span>{" "}
              for developers
            </p>
            <div className="flex flex-col items-start sm:flex-row sm:items-center">
              <p className="md:text-md text-md mr-4">
                <a
                  href="https://github.com/kms/kms"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-bold bg-gradient-to-tr from-yellow-500 to-primary-500 bg-clip-text text-transparent"
                >
                  KMS
                </a>{" "}
                is the all-in-one secret management platform to securely manage secrets, configs,
                and certificates across your team and infrastructure.
              </p>
              <div className="mt-4 cursor-pointer sm:mt-0">
                <a target="_blank" rel="noopener noreferrer" href="https://lux.network">
                  <div className="flex items-center justify-between rounded-md border border-mineshaft-400/40 bg-mineshaft-600 px-3 py-2 duration-200 hover:border-primary/60 hover:bg-primary/20 hover:text-white">
                    <p className="mr-4 whitespace-nowrap">Try KMS</p>
                    <FontAwesomeIcon icon={faArrowRight} />
                  </div>
                </a>
              </div>
            </div>
          </div>
        </div>
        <div className="w-full bg-mineshaft-600 p-2">
          <p className="text-center text-sm text-mineshaft-300">
            Made with ❤️ by{" "}
            <a className="text-primary" href="https://lux.network">
              KMS
            </a>
            <br />
            235 2nd st, San Francisco, California, 94105, United States. 🇺🇸
          </p>
        </div>
      </div>
    </>
  );
};
