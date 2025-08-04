import { createFileRoute } from "@tanstack/react-router";

import { CasdoorCallbackPage } from "./CasdoorCallbackPage";

export const Route = createFileRoute("/_restrict-login-signup/auth/casdoor-callback")({
  component: CasdoorCallbackPage
});