import { useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";

export const CasdoorCallbackPage = () => {
  const navigate = useNavigate();

  useEffect(() => {
    // Backend handles OAuth callback and sets cookies directly.
    // If we reach this page, redirect to dashboard (cookies are already set).
    const params = new URLSearchParams(window.location.search);
    if (params.get("error")) {
      navigate({ to: "/login" });
    } else {
      navigate({ to: "/organization/projects" });
    }
  }, [navigate]);

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-bunker-800">
      <p className="text-gray-400">Authenticating...</p>
    </div>
  );
};
