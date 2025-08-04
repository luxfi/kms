import { useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useSearchParams } from "@tanstack/react-router";

import { useAuthStore } from "@app/hooks/api/auth/useAuthStore";
import { Lottie } from "@app/components/v2";

export const CasdoorCallbackPage = () => {
  const navigate = useNavigate();
  const searchParams = useSearchParams();
  const { setAccessToken, setRefreshToken } = useAuthStore();
  
  useEffect(() => {
    const handleCallback = async () => {
      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const error = searchParams.get("error");
      
      if (error) {
        console.error("OAuth error:", error);
        navigate({ to: "/login", search: { error } });
        return;
      }
      
      if (code) {
        try {
          // The backend will handle the OAuth callback and set cookies
          // The cookies will be automatically included in subsequent requests
          const callbackUrl = new URL(window.location.href);
          
          // Redirect to backend callback endpoint
          window.location.href = `/api/v1/auth/casdoor/callback?${callbackUrl.search}`;
        } catch (err) {
          console.error("Callback error:", err);
          navigate({ to: "/login", search: { error: "callback_failed" } });
        }
      } else {
        navigate({ to: "/login" });
      }
    };
    
    handleCallback();
  }, [searchParams, navigate, setAccessToken, setRefreshToken]);
  
  return (
    <div className="flex h-screen w-screen items-center justify-center bg-bunker-800">
      <div className="flex flex-col items-center space-y-4">
        <Lottie isAutoPlay icon="kms_loading" className="h-32 w-32" />
        <p className="text-gray-400">Authenticating...</p>
      </div>
    </div>
  );
};