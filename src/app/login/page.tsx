import { Suspense } from "react";

import { SSO } from "@/lib/sso";
import { LoginForm } from "@/components/auth/login-form";

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm sso={SSO ? { name: SSO.name } : null} />
    </Suspense>
  );
}
