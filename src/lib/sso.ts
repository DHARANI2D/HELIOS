// Single sign-on for staff with the company's OpenID Connect identity
// provider (Entra ID, Okta, Google, Keycloak…), configured by environment.
// Only existing, active staff accounts can sign in this way, matched by
// verified email (lib/auth); the identity provider enforces its own MFA.
export const SSO = process.env.HELIOS_SSO_ISSUER
  ? { id: "sso", name: process.env.HELIOS_SSO_NAME || "single sign-on", issuer: process.env.HELIOS_SSO_ISSUER }
  : null;
