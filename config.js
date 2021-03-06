const env = process.env;

const config = {
  ms: {
    OAUTH_APP_ID: "24e18d20-d5ce-4b2a-9e75-7bd9b8f401a6",
    OAUTH_APP_PASSWORD: "6_VrISo32O1n-9sK7LqB6D-3s2i-5434mC",
    OAUTH_REDIRECT_URI:
      env.MS_CALLBACK || "http://localhost:3000/auth/callback",
    OAUTH_SCOPES: "profile offline_access user.read calendars.read",
    OAUTH_AUTHORITY: "https://login.microsoftonline.com/common",
    OAUTH_ID_METADATA: "/v2.0/.well-known/openid-configuration",
    OAUTH_AUTHORIZE_ENDPOINT: "/oauth2/v2.0/authorize",
    OAUTH_TOKEN_ENDPOINT: "/oauth2/v2.0/token",
  },
};

module.exports = config;
