# Google sign-in setup

Google sign-in is optional. With both Google environment values blank, email/password authentication remains available. The application is a confidential server-side web client: keep the client secret on the server.

## Create or select the project

1. Open [Google Cloud Console](https://console.cloud.google.com/welcome) using an account permitted to manage the intended project.
2. Select a dedicated project for your copy of the lab. Open **Google Auth Platform**. Google may first offer **Get started** to create the app configuration.
3. Complete **Branding** with the app name, a monitored support email, and the required developer contact. Use domains you control for any homepage, privacy, or terms URLs you supply.
4. In **Audience**, choose the audience appropriate to the project. For a public tutorial this will usually be **External**. While the app is in **Testing**, add each account that will sign in under **Test users**.
5. In **Data Access**, request only `openid`, `email`, and `profile`. The application needs identity claims, not Gmail mailbox access. A Google/Gmail address can sign in without granting Gmail API permissions.

Console labels can change. The required outcome is an OAuth consent configuration with a Web application client and the exact redirect URI below.

## Create the Web application client

In **Clients**, create a client of type **Web application**, for example `Northstar Workspace - Lab`.

For a local copy:

| Field | Value |
| --- | --- |
| Authorized JavaScript origin, if requested | `http://localhost:3000` |
| Authorized redirect URI | `http://localhost:3000/api/auth/google/callback` |

For the SecureNow-hosted lab:

| Field | Value |
| --- | --- |
| Authorized JavaScript origin, if requested | `https://lab-auth.labs.securenow.ai` |
| Authorized redirect URI | `https://lab-auth.labs.securenow.ai/api/auth/google/callback` |

For your own deployment, substitute your origin in both places. Do not add wildcards, an extra slash, `www`, an IP address, or a different port. The server computes its callback from `APP_ORIGIN`; a mismatch causes Google to reject the callback. The browser does not need the client secret or a Google JavaScript SDK.

Copy the client ID and secret into your local private `.env`, or update the deployed lab's AWS Secrets Manager runtime secret. Never commit the downloaded client JSON, client secret, screenshots of credentials, or Google session cookies. Restart the application after updating runtime configuration. See [AWS operations](aws-deployment.md) for the deployed secret location and refresh procedure.

## Verify the complete flow

1. Open a fresh browser session and choose **Continue with Google**.
2. Confirm the consent screen shows the expected project/application and only identity scopes.
3. Sign in with an allowed Google account. Confirm the browser returns to the configured origin and the dashboard shows that account with role `member`.
4. Sign out and sign in again. Confirm the same identity is reused and no duplicate account is created.
5. Exercise the email/password account collision behavior described in the [threat model](threat-model-authentication.md). A matching email is not sufficient to silently link two authentication identities.
6. In a separate browser session, open a callback URL without a valid login transaction. Confirm it does not create a session.
7. Verify the public configuration response reveals only whether Google is enabled, and browser assets contain no client secret.

Record date, revision, environment, test-account identifier, and pass/fail result. Test-user consent and live account verification require a real authorized Google account; a unit test cannot establish that the Google project configuration works.

## Common failures

| Symptom | Check |
| --- | --- |
| Google button unavailable | Both client ID and secret are set, and the process was restarted |
| `redirect_uri_mismatch` | Exact scheme, host, port, path, and `APP_ORIGIN` |
| Access denied during testing | The chosen Google account is listed as a test user for this project |
| Callback rejected after returning | Same browser/session used, cookies enabled, HTTPS/proxy configured, and no stale login tab |
| Existing email account cannot sign in through Google | Identity linking requires a separate deliberate workflow; use its original sign-in method |

Remove test users and delete or rotate unused OAuth clients when retiring a deployment. Publishing an OAuth app is a separate Google configuration and review decision; deploying this repository does not publish the consent screen.
