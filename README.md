# bahari/sso-php

Framework-free PHP client for Bahari Accounts: customer sign-in (OIDC, PKCE), admin SSO, session rechecks with token
rotation, logout and back-channel logout, platform switcher, wallet links and platform APIs. Laravel apps should use
[`bahari/laravel`](https://packagist.org/packages/bahari/laravel), which wraps this package.

Only the issuer and client credentials are configured. Endpoints and the current admin host come from
`/.well-known/bahari-configuration` (cached; the last good copy is used if Bahari cannot be reached).

```php
use Bahari\Sso\{Client, Config};

$bahari = new Client(Config::fromArray([
    'issuer' => 'https://accounts.baharione.com',
    'client_id' => getenv('BAHARI_CLIENT_ID'),
    'client_secret' => getenv('BAHARI_CLIENT_SECRET'),
    'platform' => 'your-platform',
]), cache: $psr16Cache);

// 1. Start: keep the transaction in the server-side session.
$login = $bahari->beginLogin('client', 'https://your-app/auth/client/callback');
$_SESSION['bahari'][$login->state] = $login->transaction;
header('Location: '.$login->url);

// 2. Callback: check state, then finish.
$transaction = $_SESSION['bahari'][$_GET['state']] ?? null; unset($_SESSION['bahari'][$_GET['state']]);
$identity = $bahari->completeLogin($transaction, $_GET['code']);   // ->subject, ->profile, ->tokens (store encrypted)

// 3. On later requests: recheck, store rotated tokens; AccessDeniedException means sign the person out.
$identity = $bahari->refresh('client', $tokens, $subject, $secondsUntilAccessTokenExpires);

// Logout and back-channel logout
$bahari->revoke('client', $tokens);
header('Location: '.$bahari->logoutUrl('client', 'https://your-app/'));
$claims = $bahari->verifyLogoutToken($_POST['logout_token']);       // end sessions of $claims['sub'] once per jti
```

Kinds: `client` (customers) and `admin` (platform administrators via Bahari admin SSO; requires `platform`).

Pass your framework's PSR-16 cache and, for cached machine tokens, `seal`/`unseal` encryption callbacks. Implement
`Bahari\Sso\Http\HttpClient` to use another HTTP client.


## No local authentication

The app has no sign-in of its own. Bahari Accounts does sign-in, registration, passwords, password reset,
verification, 2FA and administrator sign-in. Remove any login or registration forms, password fields and local admin
logins, and store no passwords: local users keep only the Bahari ID and copies of name and email.

| Button | Route |
| --- | --- |
| Sign in | `GET /auth/login` |
| Create account | `GET /auth/register` |
| Administrator sign-in (optional) | `GET /auth/admin/login` |
| Sign out | `POST /auth/{client\|admin}/logout` |

Clicking Sign in opens Bahari ("Sign in to continue to *your app*"). After sign-in or registration Bahari sends the
person straight back to the page they wanted in your app; connected apps see no consent screen. Sign out ends the app
session and Bahari's, then returns to your home page without a confirmation page (the package sends the ID token as
`id_token_hint`).
