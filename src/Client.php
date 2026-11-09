<?php

namespace Bahari\Sso;

use Bahari\Sso\Cache\ArrayCache;
use Bahari\Sso\Exception\AccessDeniedException;
use Bahari\Sso\Exception\BahariException;
use Bahari\Sso\Exception\HttpException;
use Bahari\Sso\Http\CurlHttpClient;
use Bahari\Sso\Http\HttpClient;
use Bahari\Sso\Http\Response;
use Closure;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * Bahari Accounts for one app. Only the issuer and the client credentials are configured; every endpoint, including the
 * admin host, comes from /.well-known/bahari-configuration, so Bahari can move domains without app changes.
 *
 * Kinds: "client" signs in customers with OIDC authorization code + PKCE. "admin" signs in platform administrators
 * through Bahari's admin SSO and a server-to-server exchange.
 */
class Client
{
    public const KINDS = ['client', 'admin'];

    private ?Discovery $discovery = null;

    private ?string $sdkStatus = null;

    private ?TokenVerifier $verifier = null;

    /**
     * @param  string  $sdk  Sent as X-Bahari-SDK so Bahari can tell you when the package is outdated.
     * @param  Closure(string): string|null  $seal  Encrypts cached machine tokens (pass your framework's encrypter).
     * @param  Closure(string): string|null  $unseal
     */
    public function __construct(
        private readonly Config $config,
        private readonly HttpClient $http = new CurlHttpClient,
        private readonly CacheInterface $cache = new ArrayCache,
        private readonly string $sdk = Sdk::PACKAGE.'/'.Sdk::VERSION,
        private readonly ?Closure $seal = null,
        private readonly ?Closure $unseal = null,
    ) {}

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * The discovery document: cached for the configured TTL, then the last good copy (up to a week) if Bahari is
     * unreachable, and finally the long-standing default endpoints.
     */
    public function discovery(): Discovery
    {
        if ($this->discovery) {
            return $this->discovery;
        }
        $key = 'bahari:discovery:'.hash('sha256', $this->config->issuer);
        $cached = $this->cache->get($key);
        if (is_array($cached)) {
            return $this->discovery = new Discovery($cached, ($cached['issuer'] ?? null) === $this->config->issuer);
        }
        try {
            $data = $this->send('GET', $this->config->issuer.'/.well-known/bahari-configuration')->json();
            if (is_array($data) && ($data['issuer'] ?? null) === $this->config->issuer) {
                $this->cache->set($key, $data, $this->config->discoveryTtl);
                $this->cache->set($key.':last-good', $data, 604800);

                return $this->discovery = new Discovery($data);
            }
        } catch (Throwable) {
            // Fall through to the last good copy or the defaults.
        }
        $last = $this->cache->get($key.':last-good');
        $discovery = is_array($last) ? new Discovery($last) : Discovery::fallback($this->config);
        $this->cache->set($key, $discovery->toArray(), 60);

        return $this->discovery = $discovery;
    }

    /**
     * Starts a sign-in. Store $request->transaction in the server-side session under $request->state, then redirect
     * the browser to $request->url.
     */
    /**
     * @param  string|null  $prompt  "create" opens Bahari registration (then continues the sign-in); "login" forces
     *                               the password to be entered again. Customer sign-in only.
     */
    public function beginLogin(string $kind, string $redirectUri, ?string $loginHint = null, ?string $prompt = null): LoginRequest
    {
        $this->assertKind($kind);
        if (! $this->config->configured()) {
            throw new BahariException('Bahari sign-in is not configured: set the client ID and secret.');
        }
        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        $verifier = bin2hex(random_bytes(32));
        $parameters = ['client_id' => $this->config->clientId, 'redirect_uri' => $redirectUri, 'state' => $state, 'code_challenge' => self::base64Url(hash('sha256', $verifier, true))];
        if ($kind === 'client') {
            $parameters += ['response_type' => 'code', 'scope' => $this->config->scopes, 'nonce' => $nonce, 'code_challenge_method' => 'S256'];
        }
        if ($kind === 'client' && in_array($prompt, ['create', 'login'], true)) {
            $parameters['prompt'] = $prompt;
        }
        if ($loginHint !== null && filter_var($loginHint, FILTER_VALIDATE_EMAIL)) {
            $parameters['login_hint'] = $loginHint;
        }
        $endpoint = $this->discovery()->url($kind === 'admin' ? 'admin.authorize_endpoint' : 'authorization_endpoint');

        return new LoginRequest($endpoint.'?'.http_build_query($parameters), $state, ['kind' => $kind, 'nonce' => $nonce, 'verifier' => $verifier, 'redirect_uri' => $redirectUri, 'created_at' => time()]);
    }

    /**
     * Finishes a sign-in with the transaction saved by beginLogin() and the code from the callback.
     */
    public function completeLogin(array $transaction, string $code): Identity
    {
        $kind = $transaction['kind'] ?? null;
        $this->assertKind((string) $kind);
        if (! is_int($transaction['created_at'] ?? null) || time() - $transaction['created_at'] > 600) {
            throw new BahariException('The sign-in expired. Start again.');
        }
        $exchange = ['code' => $code, 'code_verifier' => $transaction['verifier'], 'redirect_uri' => $transaction['redirect_uri']];
        if ($kind === 'admin') {
            $profile = $this->machine('admin.exchange_endpoint', $exchange);
            $tokens = ['session_token' => (string) ($profile['session_token'] ?? '')];
            unset($profile['session_token']);
            $this->checkIdentity($profile);
            $this->authorizeAdmin($profile);

            return new Identity('admin', $profile['id'], $tokens, $profile);
        }
        $tokens = $this->token($exchange + ['grant_type' => 'authorization_code']);
        $claims = $this->verifier()->verify((string) ($tokens['id_token'] ?? ''), $transaction['nonce']);
        $profile = $this->profile((string) $tokens['access_token'], $claims['sub']);
        $this->checkIdentity($profile);

        return new Identity('client', $claims['sub'], $tokens, $profile, self::lifetime($tokens), true);
    }

    /**
     * The admin access Bahari reports for a signed-in customer: set when their account is linked to an administrator
     * of this platform. Send such people on to admin sign-in (Bahari asks for the admin password and 2FA).
     *
     * @return array{platform: string, role: string, two_factor_ready: bool}|null
     */
    public function adminAccess(Identity $identity): ?array
    {
        $access = $identity->kind === 'client' ? ($identity->profile['admin_access'] ?? null) : null;

        return is_array($access) && ($access['platform'] ?? null) === $this->config->platform && in_array($access['role'] ?? null, ['ADMIN', 'SUPER_ADMIN'], true) ? $access : null;
    }

    /**
     * Re-checks a stored session with Bahari (call on each request or every few minutes). Client access tokens are
     * rotated when they expire within 30 seconds; store the returned tokens when tokensChanged is true.
     *
     * @throws AccessDeniedException when the session must end.
     */
    public function refresh(string $kind, array $tokens, string $subject, ?int $accessExpiresIn = null): Identity
    {
        $this->assertKind($kind);
        try {
            if ($kind === 'admin') {
                $profile = $this->machine('admin.session_endpoint', ['session_token' => (string) ($tokens['session_token'] ?? '')]);
                unset($profile['session_token']);
                if (($profile['id'] ?? null) !== $subject) {
                    throw new AccessDeniedException('The admin session belongs to another account.');
                }
                $this->authorizeAdmin($profile);

                return new Identity('admin', $subject, $tokens, $profile);
            }
            $changed = false;
            $lifetime = $accessExpiresIn;
            if ($accessExpiresIn !== null && $accessExpiresIn < 30) {
                $tokens = $this->token(['grant_type' => 'refresh_token', 'refresh_token' => (string) ($tokens['refresh_token'] ?? '')]);
                $claims = $this->verifier()->verify((string) ($tokens['id_token'] ?? ''));
                if ($claims['sub'] !== $subject) {
                    throw new AccessDeniedException('The identity changed during refresh.');
                }
                $changed = true;
                $lifetime = self::lifetime($tokens);
            }
            $profile = $this->profile((string) ($tokens['access_token'] ?? ''), $subject);

            return new Identity('client', $subject, $tokens, $profile, $lifetime, $changed);
        } catch (HttpException $exception) {
            if (in_array($exception->response->status, [400, 401, 403], true)) {
                throw new AccessDeniedException('Bahari ended this session.', previous: $exception);
            }
            throw $exception;
        }
    }

    /**
     * Ends the session at Bahari (admin session or client tokens).
     */
    public function revoke(string $kind, array $tokens): void
    {
        $this->assertKind($kind);
        if ($kind === 'admin') {
            $this->machine('admin.revoke_endpoint', ['session_token' => (string) ($tokens['session_token'] ?? '')]);

            return;
        }
        foreach (['refresh_token', 'access_token'] as $type) {
            if (isset($tokens[$type])) {
                $this->form($this->discovery()->url('revocation_endpoint'), ['token' => $tokens[$type], 'token_type_hint' => $type, 'client_id' => $this->config->clientId, 'client_secret' => $this->config->clientSecret]);
            }
        }
    }

    /**
     * Where to send the browser after the local logout: Bahari's logout for customers (pass the stored id_token), the
     * admin panel for admins.
     */
    public function logoutUrl(string $kind, string $postLogoutRedirect, ?string $idTokenHint = null): string
    {
        $this->assertKind($kind);
        if ($kind === 'admin') {
            return $this->discovery()->url('admin.panel_url');
        }

        // With the ID token as proof, Bahari signs out at once and returns to the app (no confirmation page).
        return $this->discovery()->url('end_session_endpoint').'?'.http_build_query(array_filter(['client_id' => $this->config->clientId, 'post_logout_redirect_uri' => $postLogoutRedirect, 'id_token_hint' => $idTokenHint]));
    }

    /**
     * The platform switcher for the signed-in person. For customers the wallet link opens Bahari's wallet for this platform.
     */
    public function navigation(string $kind, array $tokens, ?string $walletReturnTo = null): array
    {
        $this->assertKind($kind);
        if ($kind === 'admin') {
            return $this->machine('admin.navigation_endpoint', ['session_token' => (string) ($tokens['session_token'] ?? '')]);
        }
        $navigation = $this->send('GET', $this->discovery()->url('api.platform_navigation'), ['Authorization' => 'Bearer '.($tokens['access_token'] ?? '')], null, true)->json('data');
        if (is_array($navigation) && isset($navigation['wallet']) && is_array($navigation['wallet'])) {
            $navigation['wallet']['url'] = $this->walletUrl($walletReturnTo);
        }

        return is_array($navigation) ? $navigation : [];
    }

    /**
     * Saves the customer's pinned platforms. Returns Bahari's response so validation errors (422) can be shown.
     */
    public function updatePinned(array $tokens, array $keys): Response
    {
        $url = $this->discovery()->url('api.platform_navigation');
        $response = $this->send('PUT', $url, ['Authorization' => 'Bearer '.($tokens['access_token'] ?? ''), 'Content-Type' => 'application/json'], json_encode(['pinned_keys' => array_values($keys)]));
        if (! $response->successful() && $response->status !== 422) {
            throw new HttpException($response, $url);
        }

        return $response;
    }

    /**
     * Verifies a back-channel logout token. Returns its claims; end every local customer session of claims['sub'],
     * once per claims['jti'].
     */
    public function verifyLogoutToken(string $token): array
    {
        return $this->verifier()->verify($token, logout: true);
    }

    /**
     * A URL from discovery, such as client.wallet_url, client.profile_url, admin.panel_url or admin.billing_url.
     */
    public function url(string $name, array $query = []): string
    {
        $url = $this->discovery()->url($name);

        return $query === [] ? $url : $url.(str_contains($url, '?') ? '&' : '?').http_build_query($query);
    }

    public function walletUrl(?string $returnTo = null): string
    {
        return $this->url('client.wallet_url', array_filter(['platform' => $this->config->platform, 'return_to' => $returnTo]));
    }

    /**
     * Calls a platform API endpoint with this app's machine token (client credentials). $path is relative to the API
     * base URL, for example "platform-wallets/123/debits".
     */
    public function api(string $method, string $path, array $data = [], string $scope = 'identity:lookup'): array
    {
        $url = rtrim($this->discovery()->url('api.base_url'), '/').'/'.ltrim($path, '/');
        $body = $method === 'GET' ? null : json_encode($data);
        if ($method === 'GET' && $data !== []) {
            $url .= '?'.http_build_query($data);
        }
        $response = $this->send($method, $url, ['Authorization' => 'Bearer '.$this->machineToken($scope), 'Content-Type' => 'application/json'], $body, true);

        return (array) $response->json();
    }

    // ---------------------------------------------------------------- billing (features "Invoices" / "Subscriptions")
    // The app sets its prices; Bahari invoices, takes payment and renews. $reference is your own UUID (idempotent).
    // Answers are ['data' => ..., 'payment' => ...]; send the customer to data.checkout_url (or
    // data.open_invoice.checkout_url) unless you paid with 'pay' => 'wallet' (feature "Charge without confirmation").

    /** @param array{user_id: string, reference: string, items: list<array{description: string, quantity?: int, unit_price: string}>, currency?: string, due_in_days?: int, return_to?: string, pay?: string} $invoice */
    public function createInvoice(array $invoice): array
    {
        return $this->api('POST', 'platform-billing/invoices', $invoice, 'billing');
    }

    public function invoice(string $reference): array
    {
        return $this->api('GET', 'platform-billing/invoices/'.rawurlencode($reference), [], 'billing');
    }

    public function voidInvoice(string $reference): array
    {
        return $this->api('POST', 'platform-billing/invoices/'.rawurlencode($reference).'/void', [], 'billing');
    }

    /** @param array{user_id: string, reference: string, plan_name: string, cycle: string, amount: string, currency?: string, external_id?: string, return_to?: string, pay?: string} $subscription */
    public function createSubscription(array $subscription): array
    {
        return $this->api('POST', 'platform-billing/subscriptions', $subscription, 'billing');
    }

    public function subscription(string $reference): array
    {
        return $this->api('GET', 'platform-billing/subscriptions/'.rawurlencode($reference), [], 'billing');
    }

    /** Changes plan_name, amount or cycle from the next renewal invoice. */
    public function updateSubscription(string $reference, array $changes): array
    {
        return $this->api('PATCH', 'platform-billing/subscriptions/'.rawurlencode($reference), $changes, 'billing');
    }

    /** @param 'period_end'|'now' $when */
    public function cancelSubscription(string $reference, string $when = 'period_end'): array
    {
        return $this->api('POST', 'platform-billing/subscriptions/'.rawurlencode($reference).'/cancel', ['when' => $when], 'billing');
    }

    public function resumeSubscription(string $reference): array
    {
        return $this->api('POST', 'platform-billing/subscriptions/'.rawurlencode($reference).'/resume', [], 'billing');
    }

    public function customerSubscriptions(string $userId): array
    {
        return $this->api('GET', 'platform-billing/customers/'.rawurlencode($userId).'/subscriptions', [], 'billing');
    }

    /**
     * "ok", "outdated", "unsupported" or "unknown" from the last Bahari response, or null before any request.
     */
    public function sdkStatus(): ?string
    {
        return $this->sdkStatus;
    }

    public function jwks(bool $fresh = false): array
    {
        $url = $this->discovery()->url('jwks_uri');
        $key = 'bahari:jwks:'.hash('sha256', $url);
        $jwks = $fresh ? null : $this->cache->get($key);
        if (! is_array($jwks)) {
            $jwks = (array) $this->send('GET', $url, [], null, true)->json();
            $this->cache->set($key, $jwks, 300);
        }

        return $jwks;
    }

    public function verifier(): TokenVerifier
    {
        return $this->verifier ??= new TokenVerifier($this);
    }

    private function token(array $data): array
    {
        $response = $this->form($this->discovery()->url('token_endpoint'), $data + ['client_id' => $this->config->clientId, 'client_secret' => $this->config->clientSecret]);
        $tokens = $response->json();
        if (! is_array($tokens) || ! is_string($tokens['access_token'] ?? null)) {
            throw new BahariException('Bahari returned no access token.');
        }

        return $tokens;
    }

    private function profile(string $accessToken, string $subject): array
    {
        $profile = $this->send('GET', $this->discovery()->url('profile_endpoint'), ['Authorization' => 'Bearer '.$accessToken], null, true)->json('data');
        if (! is_array($profile) || ($profile['id'] ?? null) !== $subject || ($profile['status'] ?? null) !== 'active' || ! TokenVerifier::uuid($profile['customer']['id'] ?? null)) {
            throw new AccessDeniedException('The Bahari account is unavailable.');
        }

        return $profile;
    }

    private function machine(string $endpoint, array $data): array
    {
        $url = $this->discovery()->url($endpoint);
        $call = fn (): Response => $this->send('POST', $url, ['Authorization' => 'Bearer '.$this->machineToken('identity:lookup'), 'Content-Type' => 'application/json'], json_encode($data));
        $response = $call();
        if ($response->status === 401) {
            $this->cache->delete($this->machineKey('identity:lookup'));
            $response = $call();
        }
        if (! $response->successful()) {
            throw new HttpException($response, $url);
        }
        $result = $response->json('data');

        return is_array($result) ? $result : [];
    }

    private function machineToken(string $scope): string
    {
        $key = $this->machineKey($scope);
        $sealed = $this->cache->get($key);
        if (is_string($sealed)) {
            return $this->unseal ? ($this->unseal)($sealed) : $sealed;
        }
        $tokens = $this->token(['grant_type' => 'client_credentials', 'scope' => $scope]);
        $token = $tokens['access_token'];
        $this->cache->set($key, $this->seal ? ($this->seal)($token) : $token, max(30, min(600, (int) ($tokens['expires_in'] ?? 600) - 60)));

        return $token;
    }

    private function machineKey(string $scope): string
    {
        return 'bahari:machine:'.hash('sha256', $this->config->clientId."\0".$this->config->clientSecret."\0".$scope);
    }

    private function form(string $url, array $data): Response
    {
        return $this->send('POST', $url, ['Content-Type' => 'application/x-www-form-urlencoded'], http_build_query($data), true);
    }

    private function send(string $method, string $url, array $headers = [], ?string $body = null, bool $throw = false): Response
    {
        $response = $this->http->send($method, $url, $headers + ['Accept' => 'application/json', 'X-Bahari-SDK' => $this->sdk], $body);
        $this->sdkStatus = $response->header('X-Bahari-SDK-Status') ?? $this->sdkStatus;
        if ($throw && ! $response->successful()) {
            throw new HttpException($response, $url);
        }

        return $response;
    }

    private function checkIdentity(array $profile): void
    {
        if (! TokenVerifier::uuid($profile['id'] ?? null) || ! filter_var($profile['email'] ?? '', FILTER_VALIDATE_EMAIL) || ! is_string($profile['name'] ?? null)) {
            throw new BahariException('Bahari returned an invalid identity.');
        }
    }

    private function authorizeAdmin(array $profile): void
    {
        if ($this->config->platform === null || ($profile['platform'] ?? null) !== $this->config->platform || ! in_array($profile['role'] ?? null, ['ADMIN', 'SUPER_ADMIN'], true)) {
            throw new AccessDeniedException('Administration of this platform is not authorized.');
        }
    }

    private function assertKind(string $kind): void
    {
        if (! in_array($kind, self::KINDS, true)) {
            throw new \InvalidArgumentException('Kind must be "client" or "admin".');
        }
    }

    private static function lifetime(array $tokens): int
    {
        return min(900, max(1, (int) ($tokens['expires_in'] ?? 900)));
    }

    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
