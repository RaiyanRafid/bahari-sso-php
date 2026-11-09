<?php

namespace Bahari\Sso\Tests;

use Bahari\Sso\Cache\ArrayCache;
use Bahari\Sso\Client;
use Bahari\Sso\Config;
use Bahari\Sso\Exception\AccessDeniedException;
use Bahari\Sso\Exception\InvalidTokenException;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    private const ISSUER = 'https://accounts.example.test';

    private const SUBJECT = '0198a6c1-1111-7000-8000-000000000001';

    private string $privateKey = '';

    private array $jwk;

    protected function setUp(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $this->privateKey);
        $details = openssl_pkey_get_details($key);
        $this->jwk = ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => 'k1', 'n' => Client::base64Url($details['rsa']['n']), 'e' => Client::base64Url($details['rsa']['e'])];
    }

    private function client(FakeHttp $http, ?ArrayCache $cache = null, array $config = []): Client
    {
        return new Client(Config::fromArray($config + ['issuer' => self::ISSUER, 'client_id' => 'client-1', 'client_secret' => 'secret-1', 'platform' => 'reseller']), $http, $cache ?? new ArrayCache, 'bahari/sso-php/0.1.0');
    }

    private function discovery(string $admin = 'https://admin.example.test'): array
    {
        return ['issuer' => self::ISSUER, 'authorization_endpoint' => self::ISSUER.'/oauth/authorize', 'token_endpoint' => self::ISSUER.'/oauth/token', 'profile_endpoint' => self::ISSUER.'/oauth/user',
            'jwks_uri' => self::ISSUER.'/oauth/jwks', 'revocation_endpoint' => self::ISSUER.'/oauth/revoke', 'end_session_endpoint' => self::ISSUER.'/oauth/logout',
            'client' => ['wallet_url' => self::ISSUER.'/dashboard/wallet'],
            'admin' => ['panel_url' => $admin.'/admin', 'authorize_endpoint' => $admin.'/admin-sso/authorize', 'exchange_endpoint' => self::ISSUER.'/api/v1/admin-sso/exchange', 'session_endpoint' => self::ISSUER.'/api/v1/admin-sso/session', 'revoke_endpoint' => self::ISSUER.'/api/v1/admin-sso/revoke', 'navigation_endpoint' => self::ISSUER.'/api/v1/admin-sso/navigation'],
            'api' => ['base_url' => self::ISSUER.'/api/v1', 'platform_navigation' => self::ISSUER.'/api/v1/platform-navigation']];
    }

    private function idToken(array $claims = []): string
    {
        return JWT::encode($claims + ['iss' => self::ISSUER, 'aud' => ['client-1'], 'sub' => self::SUBJECT, 'iat' => time(), 'exp' => time() + 900], $this->privateKey, 'RS256', 'k1');
    }

    private function profile(array $overrides = []): array
    {
        return $overrides + ['id' => self::SUBJECT, 'name' => 'Rafi', 'email' => 'rafi@example.test', 'status' => 'active', 'customer' => ['id' => '0198a6c1-2222-7000-8000-000000000002']];
    }

    public function test_admin_login_uses_the_admin_host_from_discovery_and_sends_the_sdk_header(): void
    {
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery('https://new-admin.example.test'), headers: ['x-bahari-sdk-status' => 'outdated'])]);
        $login = $this->client($http)->beginLogin('admin', 'https://app.example.test/auth/admin/callback');

        $this->assertStringStartsWith('https://new-admin.example.test/admin-sso/authorize?', $login->url);
        parse_str(parse_url($login->url, PHP_URL_QUERY), $query);
        $this->assertSame($login->state, $query['state']);
        $this->assertSame(Client::base64Url(hash('sha256', $login->transaction['verifier'], true)), $query['code_challenge']);
        $this->assertSame('bahari/sso-php/0.1.0', $http->sent[0]['headers']['X-Bahari-SDK']);
    }

    public function test_discovery_falls_back_to_defaults_and_rejects_a_document_for_another_issuer(): void
    {
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json(['issuer' => 'https://evil.example.test'] + $this->discovery('https://evil.example.test'))]);
        $client = $this->client($http, config: ['admin_issuer' => 'https://admin-fallback.example.test']);

        $this->assertFalse($client->discovery()->fromServer);
        $this->assertSame('https://admin-fallback.example.test/admin-sso/authorize', $client->discovery()->url('admin.authorize_endpoint'));
        $this->assertSame(self::ISSUER.'/oauth/token', $client->discovery()->url('token_endpoint'));
    }

    public function test_last_good_discovery_is_used_when_bahari_is_unreachable(): void
    {
        $cache = new ArrayCache;
        $this->client(new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery('https://moved-admin.example.test'))]), $cache)->discovery();
        $cache->delete('bahari:discovery:'.hash('sha256', self::ISSUER));

        $client = $this->client(new FakeHttp, $cache);

        $this->assertSame('https://moved-admin.example.test/admin', $client->url('admin.panel_url'));
    }

    public function test_client_login_verifies_the_id_token_nonce_and_profile(): void
    {
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery()), 'GET '.self::ISSUER.'/oauth/jwks' => FakeHttp::json(['keys' => [$this->jwk]]), 'GET '.self::ISSUER.'/oauth/user' => FakeHttp::json(['data' => $this->profile()])]);
        $client = $this->client($http);
        $login = $client->beginLogin('client', 'https://app.example.test/cb');
        $http->routes['POST '.self::ISSUER.'/oauth/token'] = FakeHttp::json(['access_token' => 'a', 'refresh_token' => 'r', 'expires_in' => 3600, 'id_token' => $this->idToken(['nonce' => $login->transaction['nonce']])]);

        $identity = $client->completeLogin($login->transaction, 'code-1');

        $this->assertSame(self::SUBJECT, $identity->subject);
        $this->assertSame(900, $identity->accessExpiresIn);
        $this->assertSame('rafi@example.test', $identity->profile['email']);

        $http->routes['POST '.self::ISSUER.'/oauth/token'] = FakeHttp::json(['access_token' => 'a', 'id_token' => $this->idToken(['nonce' => 'wrong'])]);
        $this->expectException(InvalidTokenException::class);
        $client->completeLogin($login->transaction, 'code-2');
    }

    public function test_admin_exchange_requires_an_admin_role_for_this_platform(): void
    {
        $profile = $this->profile(['platform' => 'reseller', 'role' => 'ADMIN', 'session_token' => str_repeat('s', 64)]);
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery()), 'POST '.self::ISSUER.'/oauth/token' => FakeHttp::json(['access_token' => 'machine', 'expires_in' => 3600]),
            'POST '.self::ISSUER.'/api/v1/admin-sso/exchange' => function () use (&$profile) { return FakeHttp::json(['data' => $profile]); }]);
        $client = $this->client($http);
        $login = $client->beginLogin('admin', 'https://app.example.test/cb');

        $identity = $client->completeLogin($login->transaction, 'code');
        $this->assertSame(['session_token' => str_repeat('s', 64)], $identity->tokens);
        $this->assertArrayNotHasKey('session_token', $identity->profile);

        $profile['platform'] = 'sms';
        $this->expectException(AccessDeniedException::class);
        $client->completeLogin($login->transaction, 'code');
    }

    public function test_refresh_rotates_expiring_tokens_and_rejects_another_subject(): void
    {
        $other = '0198a6c1-3333-7000-8000-000000000003';
        $subject = self::SUBJECT;
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery()), 'GET '.self::ISSUER.'/oauth/jwks' => FakeHttp::json(['keys' => [$this->jwk]]),
            'GET '.self::ISSUER.'/oauth/user' => FakeHttp::json(['data' => $this->profile()]),
            'POST '.self::ISSUER.'/oauth/token' => function () use (&$subject) { return FakeHttp::json(['access_token' => 'new-a', 'refresh_token' => 'new-r', 'expires_in' => 600, 'id_token' => $this->idToken(['sub' => $subject])]); }]);
        $client = $this->client($http);

        $fresh = $client->refresh('client', ['access_token' => 'a', 'refresh_token' => 'r'], self::SUBJECT, 300);
        $this->assertFalse($fresh->tokensChanged);

        $rotated = $client->refresh('client', ['access_token' => 'a', 'refresh_token' => 'r'], self::SUBJECT, 10);
        $this->assertTrue($rotated->tokensChanged);
        $this->assertSame('new-r', $rotated->tokens['refresh_token']);
        $this->assertSame(600, $rotated->accessExpiresIn);

        $subject = $other;
        $this->expectException(AccessDeniedException::class);
        $client->refresh('client', ['access_token' => 'a', 'refresh_token' => 'r'], self::SUBJECT, 10);
    }

    public function test_revoked_admin_session_is_access_denied(): void
    {
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery()), 'POST '.self::ISSUER.'/oauth/token' => FakeHttp::json(['access_token' => 'machine']),
            'POST '.self::ISSUER.'/api/v1/admin-sso/session' => FakeHttp::json(['message' => 'revoked'], 403)]);

        $this->expectException(AccessDeniedException::class);
        $this->client($http)->refresh('admin', ['session_token' => 'x'], self::SUBJECT);
    }

    public function test_logout_token_and_urls(): void
    {
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery()), 'GET '.self::ISSUER.'/oauth/jwks' => FakeHttp::json(['keys' => [$this->jwk]])]);
        $client = $this->client($http);

        $claims = $client->verifyLogoutToken($this->idToken(['jti' => 'j1', 'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass]]));
        $this->assertSame(self::SUBJECT, $claims['sub']);
        $this->assertSame(self::ISSUER.'/oauth/logout?client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example.test%2F', $client->logoutUrl('client', 'https://app.example.test/'));
        $this->assertSame('https://admin.example.test/admin', $client->logoutUrl('admin', 'https://app.example.test/'));
        $this->assertSame(self::ISSUER.'/dashboard/wallet?platform=reseller&return_to=%2Fdashboard', $client->walletUrl('/dashboard'));

        $this->expectException(InvalidTokenException::class);
        $client->verifyLogoutToken($this->idToken(['jti' => 'j2']));
    }

    public function test_issuer_must_be_https(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray(['issuer' => 'http://accounts.example.test', 'client_id' => 'a', 'client_secret' => 'b']);
    }

    public function test_admin_access_is_reported_only_for_this_platform_and_login_hint_reaches_admin_sign_in(): void
    {
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery())]);
        $client = $this->client($http);
        $access = ['platform' => 'reseller', 'role' => 'ADMIN', 'two_factor_ready' => true];

        $this->assertSame($access, $client->adminAccess(new \Bahari\Sso\Identity('client', self::SUBJECT, [], $this->profile(['admin_access' => $access]))));
        $this->assertNull($client->adminAccess(new \Bahari\Sso\Identity('client', self::SUBJECT, [], $this->profile(['admin_access' => ['platform' => 'sms', 'role' => 'ADMIN']]))));
        $this->assertNull($client->adminAccess(new \Bahari\Sso\Identity('client', self::SUBJECT, [], $this->profile())));

        parse_str(parse_url($client->beginLogin('admin', 'https://app.example.test/cb', 'rafi@example.test')->url, PHP_URL_QUERY), $query);
        $this->assertSame('rafi@example.test', $query['login_hint']);
        parse_str(parse_url($client->beginLogin('admin', 'https://app.example.test/cb', 'not an email')->url, PHP_URL_QUERY), $query);
        $this->assertArrayNotHasKey('login_hint', $query);
    }

    public function test_registration_prompt_and_logout_hint(): void
    {
        $client = $this->client(new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery())]));

        parse_str(parse_url($client->beginLogin('client', 'https://app.example.test/cb', prompt: 'create')->url, PHP_URL_QUERY), $query);
        $this->assertSame('create', $query['prompt']);
        parse_str(parse_url($client->beginLogin('client', 'https://app.example.test/cb', prompt: 'consent')->url, PHP_URL_QUERY), $query);
        $this->assertArrayNotHasKey('prompt', $query);
        parse_str(parse_url($client->logoutUrl('client', 'https://app.example.test/', 'id.token.value'), PHP_URL_QUERY), $query);
        $this->assertSame('id.token.value', $query['id_token_hint']);
    }

    public function test_billing_calls_use_a_billing_machine_token_and_the_billing_api(): void
    {
        $http = new FakeHttp(['GET '.self::ISSUER.'/.well-known/bahari-configuration' => FakeHttp::json($this->discovery()),
            'POST '.self::ISSUER.'/oauth/token' => function (?string $body) { parse_str((string) $body, $form); return FakeHttp::json(['access_token' => 'tok-'.$form['scope'], 'expires_in' => 900]); },
            'POST '.self::ISSUER.'/api/v1/platform-billing/subscriptions' => FakeHttp::json(['data' => ['status' => 'pending'], 'payment' => null], 201),
            'POST '.self::ISSUER.'/api/v1/platform-billing/subscriptions/ref-1/cancel' => function (?string $body) { return FakeHttp::json(['data' => ['status' => 'active', 'cancel_at_period_end' => json_decode((string) $body, true)['when'] === 'period_end']]); }]);
        $client = $this->client($http);

        $this->assertSame('pending', $client->createSubscription(['user_id' => self::SUBJECT, 'reference' => 'ref-1', 'plan_name' => 'Starter', 'cycle' => 'monthly', 'amount' => '999.00'])['data']['status']);
        $this->assertTrue($client->cancelSubscription('ref-1')['data']['cancel_at_period_end']);
        $sent = array_values(array_filter($http->sent, fn (array $r): bool => str_contains($r['url'], 'platform-billing')));
        $this->assertSame('Bearer tok-billing', $sent[0]['headers']['Authorization']);
    }
}
