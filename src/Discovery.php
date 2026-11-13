<?php

namespace Bahari\Sso;

/**
 * The Bahari discovery document (/.well-known/bahari-configuration). Read values with dot paths: get('admin.authorize_endpoint').
 */
final class Discovery
{
    public function __construct(private readonly array $data, public readonly bool $fromServer = true) {}

    /**
     * Endpoints Bahari has always used, for when discovery cannot be reached and nothing is cached yet.
     */
    public static function fallback(Config $config): self
    {
        $issuer = $config->issuer;
        $admin = $config->adminIssuer ?? $issuer;
        $api = $issuer.'/api/v1';

        return new self([
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'userinfo_endpoint' => $issuer.'/oauth/userinfo',
            'profile_endpoint' => $issuer.'/oauth/user',
            'jwks_uri' => $issuer.'/oauth/jwks',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'end_session_endpoint' => $issuer.'/oauth/logout',
            'client' => [
                'dashboard_url' => $issuer.'/dashboard', 'profile_url' => $issuer.'/dashboard/personal-details', 'security_url' => $issuer.'/dashboard/security',
                'identity_url' => $issuer.'/dashboard/identity-verification', 'wallet_url' => $issuer.'/dashboard/wallet', 'billing_url' => $issuer.'/dashboard/billing',
                'applications_url' => $issuer.'/dashboard/applications',
            ],
            'admin' => [
                'origin' => $admin, 'panel_url' => $admin.'/admin', 'billing_url' => $admin.'/admin/billing', 'profile_url' => $admin.'/admin/profile', 'authorize_endpoint' => $admin.'/admin-sso/authorize',
                'exchange_endpoint' => $api.'/admin-sso/exchange', 'session_endpoint' => $api.'/admin-sso/session', 'revoke_endpoint' => $api.'/admin-sso/revoke', 'navigation_endpoint' => $api.'/admin-sso/navigation',
            ],
            'api' => ['base_url' => $api, 'platform_navigation' => $api.'/platform-navigation', 'peer_register_endpoint' => $api.'/platform-peers/register', 'platform_branding' => $api.'/platform-branding/{key}'],
            'sdk' => ['packages' => []],
        ], false);
    }

    public function get(string $path, mixed $default = null): mixed
    {
        $value = $this->data;
        foreach (explode('.', $path) as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * A URL from the document. Throws when it is missing so a typo never sends a request to the wrong place.
     */
    public function url(string $path): string
    {
        $url = $this->get($path);
        if (! is_string($url) || ! preg_match('~^https?://~', $url)) {
            throw new Exception\BahariException("Bahari discovery has no URL for '{$path}'.");
        }

        return $url;
    }

    public function toArray(): array
    {
        return $this->data;
    }
}
