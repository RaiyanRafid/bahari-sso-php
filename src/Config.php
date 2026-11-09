<?php

namespace Bahari\Sso;

use InvalidArgumentException;

/**
 * The only settings an app needs. Everything else (endpoints, the admin host, API URLs) comes from discovery.
 */
final class Config
{
    public readonly string $issuer;

    public readonly ?string $adminIssuer;

    /**
     * @param  string|null  $adminIssuer  Only used when discovery cannot be reached and nothing is cached.
     */
    public function __construct(
        string $issuer,
        public readonly string $clientId,
        public readonly string $clientSecret,
        public readonly ?string $platform = null,
        public readonly string $scopes = 'openid profile email phone profile:read identity:read wallet:read platform:read',
        ?string $adminIssuer = null,
        public readonly int $discoveryTtl = 300,
    ) {
        $this->issuer = self::origin($issuer, 'issuer');
        $this->adminIssuer = $adminIssuer ? self::origin($adminIssuer, 'admin issuer') : null;
    }

    public static function fromArray(array $config): self
    {
        return new self(
            (string) ($config['issuer'] ?? ''),
            (string) ($config['client_id'] ?? ''),
            (string) ($config['client_secret'] ?? ''),
            $config['platform'] ?? null,
            $config['scopes'] ?? 'openid profile email phone profile:read identity:read wallet:read platform:read',
            $config['admin_issuer'] ?? null,
            (int) ($config['discovery_ttl'] ?? 300),
        );
    }

    public function configured(): bool
    {
        return $this->clientId !== '' && $this->clientSecret !== '';
    }

    private static function origin(string $url, string $name): string
    {
        $url = rtrim(trim($url), '/');
        $parts = parse_url($url);
        $local = in_array($parts['host'] ?? '', ['localhost', '127.0.0.1', '::1'], true);
        if (! $parts || ! isset($parts['host']) || ! (($parts['scheme'] ?? '') === 'https' || (($parts['scheme'] ?? '') === 'http' && $local)) || isset($parts['user']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new InvalidArgumentException("The Bahari {$name} must be an https URL such as https://accounts.baharione.com.");
        }

        return $url;
    }
}
