<?php

namespace Bahari\Sso;

use Bahari\Sso\Exception\InvalidTokenException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Throwable;

/**
 * Verifies RS256 ID and logout tokens against the issuer's JWKS (cached; refetched once when the key is unknown).
 */
final class TokenVerifier
{
    public const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(private readonly Client $client) {}

    public function verify(string $token, ?string $nonce = null, bool $logout = false): array
    {
        $parts = explode('.', $token);
        $header = count($parts) === 3 ? json_decode((string) JWT::urlsafeB64Decode($parts[0]), true) : null;
        if (! is_array($header) || ($header['alg'] ?? null) !== 'RS256' || ! is_string($header['kid'] ?? null)) {
            throw new InvalidTokenException('Invalid token algorithm.');
        }
        try {
            $claims = $this->decode($token, $this->client->jwks(), $header['kid']);
        } catch (InvalidTokenException $exception) {
            throw $exception;
        } catch (Throwable) {
            try {
                $claims = $this->decode($token, $this->client->jwks(fresh: true), $header['kid']);
            } catch (Throwable $exception) {
                throw new InvalidTokenException('Invalid token signature.', previous: $exception);
            }
        }
        $config = $this->client->config();
        $audience = (array) ($claims['aud'] ?? []);
        if (($claims['iss'] ?? null) !== $config->issuer || ! in_array($config->clientId, $audience, true) || ! self::uuid($claims['sub'] ?? null) || ! isset($claims['exp'], $claims['iat']) || $claims['iat'] > time() + 30) {
            throw new InvalidTokenException('Invalid token claims.');
        }
        if ($nonce !== null && (! is_string($claims['nonce'] ?? null) || ! hash_equals($nonce, $claims['nonce']))) {
            throw new InvalidTokenException('Invalid token nonce.');
        }
        if ($logout) {
            $events = (array) ($claims['events'] ?? []);
            if (! isset($claims['jti']) || isset($claims['nonce']) || ! array_key_exists(self::LOGOUT_EVENT, $events) || abs(time() - $claims['iat']) > 300) {
                throw new InvalidTokenException('Invalid logout token.');
            }
        }

        return $claims;
    }

    private function decode(string $token, array $jwks, string $kid): array
    {
        $keys = JWK::parseKeySet($jwks, 'RS256');
        if (! isset($keys[$kid])) {
            throw new \UnexpectedValueException('Unknown signing key.');
        }
        JWT::$leeway = 30;

        return json_decode(json_encode(JWT::decode($token, $keys)), true);
    }

    public static function uuid(mixed $value): bool
    {
        return is_string($value) && (bool) preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iD', $value);
    }
}
