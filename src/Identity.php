<?php

namespace Bahari\Sso;

/**
 * A signed-in Bahari identity. kind is "client" (a customer) or "admin" (a platform administrator).
 * tokens must be stored encrypted on the server. accessExpiresIn is in seconds (client sessions only).
 */
final class Identity
{
    public function __construct(
        public readonly string $kind,
        public readonly string $subject,
        public readonly array $tokens,
        public readonly array $profile,
        public readonly ?int $accessExpiresIn = null,
        public readonly bool $tokensChanged = false,
    ) {}
}
