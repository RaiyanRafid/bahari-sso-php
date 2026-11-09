<?php

namespace Bahari\Sso;

/**
 * Where to send the browser, and what to keep in the server-side session until the callback (never in a cookie
 * readable by the browser): pass $transaction back to Client::completeLogin().
 */
final class LoginRequest
{
    public function __construct(public readonly string $url, public readonly string $state, public readonly array $transaction) {}
}
