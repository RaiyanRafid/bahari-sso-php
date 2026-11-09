<?php

namespace Bahari\Sso\Http;

interface HttpClient
{
    /**
     * Sends a request without following redirects.
     *
     * @param  array<string, string>  $headers
     */
    public function send(string $method, string $url, array $headers = [], ?string $body = null): Response;
}
