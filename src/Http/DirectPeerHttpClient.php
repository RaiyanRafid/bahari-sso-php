<?php

namespace Bahari\Sso\Http;

interface DirectPeerHttpClient extends HttpClient
{
    /**
     * @param  array<string, string>  $headers
     * @param  list<string>  $resolve  Optional cURL CURLOPT_RESOLVE entries ("host:port:ip").
     */
    public function sendWithResolve(string $method, string $url, array $headers = [], ?string $body = null, array $resolve = []): Response;
}
