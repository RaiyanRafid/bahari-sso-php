<?php

namespace Bahari\Sso\Http;

use Bahari\Sso\Exception\BahariException;

final class CurlHttpClient implements DirectPeerHttpClient
{
    public function __construct(private readonly int $connectTimeout = 3, private readonly int $timeout = 10) {}

    public function send(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        return $this->sendWithResolve($method, $url, $headers, $body, []);
    }

    /**
     * @param  list<string>  $resolve  Optional cURL CURLOPT_RESOLVE entries ("host:port:ip").
     */
    public function sendWithResolve(string $method, string $url, array $headers = [], ?string $body = null, array $resolve = []): Response
    {
        $handle = curl_init($url);
        $received = [];
        $options = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
            CURLOPT_HTTPHEADER => array_map(fn (string $name, string $value): string => $name.': '.$value, array_keys($headers), $headers),
            CURLOPT_HEADERFUNCTION => function ($curl, string $line) use (&$received): int {
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $received[strtolower(trim($name))] = trim($value);
                }

                return strlen($line);
            },
        ];
        if ($resolve !== []) {
            $options[CURLOPT_RESOLVE] = $resolve;
        }
        if ($body !== null) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($handle, $options);
        $result = curl_exec($handle);
        if ($result === false) {
            $error = curl_error($handle);
            throw new BahariException('Bahari Accounts could not be reached: '.$error);
        }

        return new Response((int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE), (string) $result, $received);
    }
}
