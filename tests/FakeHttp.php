<?php

namespace Bahari\Sso\Tests;

use Bahari\Sso\Exception\BahariException;
use Bahari\Sso\Http\HttpClient;
use Bahari\Sso\Http\Response;

final class FakeHttp implements HttpClient
{
    /** @var array<int, array{method: string, url: string, headers: array, body: ?string}> */
    public array $sent = [];

    /** @param array<string, Response|callable> $routes "METHOD url-without-query" => response */
    public function __construct(public array $routes = []) {}

    public function send(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $this->sent[] = compact('method', 'url', 'headers', 'body');
        $route = $this->routes[$method.' '.strtok($url, '?')] ?? null;
        if ($route === null) {
            throw new BahariException('Unexpected request '.$method.' '.$url);
        }

        return is_callable($route) ? $route($body, $headers) : $route;
    }

    public static function json(array $data, int $status = 200, array $headers = []): Response
    {
        return new Response($status, json_encode($data), $headers);
    }
}
