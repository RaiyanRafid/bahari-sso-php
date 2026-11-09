<?php

namespace Bahari\Sso\Http;

final class Response
{
    /**
     * @param  array<string, string>  $headers  Lower-case header names.
     */
    public function __construct(public readonly int $status, public readonly string $body, public readonly array $headers = []) {}

    public function json(?string $key = null): mixed
    {
        $data = json_decode($this->body, true);
        if ($key === null) {
            return $data;
        }

        return is_array($data) ? ($data[$key] ?? null) : null;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function successful(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }
}
