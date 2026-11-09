<?php

namespace Bahari\Sso\Cache;

use DateInterval;
use DateTimeImmutable;
use Psr\SimpleCache\CacheInterface;

/**
 * In-memory cache for scripts and tests. Use your framework's PSR-16 cache in production.
 */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{0: mixed, 1: int|null}> */
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        if (! isset($this->items[$key]) || ($this->items[$key][1] !== null && $this->items[$key][1] < time())) {
            return $default;
        }

        return $this->items[$key][0];
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $seconds = $ttl instanceof DateInterval ? (new DateTimeImmutable)->add($ttl)->getTimestamp() - time() : $ttl;
        $this->items[$key] = [$value, $seconds === null ? null : time() + $seconds];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $this) !== $this;
    }
}
