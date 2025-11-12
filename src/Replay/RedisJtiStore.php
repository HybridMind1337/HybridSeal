<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Replay;

/**
 * Redis-backed JTI store (requires ext-redis).
 *
 * Keys are stored as "hseal:jti:{jti}" with NX + EX to ensure single use.
 */
final class RedisJtiStore implements JtiStoreInterface
{
    private \Redis $redis;
    private string $prefix;

    public function __construct(\Redis $redis, string $prefix = 'hseal:jti:')
    {
        $this->redis = $redis;
        $this->prefix = $prefix;
    }

    public function tryConsume(string $jti, int $ttl): bool
    {
        $ttl = max(0, $ttl);
        $key = $this->prefix . $jti;

        // If TTL is zero, still prevent immediate replay (set short expiry).
        $exp = $ttl > 0 ? $ttl : 30;

        // SET key value NX EX <exp> → only succeeds if key does not exist
        $ok = $this->redis->set($key, '1', ['nx', 'ex' => $exp]);
        // Redis returns true on success, false on failure; some versions return "OK"
        return $ok === true || $ok === 'OK';
    }
}
