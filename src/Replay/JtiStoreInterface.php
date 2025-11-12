<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Replay;

/**
 * Interface for tracking and preventing token replay attacks.
 *
 * Implementations should store a JTI (unique token id) with a TTL
 * so it cannot be reused after first successful verification.
 */
interface JtiStoreInterface
{
    /**
     * Attempt to consume the given JTI for the provided TTL.
     *
     * @param string $jti Unique token id
     * @param int    $ttl Seconds until this JTI expires (>= 0)
     * @return bool  True if this JTI was newly stored (first use), false if it already existed (replay)
     */
    public function tryConsume(string $jti, int $ttl): bool;
}
