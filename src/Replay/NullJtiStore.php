<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Replay;

/**
 * No-op JTI store: disables replay protection while keeping the same API.
 * Useful for tests or environments where replay tracking is not required.
 */
final class NullJtiStore implements JtiStoreInterface
{
    public function tryConsume(string $jti, int $ttl): bool
    {
        return true; // always "first use"
    }
}
