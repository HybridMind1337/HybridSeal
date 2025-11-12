<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Crypto;

/**
 * HKDF-SHA256 key derivation utility (RFC 5869).
 * Derives subkeys from a master secret to isolate per-purpose signing keys.
 */
final class Kdf
{
    /**
     * @param string $ikm  Binary master secret
     * @param string $salt Contextual salt (e.g., key id)
     * @param string $info Purpose string (e.g., 'HSEAL-HS256:auth:web')
     * @param int    $len  Output length in bytes (16..64)
     */
    public static function hkdfSha256(string $ikm, string $salt, string $info, int $len = 32): string
    {
        if ($len < 16 || $len > 64) {
            throw new \RuntimeException('HKDF: output length must be between 16 and 64 bytes.');
        }
        return hash_hkdf('sha256', $ikm, $len, $info, $salt);
    }
}
