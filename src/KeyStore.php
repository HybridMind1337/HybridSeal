<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal;

use InvalidArgumentException;
use Random\RandomException;

/**
 * KeyStore manages HMAC secrets and key rotation.
 *
 * - kid => secret (binary)
 * - hex import/export
 * - current key selection and rotation
 * - minimum 32-byte secrets
 */
final class KeyStore
{
    /** @var array<string,string> kid => binary secret */
    private array $secrets;

    private string $currentKid;

    /**
     * @param array<string,string> $secrets kid => binary secret
     */
    public function __construct(array $secrets, string $currentKid)
    {
        if (!isset($secrets[$currentKid])) {
            throw new InvalidArgumentException('KeyStore: $currentKid must exist in secrets.');
        }
        foreach ($secrets as $kid => $secret) {
            if (strlen($secret) < 32) {
                throw new InvalidArgumentException("KeyStore: secret for key '$kid' is too short (min 32 bytes).");
            }
        }
        $this->secrets = $secrets;
        $this->currentKid = $currentKid;
    }

    /**
     * @throws RandomException
     */
    public static function generate(?string $kid = null): self
    {
        $kid ??= self::randomId();
        $secret = random_bytes(32);
        return new self([$kid => $secret], $kid);
    }

    public function getCurrentKid(): string
    {
        return $this->currentKid;
    }

    public function getSecret(string $kid): ?string
    {
        return $this->secrets[$kid] ?? null;
    }

    public function addKey(string $kid, string $binarySecret, bool $makeCurrent = false): void
    {
        if (strlen($binarySecret) < 32) {
            throw new InvalidArgumentException('KeyStore: secret must be at least 32 bytes.');
        }
        $this->secrets[$kid] = $binarySecret;
        if ($makeCurrent) {
            $this->currentKid = $kid;
        }
    }

    /**
     * @param array<string,string> $hexByKid kid => hex secret
     */
    public static function fromHex(array $hexByKid, string $currentKid): self
    {
        $bin = [];
        foreach ($hexByKid as $kid => $hex) {
            $binSecret = hex2bin($hex);
            if ($binSecret === false) {
                throw new InvalidArgumentException("KeyStore: invalid hex for key '$kid'.");
            }
            $bin[$kid] = $binSecret;
        }
        return new self($bin, $currentKid);
    }

    /**
     * @return array<string,string> kid => hex
     */
    public function toHex(): array
    {
        return array_map(static function ($secret) {
            return bin2hex($secret);
        }, $this->secrets);
    }

    /**
     * Generate a random, URL-safe ID for key or token use.
     *
     * @param positive-int $bytes
     * @throws RandomException
     */
    public static function randomId(int $bytes = 12): string
    {
        if ($bytes < 1) {
            throw new InvalidArgumentException('KeyStore::randomId(): $bytes must be >= 1.');
        }
        $raw = random_bytes($bytes);
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
