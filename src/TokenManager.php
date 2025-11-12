<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal;

use HybridMind\HybridSeal\Crypto\HmacSha256;
use HybridMind\HybridSeal\Crypto\Kdf;
use HybridMind\HybridSeal\Util\Base64Url;
use HybridMind\HybridSeal\Replay\JtiStoreInterface;
use HybridMind\HybridSeal\Exceptions\{
    MalformedTokenException,
    InvalidSignatureException,
    UnknownKeyException,
    TokenExpiredException,
    TokenNotYetValidException,
    AudienceMismatchException,
    SubjectMismatchException,
    ReplayDetectedException
};

/**
 * TokenManager — secure, dependency-free HS256 token generator/validator.
 */
final class TokenManager
{
    private const HEADER_TYP = 'HSEAL';
    private const HEADER_ALG = 'HS256';
    private const HEADER_VER = 1;

    private const MAX_HEADER_BYTES  = 4096; // 4 KiB
    private const MAX_PAYLOAD_BYTES = 4096; // 4 KiB

    private const HKDF_INFO_PREFIX = 'HSEAL-HS256:';

    private KeyStore $keys;
    private int $clockSkew;
    private ?JtiStoreInterface $jtiStore;

    public function __construct(KeyStore $keys, int $clockSkew = 60, ?JtiStoreInterface $jtiStore = null)
    {
        $this->keys = $keys;
        $this->clockSkew = max(0, $clockSkew);
        $this->jtiStore = $jtiStore;
    }

    /**
     * @param array<string,mixed>|null $data
     * @param string|int $expiresIn
     * @param string|null $aud
     * @param string|null $sub
     * @param string|int|null $notBefore
     * @param array<string,mixed>|null $headerExtra
     * @throws MalformedTokenException|UnknownKeyException
     */
    public function sign(
        ?array $data,
        string|int $expiresIn,
        ?string $aud = null,
        ?string $sub = null,
        string|int|null $notBefore = null,
        ?array $headerExtra = null
    ): string {
        $now = time();
        $exp = $now + $this->parseDuration($expiresIn);
        $nbf = $notBefore !== null ? $now + $this->parseDuration($notBefore) : null;

        $kid = $this->keys->getCurrentKid();
        $secret = $this->keys->getSecret($kid);
        if ($secret === null) {
            throw new UnknownKeyException('No secret found for current key id.');
        }

        $header = array_merge([
            'alg' => self::HEADER_ALG,
            'typ' => self::HEADER_TYP,
            'kid' => $kid,
            'ver' => self::HEADER_VER,
        ], $headerExtra ?? []);

        $payload = new TokenPayload(
            iat: $now,
            exp: $exp,
            nbf: $nbf,
            jti: KeyStore::randomId(12),
            aud: $aud,
            sub: $sub,
            data: $data
        );

        try {
            $headerJson  = json_encode($header, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $payloadJson = json_encode($payload->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new MalformedTokenException('JSON encode failed: ' . $e->getMessage());
        }

        $h = Base64Url::encode($headerJson);
        $p = Base64Url::encode($payloadJson);
        $signingInput = "{$h}.{$p}";

        $info    = self::HKDF_INFO_PREFIX . ($aud ?? 'generic');
        $derived = Kdf::hkdfSha256($secret, $kid, $info);

        $sig = HmacSha256::sign($derived, $signingInput);
        return "{$signingInput}." . Base64Url::encode($sig);
    }

    /**
     * @throws MalformedTokenException|UnknownKeyException|InvalidSignatureException|TokenNotYetValidException|TokenExpiredException|AudienceMismatchException|SubjectMismatchException|ReplayDetectedException
     */
    public function verify(string $token, ?string $expectedAud = null, ?string $expectedSub = null): TokenPayload
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new MalformedTokenException('Malformed token structure.');
        }

        [$h64, $p64, $s64] = $parts;

        try {
            $hRaw = Base64Url::decode($h64);
            $pRaw = Base64Url::decode($p64);
            $sRaw = Base64Url::decode($s64);
        } catch (\InvalidArgumentException $e) {
            throw new MalformedTokenException('Base64Url decode failed: ' . $e->getMessage());
        }

        if (strlen($hRaw) > self::MAX_HEADER_BYTES || strlen($pRaw) > self::MAX_PAYLOAD_BYTES) {
            throw new MalformedTokenException('Token sections exceed maximum allowed size.');
        }

        try {
            /** @var array<string,mixed>|null $header */
            $header = json_decode($hRaw, true, flags: JSON_THROW_ON_ERROR);
            /** @var array<string,mixed>|null $payloadArr */
            $payloadArr = json_decode($pRaw, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new MalformedTokenException('JSON decode failed: ' . $e->getMessage());
        }

        if (!is_array($header) || !is_array($payloadArr)) {
            throw new MalformedTokenException('Invalid token JSON structures.');
        }

        if (($header['alg'] ?? null) !== self::HEADER_ALG ||
            ($header['typ'] ?? null) !== self::HEADER_TYP ||
            ($header['ver'] ?? null) !== self::HEADER_VER ||
            !isset($header['kid']) || !is_string($header['kid']) || $header['kid'] === '') {
            throw new MalformedTokenException('Unsupported or missing header fields (alg/typ/ver/kid).');
        }

        $kid = $header['kid'];
        $secret = $this->keys->getSecret($kid);
        if ($secret === null) {
            throw new UnknownKeyException("Unknown key id: {$kid}");
        }

        $audInPayload = $payloadArr['aud'] ?? 'generic';
        if (!is_string($audInPayload) || $audInPayload === '') {
            $audInPayload = 'generic';
        }
        $info    = self::HKDF_INFO_PREFIX . $audInPayload;
        $derived = Kdf::hkdfSha256($secret, $kid, $info);

        if (strlen($sRaw) !== 32) {
            throw new InvalidSignatureException('Invalid signature length.');
        }
        $expectedSig = HmacSha256::sign($derived, "{$h64}.{$p64}");
        if (!HmacSha256::equals($expectedSig, $sRaw)) {
            throw new InvalidSignatureException('Invalid signature.');
        }

        try {
            $payload = TokenPayload::fromArray($payloadArr);
        } catch (\InvalidArgumentException $e) {
            throw new MalformedTokenException('Payload structure invalid: ' . $e->getMessage());
        }

        $now = time();
        if ($payload->nbf !== null && $now + $this->clockSkew < $payload->nbf) {
            throw new TokenNotYetValidException('Token not active yet.');
        }
        if ($now - $this->clockSkew >= $payload->exp) {
            throw new TokenExpiredException('Token expired.');
        }

        if ($expectedAud !== null && $payload->aud !== $expectedAud) {
            throw new AudienceMismatchException('Audience mismatch.');
        }
        if ($expectedSub !== null && $payload->sub !== $expectedSub) {
            throw new SubjectMismatchException('Subject mismatch.');
        }

        if ($this->jtiStore) {
            $ttl = max(0, $payload->exp - $now);
            if (!$this->jtiStore->tryConsume($payload->jti, $ttl)) {
                throw new ReplayDetectedException('Replay detected: token JTI already used.');
            }
        }

        return $payload;
    }

    public function signCsrf(string $action, string|int $ttl = '10m'): string
    {
        return $this->sign(null, $ttl, aud: 'csrf:' . $action);
    }

    public function verifyCsrf(string $action, string $token): TokenPayload
    {
        return $this->verify($token, expectedAud: 'csrf:' . $action);
    }

    public function signPasswordReset(string $userId, string $emailHash, string|int $ttl = '30m'): string
    {
        return $this->sign(
            data: ['emailHash' => $emailHash],
            expiresIn: $ttl,
            aud: 'reset:password',
            sub: $userId
        );
    }

    public function verifyPasswordReset(string $token, string $userId, string $emailHash): TokenPayload
    {
        $p = $this->verify($token, expectedAud: 'reset:password', expectedSub: $userId);
        if (($p->data['emailHash'] ?? null) !== $emailHash) {
            throw new InvalidSignatureException('Email hash mismatch.');
        }
        return $p;
    }

    public function builder(): \HybridMind\HybridSeal\Builder\TokenBuilder
    {
        return new \HybridMind\HybridSeal\Builder\TokenBuilder($this);
    }

    private function parseDuration(string|int $input): int
    {
        if (is_int($input)) {
            return $input;
        }

        $str = trim($input);
        if ($str === '' || ctype_digit($str)) {
            return (int) $str;
        }

        if (!preg_match('/^(\d+)\s*([smhd])$/i', $str, $m)) {
            throw new MalformedTokenException("Invalid duration format: {$input}");
        }

        $n = (int) $m[1];
        return match (strtolower($m[2])) {
            's' => $n,
            'm' => $n * 60,
            'h' => $n * 3600,
            'd' => $n * 86400,
            default => throw new MalformedTokenException("Invalid duration unit: {$m[2]}")
        };
    }
}
