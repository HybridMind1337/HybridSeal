<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use HybridMind\HybridSeal\KeyStore;
use HybridMind\HybridSeal\TokenManager;
use HybridMind\HybridSeal\Exceptions\{
    AudienceMismatchException,
    TokenExpiredException
};

final class TokenManagerTest extends TestCase
{
    public function testSignAndVerify(): void
    {
        $kid = 'test-kid';
        $hex = bin2hex(random_bytes(32));
        $ks  = KeyStore::fromHex([$kid => $hex], $kid);
        $tm  = new TokenManager($ks, 0);

        $token = $tm->sign(
            data: ['role' => 'user'],
            expiresIn: '10m',
            aud: 'auth:web',
            sub: 'user_1'
        );

        $p = $tm->verify($token, expectedAud: 'auth:web', expectedSub: 'user_1');

        $this->assertSame('user_1', $p->sub);
        $this->assertSame('auth:web', $p->aud);
        $this->assertSame('user', $p->data['role'] ?? null);
    }

    public function testAudienceMismatch(): void
    {
        $kid = 'test-kid';
        $hex = bin2hex(random_bytes(32));
        $ks  = KeyStore::fromHex([$kid => $hex], $kid);
        $tm  = new TokenManager($ks, 0);

        $token = $tm->sign(null, '5m', aud: 'auth:web');

        $this->expectException(AudienceMismatchException::class);
        $tm->verify($token, expectedAud: 'auth:api');
    }

    public function testExpiredToken(): void
    {
        $kid = 'test-kid';
        $hex = bin2hex(random_bytes(32));
        $ks  = KeyStore::fromHex([$kid => $hex], $kid);
        $tm  = new TokenManager($ks, 0);

        $token = $tm->sign(null, '1s', aud: 'auth:web');
        usleep(1_200_000);

        $this->expectException(TokenExpiredException::class);
        $tm->verify($token, expectedAud: 'auth:web');
    }
}
