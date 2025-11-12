<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use HybridMind\HybridSeal\KeyStore;
use HybridMind\HybridSeal\TokenManager;

final class HkdfIsolationTest extends TestCase
{
    public function testDifferentAudiencesProduceDifferentTokens(): void
    {
        $kid = 'kid-1';
        $hex = bin2hex(random_bytes(32));
        $ks  = KeyStore::fromHex([$kid => $hex], $kid);
        $tm  = new TokenManager($ks, 0);

        $t1 = $tm->sign(['k'=>'v'], '10m', aud: 'auth:web', sub: 'u1');
        $t2 = $tm->sign(['k'=>'v'], '10m', aud: 'auth:api', sub: 'u1');

        $this->assertNotSame($t1, $t2, 'Tokens should differ across audiences due to HKDF');
    }
}
