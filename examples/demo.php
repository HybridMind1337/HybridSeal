<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use HybridMind\HybridSeal\KeyStore;
use HybridMind\HybridSeal\TokenManager;

$currentKid = '2025-11-01';
$envHexSecret = getenv('HYBRIDSEAL_SECRET_HEX') ?: bin2hex(random_bytes(32));
$keystore = KeyStore::fromHex([$currentKid => $envHexSecret], $currentKid);
$seal = new TokenManager($keystore);

// Auth token
$authToken = $seal->sign(['role' => 'user', 'plan' => 'premium'], '2h', 'auth:web', 'user_123');
echo "Auth token:\n$authToken\n";

// Verify
$p = $seal->verify($authToken, 'auth:web');
echo "Verified for sub={$p->sub}, exp=" . date('c', $p->exp) . "\n";

// CSRF
$csrf = $seal->signCsrf('/checkout', '15m');
$seal->verifyCsrf('/checkout', $csrf);
echo "CSRF OK\n";

// Password reset
$emailHash = hash('sha256', strtolower('user@example.com'));
$reset = $seal->signPasswordReset('user_123', $emailHash, '30m');
$seal->verifyPasswordReset($reset, 'user_123', $emailHash);
echo "Reset OK\n";
