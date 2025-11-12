<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Exceptions;

/**
 * Base exception for all HybridSeal errors.
 * Catch this to handle any token-related issue generically.
 */
class HybridSealException extends \RuntimeException {}
