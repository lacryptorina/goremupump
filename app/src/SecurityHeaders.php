<?php
namespace SolanaBot;

class SecurityHeaders {
    public static function apply() {
        header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Content-Security-Policy: default-src \'self\'');
        header('Referrer-Policy: strict-origin-when-cross-origin');
    }
}