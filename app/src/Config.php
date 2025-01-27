<?php
namespace SolanaBot;

class Config {
    private static $instance;
    private $encryptionKey;
    
    private function __construct() {
        $this->encryptionKey = getenv('APP_ENCRYPTION_KEY');
        if (!$this->encryptionKey || strlen($this->encryptionKey) !== 32) {
            throw new \RuntimeException('Invalid encryption key configuration');
        }
    }
    
    public static function getInstance() {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function encrypt($data) {
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt(
            $data,
            'AES-256-CBC',
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        return base64_encode($iv . $ciphertext);
    }
    
    public function decrypt($data) {
        $data = base64_decode($data);
        $iv = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        return openssl_decrypt(
            $ciphertext,
            'AES-256-CBC',
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
}