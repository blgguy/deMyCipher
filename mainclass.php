<?php
class myCipher {
    private $key; // encryption keys.
    private $roundKeys = [];
    private $numRounds = 8; // Number of rounds per block encryption.
    private $blockSize = 16; // 16 bytes (128 bits) per block.

    /**
     * Constructor.
     *
     * @param string $key The encryption key.
     */
    public function __construct($key) {
        $this->key = $key;
        $this->generateRoundKeys();
    }

    /**
     * Generate round keys from the provided key.
     *
     * This simple example uses SHA-256 on the key and splits it into 32-bit words.
     */
    private function generateRoundKeys() {
        $hash = hash('sha256', $this->key);
        // SHA-256 gives 64 hex characters. We split them into eight 8-character (32-bit) round keys.
        for ($i = 0; $i < 8; $i++) {
            $this->roundKeys[$i] = hexdec(substr($hash, $i * 8, 8));
        }
    }

    /**
     * Encrypt the given plaintext.
     *
     * @param string $plaintext The plaintext to encrypt.
     * @return string The Base64-encoded ciphertext.
     */
    public function encrypt($plaintext) {
        // Pad plaintext using PKCS#7 padding.
        $padLen = $this->blockSize - (strlen($plaintext) % $this->blockSize);
        $plaintext .= str_repeat(chr($padLen), $padLen);

        $ciphertext = '';
        for ($i = 0; $i < strlen($plaintext); $i += $this->blockSize) {
            $block = substr($plaintext, $i, $this->blockSize);
            $ciphertext .= $this->encryptBlock($block);
        }
        return base64_encode($ciphertext);
    }

    /**
     * Decrypt the given ciphertext.
     *
     * @param string $ciphertext The Base64-encoded ciphertext.
     * @return string The decrypted plaintext.
     */
    public function decrypt($ciphertext) {
        $ciphertext = base64_decode($ciphertext);
        $plaintext = '';
        for ($i = 0; $i < strlen($ciphertext); $i += $this->blockSize) {
            $block = substr($ciphertext, $i, $this->blockSize);
            $plaintext .= $this->decryptBlock($block);
        }
        // Remove PKCS#7 padding.
        $padLen = ord(substr($plaintext, -1));
        return substr($plaintext, 0, -$padLen);
    }

    /**
     * Encrypt a 16-byte block.
     *
     * This method divides the block into four 32-bit words, then runs several rounds of reversible mixing.
     *
     * @param string $block A 16-byte string.
     * @return string The encrypted 16-byte block.
     */
    private function encryptBlock($block) {
        // Unpack block into four 32-bit little-endian unsigned integers.
        $words = unpack('V4', $block);
        // Use 1-based array indices.
        $a = $words[1];
        $b = $words[2];
        $c = $words[3];
        $d = $words[4];

        // Perform encryption rounds.
        for ($round = 0; $round < $this->numRounds; $round++) {
            $rk = $this->roundKeys[$round % count($this->roundKeys)];
            // Step 1: XOR a with the round key.
            $a = ($a ^ $rk) & 0xffffffff;
            // Step 2: Add a to b.
            $b = ($b + $a) & 0xffffffff;
            // Step 3: Mix c with b and rotate.
            $c = rotate_left(($c ^ $b), 3);
            // Step 4: Add c to d and rotate.
            $d = rotate_right(($d + $c), 2);
            // Step 5: Swap a and c.
            list($a, $c) = [$c, $a];
        }
        // Pack the words back into a binary string.
        return pack('V4', $a, $b, $c, $d);
    }

    /**
     * Decrypt a 16-byte block.
     *
     * This reverses the encryption process.
     *
     * @param string $block A 16-byte encrypted block.
     * @return string The decrypted 16-byte block.
     */
    private function decryptBlock($block) {
        $words = unpack('V4', $block);
        $a = $words[1];
        $b = $words[2];
        $c = $words[3];
        $d = $words[4];

        // Reverse rounds (from last to first).
        for ($round = $this->numRounds - 1; $round >= 0; $round--) {
            // Reverse Step 5: Swap a and c.
            list($a, $c) = [$c, $a];
            // Reverse Step 4: Inverse of d = rotate_right(d + c, 2)
            $d = (rotate_left($d, 2) - $c) & 0xffffffff;
            // Reverse Step 3: Inverse of c = rotate_left(c ^ b, 3)
            $c = (rotate_right($c, 3) ^ $b) & 0xffffffff;
            // Reverse Step 2: Inverse of b = b + a
            $b = ($b - $a) & 0xffffffff;
            // Reverse Step 1: Inverse of a = a ^ round key (XOR is self-inverse)
            $rk = $this->roundKeys[$round % count($this->roundKeys)];
            $a = ($a ^ $rk) & 0xffffffff;
        }
        return pack('V4', $a, $b, $c, $d);
    }
}

/**
 * Rotate a 32-bit integer to the left.
 *
 * @param int $value The integer value.
 * @param int $shift Number of bits to rotate.
 * @return int The rotated integer.
 */
function rotate_left($value, $shift) {
    return (($value << $shift) | ($value >> (32 - $shift))) & 0xffffffff;
}

/**
 * Rotate a 32-bit integer to the right.
 *
 * @param int $value The integer value.
 * @param int $shift Number of bits to rotate.
 * @return int The rotated integer.
 */
function rotate_right($value, $shift) {
    return (($value >> $shift) | ($value << (32 - $shift))) & 0xffffffff;
}


