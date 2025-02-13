<?php
  // Example usage:
$encKey  = '23456ABCDetuudueu';
$cipher = new myCipher($encKey);
$text = "text to encrypt!";
$encrypted = $cipher->encrypt($text);
$decrypted = $cipher->decrypt($encrypted);

echo "- Plaintext: " . $text . "\n - Encrypted: " . $encrypted . "\n - Decrypted: " . $decrypted . "\n";
?>
