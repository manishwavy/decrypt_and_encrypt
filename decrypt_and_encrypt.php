function encrypt1_decrypt1($string, $action)
{
    $encrypt_method = "AES-256-CBC";
    $secret_key = 'AA74CDCC2BBRT9351'; // user define private key
    $secret_iv = '5fgf5HJ5'; // user define secret key
    $key = hash('sha256', $secret_key);
    $iv = substr(hash('sha256', $secret_iv), 0, 16); // sha256 is hash_hmac_algo
    if ($action == 'encrypt') {
        $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
        $output = base64_encode($output);
    } else if ($action == 'decrypt') {
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
    }
    return $output;
}
