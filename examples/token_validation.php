<?php
include_once(__DIR__.'/../vendor/autoload.php');

use EvgenyL\AppleIdTokenUtility\ApplePublicKeyProvider;
use EvgenyL\AppleIdTokenUtility\IdentityTokenValidator;
use EvgenyL\AppleIdTokenUtility\IdentityToken;

// Apple's identity token for example.
$token = "eyJraWQiOiJBSURPUEsxIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiYXBwLnF1ZXN0aWZ5LmNsaWVudCIsImV4cCI6MTU3MTUxODAxOSwiaWF0IjoxNTcxNTE3NDE5LCJzdWIiOiIwMDExMjguMTY0NWYyMzBmMTNkNDA1Mzg3NDcwYzY1MGRlYTVmZTEuMjA0MSIsImNfaGFzaCI6Im16WjNGWnBhY2taZlJ6TmFlbDMtQmciLCJhdXRoX3RpbWUiOjE1NzE1MTc0MTl9.JsCSbkH7aHlH1tabqjOu_tsZ90_JyGAsz1namB4KYWiI6yyfon29lBEDDtzJHb5yXqlPdtbmIfnc_jFa81FOTBTvuyHk__BSLleVBTefzdaau2_hb_9n6ADMeI5_MhIRSW7TpZGUm69v8obW8_A4Z1hE-NQrBVicIRDdSx0d5_nYvGqLWQoRH0VjkopC4IDfkwNtEbpyEYGbzh9o5GOVAmz1N9bJkpxP3cmFtBjG97zT29QNCVKsrYbWW6jyYaSuEoYg5VfYx0pA2KD1gyY6_QFacSWE1PpmYzgRvztDGSHxjJhslVOHwC85upI7t6oxLh3Dx2HPelarUaxFnQFXbA";
// Your Apple's service Id to validate against.
$appleServiceId = 'app.questify.client';

// File to store locally Apple's public keys data.
$keysFilePath = __DIR__.'/tmp_keys.json';
$applePublicTokenProvider = new ApplePublicKeyProvider($keysFilePath);
// Token validator and it's settings.
$tokenValidator = new IdentityTokenValidator($appleServiceId, $applePublicTokenProvider);
// Timestamp to pass claims validation for this exact token (token expiration). Optional in production.
$tokenValidator->setTime(1571517419);

// Token wrap.
$identityToken = IdentityToken::create($token);
if ($tokenValidator->verifyToken($identityToken)) {
    echo "Token is valid!\n";
} else {
    echo "Token is invalid! Error: {$tokenValidator->getLastError()}\n";
}

$userId = $identityToken->getUserId();
echo "Parsed user Id is: $userId\n";
