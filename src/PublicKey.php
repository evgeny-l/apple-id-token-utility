<?php
namespace EvgenyL\AppleIdTokenUtility;

use EvgenyL\AppleIdTokenUtility\Exceptions\UtilityException;
use EvgenyL\AppleIdTokenUtility\JWT\JWK;
use UnexpectedValueException;

/**
 * Class PublicKey
 * @package EvgenyL\AppleIdTokenUtility
 *
 * Wraps basic public key methods.
 */
class PublicKey
{

    /** @var resource */
    private $jwkKey;

    /**
     * Returns public key string.
     *
     * @return string
     * @throws UtilityException
     */
    public function getPublicKeyString()
    {
        $publicKeyDetails = openssl_pkey_get_details($this->jwkKey);
        $publicKeyString = $publicKeyDetails['key'] ?? null;
        if (!is_string($publicKeyString)) {
            throw new UtilityException('Unable to get Apple public key string.');
        }
        return $publicKeyString;
    }

    /**
     * Parses array of public key data.
     *
     * @param array $publicKeyData
     * @return PublicKey
     * @throws UtilityException
     */
    public static function parseKey(array $publicKeyData)
    {
        $key = new PublicKey;
        try {
            $key->jwkKey = JWK::parseKey($publicKeyData);
            if (!is_resource($key->jwkKey)) {
                throw new UtilityException('Unable to parse JWK key.');
            }
        } catch (UnexpectedValueException $exception) {
            throw new UtilityException('Unable to parse Apple public key.', 0, $exception);
        }
        return $key;
    }

}