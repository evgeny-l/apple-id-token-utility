<?php
namespace EvgenyL\AppleIdTokenUtility;

/**
 * Interface ApplePublicKeyProviderInterface
 * @package EvgenyL\AppleIdTokenUtility
 *
 * Provides Apple's public keys by their id.
 */
interface ApplePublicKeyProviderInterface
{

    /**
     * Returns apple public
     *
     * @param string $keyId
     * @return null|PublicKey
     */
    public function getKeyById($keyId);

}
