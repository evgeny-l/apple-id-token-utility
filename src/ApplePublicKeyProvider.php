<?php
namespace EvgenyL\AppleIdTokenUtility;

use EvgenyL\AppleIdTokenUtility\Exceptions\UtilityException;

/**
 * Class ApplePublicKeyProvider
 * @package EvgenyL\AppleIdTokenUtility
 *
 * Manages access to Apple's public keys data.
 */
class ApplePublicKeyProvider implements ApplePublicKeyProviderInterface
{

    const APPLE_PUBLIC_KEYS_URI = 'https://appleid.apple.com/auth/keys';

    /** @var string */
    private $keysFilePath;

    /**
     * ApplePublicKeyProvider constructor.
     * @param string $keysFilePath
     */
    public function __construct($keysFilePath)
    {
        $this->keysFilePath = $keysFilePath;
    }

    /**
     * @inheritdoc
     */
    public function getKeyById($keyId)
    {
        $keysArray = $this->getKeysArray();
        $key = null;
        foreach ($keysArray as $keyData) {
            $keyDataId = $keyData['kid'] ?? null;
            if ($keyDataId == $keyId) {
                $key = PublicKey::parseKey($keyData);
                break;
            }
        }
        return $key;
    }

    protected function getKeysArray()
    {
        $keysFilePath = $this->keysFilePath;
        if (empty($keysFilePath) || !is_string($keysFilePath)) {
            throw new UtilityException('Apple public keys file path is not set.');
        }

        if (!file_exists($keysFilePath)) {
            $this->createFileAndUploadApplePublicKeys($keysFilePath);
        }

        $keyDataString = file_get_contents($keysFilePath);
        if (!is_string($keyDataString)) {
            throw new UtilityException('Apple public keys file is not readable.');
        }

        $keysData = json_decode($keyDataString, true);
        if (!is_array($keysData)) {
            throw new UtilityException('Invalid Apple public keys file contents. File path: '.$keysFilePath);
        }

        if (empty($keysData['keys'])) {
            throw new UtilityException('Apple public keys file contents doesn\'t contains keys data. File path: '.$keysFilePath);
        }

        return $keysData['keys'];
    }

    protected function createFileAndUploadApplePublicKeys($keysFilePath)
    {
        $keysData = file_get_contents(self::APPLE_PUBLIC_KEYS_URI);
        if ($keysData === false) {
            throw new UtilityException('Unable to download Apple public keys JSON file.');
        }
        if (file_put_contents($keysFilePath, $keysData) === false) {
            throw new UtilityException('Unable to save Apple public keys JSON file. File path: '.$keysFilePath);
        }
    }

}
