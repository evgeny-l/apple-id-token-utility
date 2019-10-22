<?php
namespace EvgenyL\AppleIdTokenUtility;

use EvgenyL\AppleIdTokenUtility\Exceptions\UtilityException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token as JWTToken;
use Lcobucci\JWT\ValidationData;

/**
 * Class IdentityTokenValidator
 * @package EvgenyL\AppleIdTokenUtility
 *
 * Implements Apple's IdentityToken validation logic.
 */
class IdentityTokenValidator
{

    const DEFAULT_APPLE_TOKEN_ISSUER = 'https://appleid.apple.com';

    /** @var ApplePublicKeyProviderInterface */
    private $applePublicKeyProvider;
    /** @var string */
    private $lastVerificationError = '';
    /** @var integer Timestamp. */
    private $time;
    /** @var string */
    private $audience;

    public function __construct($audience, ApplePublicKeyProviderInterface $applePublicKeyProvider)
    {
        $this->setAudience($audience);
        $this->applePublicKeyProvider = $applePublicKeyProvider;
    }

    /**
     * @param string|IdentityToken|\Lcobucci\JWT\Token $token
     * @return bool
     * @throws UtilityException
     */
    public function verifyToken($token)
    {
        $this->lastVerificationError = null;

        if (is_string($token)) {
            $jwtToken = (new Parser())->parse((string) $token);
        } elseif ($token instanceof IdentityToken) {
            $jwtToken = $token->getJwtToken();
        } elseif ($token instanceof JWTToken) {
            $jwtToken = $token;
        } else {
            throw new UtilityException('Invalid token attribute.');
        }

        $tokenHeaders = $jwtToken->getHeaders();
        if (empty($tokenHeaders['kid']) || empty($tokenHeaders['alg'])) {
            $this->lastVerificationError = 'Invalid token headers.';
            return false;
        }

        $signer = $this->getSignerByAlgoName($tokenHeaders['alg']);
        if (!$signer) {
            $this->lastVerificationError = 'Public key signer not found.';
            return false;
        }

        $applePublicKey = $this->applePublicKeyProvider->getKeyById($tokenHeaders['kid']);
        if (!$applePublicKey) {
            $this->lastVerificationError = 'Apple public key not found. Key id: '.$tokenHeaders['kid'];
            return false;
        }
        $publicKeyString = $applePublicKey->getPublicKeyString();

        if (!$jwtToken->verify($signer, $publicKeyString)) {
            $this->lastVerificationError = 'Token signature verification failed.';
            return false;
        }

        $tokenValidationData = new ValidationData($this->getTime());
        $tokenValidationData->setIssuer(self::DEFAULT_APPLE_TOKEN_ISSUER);
        $tokenValidationData->setAudience($this->getAudience());
        $tokenIsValid = $jwtToken->validate($tokenValidationData);
        if (!$tokenIsValid) {
            $this->lastVerificationError = 'Token claims validation failed.';
            return false;
        }

        return $tokenIsValid;
    }

    private function getSignerByAlgoName($algoName)
    {
        $signer = null;
        if ($algoName === 'RS256') {
            $signer = new Sha256();
        }
        return $signer;
    }

    /**
     * Returns error message from last token verification call.
     *
     * @return string
     */
    public function getLastError()
    {
        return $this->lastVerificationError;
    }

    /**
     * Sets time for token expiration validation.
     *
     * @param int $timestamp
     * @return $this
     */
    public function setTime($timestamp)
    {
        $this->time = $timestamp;
        return $this;
    }

    /**
     * Returns time for token expiration validation.
     *
     * @return int
     */
    private function getTime()
    {
        if ($this->time === null) {
            $this->time = time();
        }
        return $this->time;
    }

    /**
     * Returns audience for token validation.
     *
     * @return string
     */
    public function getAudience()
    {
        return $this->audience;
    }

    /**
     * Sets audience for token validation.
     *
     * @param string $audience
     * @return $this
     */
    public function setAudience($audience)
    {
        $this->audience = $audience;
        return $this;
    }

}
