<?php

namespace EvgenyL\AppleIdTokenUtility;

use Lcobucci\JWT\Parser;

/**
 * Class IdentityToken
 * @package EvgenyL\AppleIdTokenUtility
 */
class IdentityToken
{

    const APPLE_USER_ID_CLAIM_NAME = 'sub';

    /** @var string|null */
    private $tokenString;
    /** @var \Lcobucci\JWT\Token */
    private $jwtToken;
    /** @var string */
    private $userId;

    /**
     * @param string $tokenString
     * @return static
     */
    public static function create($tokenString)
    {
        $token = new static;
        $token->tokenString = $tokenString;
        return $token;
    }

    /**
     * Returns JWT token parsed from token string.
     *
     * @return \Lcobucci\JWT\Token
     */
    public function getJwtToken()
    {
        if ($this->jwtToken === null) {
            $this->jwtToken = (new Parser())->parse($this->tokenString);
        }
        return $this->jwtToken;
    }

    /**
     * Returns user id encoded in the token.
     *
     * @return string|null Example value: 001128.1645f230f13d405387470c650dea5fe1.2041
     */
    public function getUserId()
    {
        if ($this->userId === null) {
            $jwtToken = $this->getJwtToken();
            $this->userId = $jwtToken->getClaim(self::APPLE_USER_ID_CLAIM_NAME);
        }
        return $this->userId;
    }

}
