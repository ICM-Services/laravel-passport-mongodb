<?php

namespace MoeenBasra\LaravelPassportMongoDB\Bridge;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use MoeenBasra\LaravelPassportMongoDB\Events\RefreshTokenCreated;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /**
     * The access token repository instance.
     *
     * @var AccessTokenRepository
     */
    protected $tokens;

    /**
     * The database connection.
     *
     * @var Connection
     */
    protected $database;

    /**
     * The event dispatcher instance.
     *
     * @var Dispatcher
     */
    protected $events;

    /**
     * Create a new repository instance.
     *
     * @return void
     */
    public function __construct(AccessTokenRepository $tokens,
        Connection $database,
        Dispatcher $events)
    {
        $this->events = $events;
        $this->tokens = $tokens;
        $this->database = $database;
    }

    public function getNewRefreshToken(): RefreshTokenEntityInterface|null
    {
        return new RefreshToken();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $this->database->table('oauth_refresh_tokens')->insert([
            '_id' => $id = $refreshTokenEntity->getIdentifier(),
            'access_token_id' => $accessTokenId = $refreshTokenEntity->getAccessToken()->getIdentifier(),
            'revoked' => false,
            'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
        ]);

        $this->events->fire(new RefreshTokenCreated($id, $accessTokenId));
    }

    public function revokeRefreshToken($tokenId): void
    {
        $this->database->table('oauth_refresh_tokens')
                    ->where('_id', $tokenId)->update(['revoked' => true]);
    }

    public function isRefreshTokenRevoked($tokenId): bool
    {
        $refreshToken = $this->database->table('oauth_refresh_tokens')
                    ->where('_id', $tokenId)->first();

        if (null === $refreshToken || $refreshToken->revoked) {
            return true;
        }

        return $this->tokens->isAccessTokenRevoked(
            $refreshToken->access_token_id
        );
    }
}
