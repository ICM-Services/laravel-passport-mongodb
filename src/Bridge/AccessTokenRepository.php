<?php

namespace MoeenBasra\LaravelPassportMongoDB\Bridge;

use Illuminate\Contracts\Events\Dispatcher;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use MoeenBasra\LaravelPassportMongoDB\Events\AccessTokenCreated;
use MoeenBasra\LaravelPassportMongoDB\TokenRepository;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    use FormatsScopesForStorage;

    /**
     * The token repository instance.
     *
     * @var TokenRepository
     */
    protected $tokenRepository;

    /**
     * The event dispatcher instance.
     *
     * @var Dispatcher
     */
    private $events;

    /**
     * Create a new repository instance.
     */
    public function __construct(TokenRepository $tokenRepository, Dispatcher $events)
    {
        $this->events = $events;
        $this->tokenRepository = $tokenRepository;
    }

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null
    ): AccessTokenEntityInterface {
        return new AccessToken($userIdentifier, $clientEntity, $scopes);
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->tokenRepository->create([
            '_id' => $accessTokenEntity->getIdentifier(),
            'user_id' => $accessTokenEntity->getUserIdentifier(),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'scopes' => $this->scopesToArray($accessTokenEntity->getScopes()),
            'revoked' => false,
            'created_at' => new \DateTime(),
            'updated_at' => new \DateTime(),
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
        ]);

        $this->events->dispatch(new AccessTokenCreated(
            $accessTokenEntity->getIdentifier(),
            $accessTokenEntity->getUserIdentifier(),
            $accessTokenEntity->getClient()->getIdentifier()
        ));
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->tokenRepository->revokeAccessToken($tokenId);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return $this->tokenRepository->isAccessTokenRevoked($tokenId);
    }
}
