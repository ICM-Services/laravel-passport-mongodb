<?php

namespace MoeenBasra\LaravelPassportMongoDB\Bridge;

use Illuminate\Database\Connection;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    use FormatsScopesForStorage;

    /**
     * The database connection.
     *
     * @var Connection
     */
    protected $database;

    /**
     * Create a new repository instance.
     *
     * @return void
     */
    public function __construct(Connection $database)
    {
        $this->database = $database;
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $this->database->table('oauth_auth_codes')->insert([
            '_id' => $authCodeEntity->getIdentifier(),
            'user_id' => $authCodeEntity->getUserIdentifier(),
            'client_id' => $authCodeEntity->getClient()->getIdentifier(),
            'scopes' => $this->formatScopesForStorage($authCodeEntity->getScopes()),
            'revoked' => false,
            'expires_at' => $authCodeEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeAuthCode($codeId): void
    {
        $this->database->table('oauth_auth_codes')
                    ->where('_id', $codeId)->update(['revoked' => true]);
    }

    public function isAuthCodeRevoked($codeId): bool
    {
        return $this->database->table('oauth_auth_codes')
                    ->where('_id', $codeId)->where('revoked', 1)->exists();
    }
}
