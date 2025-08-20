<?php

namespace MoeenBasra\LaravelPassportMongoDB\Bridge;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use MoeenBasra\LaravelPassportMongoDB\Passport;

class ScopeRepository implements ScopeRepositoryInterface
{
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        if (Passport::hasScope($identifier)) {
            return new Scope($identifier);
        }

        return null;
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null
    ): array {
        if (!in_array($grantType, ['password', 'personal_access'])) {
            $scopes = collect($scopes)->reject(function ($scope) {
                return '*' === trim($scope->getIdentifier());
            })->values()->all();
        }

        return collect($scopes)->filter(function ($scope) {
            return Passport::hasScope($scope->getIdentifier());
        })->values()->all();
    }
}
