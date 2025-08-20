<?php

namespace MoeenBasra\LaravelPassportMongoDB\Bridge;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use MoeenBasra\LaravelPassportMongoDB\ClientRepository as ClientModelRepository;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * The client model repository.
     *
     * @var ClientModelRepository
     */
    protected $clients;

    /**
     * Create a new repository instance.
     *
     * @return void
     */
    public function __construct(ClientModelRepository $clients)
    {
        $this->clients = $clients;
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $record = $this->clients->findActive($clientIdentifier);

        if (!$record) {
            return null;
        }

        return new Client(
            $clientIdentifier,
            $record->name,
            $record->redirect,
            // $record->confidential(),
            // $record->provider
        );
    }

    /**
     * Determine if the given client can handle the given grant type.
     *
     * @param \MoeenBasra\LaravelPassportMongoDB\Client $record
     */
    protected function handlesGrant($record, string $grantType): bool
    {
        switch ($grantType) {
            case 'authorization_code':
                return !$record->firstParty();
            case 'personal_access':
                return $record->personal_access_client;
            case 'password':
                return $record->password_client;
            default:
                return true;
        }
    }

    public function validateClient(
        string $clientIdentifier,
        ?string $clientSecret,
        ?string $grantType
    ): bool {
        $record = $this->clients->findActive($clientIdentifier);

        if (!$record || !$this->handlesGrant($record, $grantType)) {
            return false;
        }

        if (!$clientSecret) {
            return false;
        }

        return hash_equals($record->secret, (string) $clientSecret);
    }
}
