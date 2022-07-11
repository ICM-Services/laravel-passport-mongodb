<?php

namespace MoeenBasra\LaravelPassportMongoDB\Bridge;

use MoeenBasra\LaravelPassportMongoDB\ClientRepository as ClientModelRepository;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * The client model repository.
     *
     * @var \MoeenBasra\LaravelPassportMongoDB\ClientRepository
     */
    protected $clients;

    /**
     * Create a new repository instance.
     *
     * @param  \MoeenBasra\LaravelPassportMongoDB\ClientRepository  $clients
     * @return void
     */
    public function __construct(ClientModelRepository $clients)
    {
        $this->clients = $clients;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier)
    {
        $record = $this->clients->findActive($clientIdentifier);

        if (! $record) {
            return;
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
     * @param  \MoeenBasra\LaravelPassportMongoDB\Client  $record
     * @param  string  $grantType
     * @return bool
     */
    protected function handlesGrant($record, $grantType)
    {
        switch ($grantType) {
            case 'authorization_code':
                return ! $record->firstParty();
            case 'personal_access':
                return $record->personal_access_client;
            case 'password':
                return $record->password_client;
            default:
                return true;
        }
    }

    public function validateClient($clientIdentifier, $clientSecret, $grantType) {
        // First, we will verify that the client exists and is authorized to create personal
        // access tokens. Generally personal access tokens are only generated by the user
        // from the main interface. We'll only let certain clients generate the tokens.
        $record = $this->clients->findActive($clientIdentifier);

        if (! $record || ! $this->handlesGrant($record, $grantType) || ! hash_equals($record->secret, (string) $clientSecret)) {
            return false;
        }

        return true;
    }
}
