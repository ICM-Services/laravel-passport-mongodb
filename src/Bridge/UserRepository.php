<?php

namespace MoeenBasra\LaravelPassportMongoDB\Bridge;

use Illuminate\Contracts\Hashing\Hasher;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

class UserRepository implements UserRepositoryInterface
{
    /**
     * The hasher implementation.
     *
     * @var Hasher
     */
    protected $hasher;

    /**
     * Create a new repository instance.
     *
     * @return void
     */
    public function __construct(Hasher $hasher)
    {
        $this->hasher = $hasher;
    }

    public function getUserEntityByUserCredentials($username, $password, $grantType, ClientEntityInterface $clientEntity): ?UserEntityInterface
    {
        $provider = config('auth.guards.api.provider');

        if (is_null($model = config('auth.providers.'.$provider.'.model'))) {
            throw new \RuntimeException('Unable to determine authentication model from configuration.');
        }

        if (method_exists($model, 'findForPassport')) {
            $user = (new $model())->findForPassport($username);
        } else {
            $user = (new $model())->where('email', $username)->first();
        }

        if (!$user) {
            return null;
        } elseif (method_exists($user, 'validateForPassportPasswordGrant')) {
            if (!$user->validateForPassportPasswordGrant($password)) {
                return null;
            }
        } elseif (!$this->hasher->check($password, $user->getAuthPassword())) {
            return null;
        }

        return new User($user->getAuthIdentifier());
    }
}
