<?php

namespace MoeenBasra\LaravelPassportMongoDB;

use MongoDB\Laravel\Eloquent\Model;

class AuthCode extends Model
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'oauth_auth_codes';

    /**
     * The guarded attributes on the model.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'revoked' => 'bool',
    ];

    /**
     * The attributes that should be mutated to dates.
     *
     * @var array
     */
    protected $dates = [
        'expires_at',
    ];

    /**
     * Get the client that owns the authentication code.
     *
     * @return \MongoDB\Laravel\Relations\BelongsTo
     */
    public function client()
    {
        return $this->belongTo(Client::class);
    }
}
