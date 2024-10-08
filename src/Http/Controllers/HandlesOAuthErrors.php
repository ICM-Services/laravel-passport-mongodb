<?php

namespace MoeenBasra\LaravelPassportMongoDB\Http\Controllers;

use Exception;
use Throwable;
use Illuminate\Http\Response;
use Illuminate\Container\Container;
use Laminas\Diactoros\Response as Psr7Response;
use Illuminate\Contracts\Debug\ExceptionHandler;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\Debug\Exception\FatalThrowableError;

trait HandlesOAuthErrors
{
    use ConvertsPsrResponses;

    /**
     * Perform the given callback with exception handling.
     *
     * @param  \Closure  $callback
     * @return \Illuminate\Http\Response
     */
    // protected function withErrorHandling($callback)
    // {
    //     try {
    //         return $callback();
    //     } catch (OAuthServerException $e) {
    //         $this->exceptionHandler()->report($e);

    //         return $this->convertResponse(
    //             $e->generateHttpResponse(new Psr7Response)
    //         );
    //     } catch (Exception $e) {
    //         $this->exceptionHandler()->report($e);

    //         return new Response($e->getMessage(), 500);
    //     } catch (Throwable $e) {
    //         $this->exceptionHandler()->report(new FatalThrowableError($e));

    //         return new Response($e->getMessage(), 500);
    //     }
    // }

    protected function withErrorHandling($callback)
    {
        try {
            return $callback();
        } catch (LeagueException $e) {
            throw new OAuthServerException(
                $e,
                $this->convertResponse($e->generateHttpResponse(new Psr7Response)),
                $e->getMessage()
            );
        }
    }

    /**
     * Get the exception handler instance.
     *
     * @return \Illuminate\Contracts\Debug\ExceptionHandler
     */
    protected function exceptionHandler()
    {
        return Container::getInstance()->make(ExceptionHandler::class);
    }
}
