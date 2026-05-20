<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Middleware;

use Closure;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\IdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Middleware\Concerns\ChecksLocalLogin;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class LivewireAuth
{
    use ChecksLocalLogin;

    public function __construct(
        protected IdentityManager $identityManager
    ) {}

    /**
     * Assure all Livewire updates are from authenticated users.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->path() !== 'livewire/update' || $request->getMethod() !== 'POST') {
            return $next($request);
        }

        if ($this->isLoggedInLocally() || $this->identityManager->hasRemoteIdentity()) {
            return $next($request);
        }

        // This is a /livewire/update without a logged in user, so return forbidden.
        if (app()->runningInConsole()) {
            return response('Forbidden', Response::HTTP_FORBIDDEN);
        }
        abort(403);
    }
}
