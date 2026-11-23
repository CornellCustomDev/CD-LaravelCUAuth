<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Middleware;

use Closure;
use CornellCustomDev\LaravelStarterKit\CUAuth\Events\CUAuthenticated;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\IdentityManager;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class AppTesters
{
    private Collection $app_testers;

    public function __construct(
        protected IdentityManager $identityManager
    ) {
        $this->app_testers = Str::of(config('cu-auth.app_testers'))
            ->split('/[\s,]+/')
            ->filter();
    }

    public function handle(Request $request, Closure $next): Response
    {
        // Anyone can use production
        if (config('app.env') === 'production') {
            return $next($request);
        }

        // If no app_testers are defined, anyone can use
        if ($this->app_testers->isEmpty()) {
            return $next($request);
        }

        // Make sure we are using HTTPS.
        if (! $request->secure()) {
            return redirect()->secure($request->getRequestUri());
        }

        // SSO routes need to pass through so a tester can log in.
        if ($request->routeIs('cu-auth.sso-*', 'cu-auth.shibboleth-*')) {
            return $next($request);
        }

        if (! auth()->check()) {
            // If nobody is logged in yet, redirect to the SSO login route instead of denying access.
            if (! $this->identityManager->hasRemoteIdentity()) {
                return redirect()->route('cu-auth.sso-login', ['redirect_url' => $request->fullUrl()]);
            }

            // If requiring a local user, attempt to log in the user so they can be checked as a tester.
            if (config('cu-auth.require_local_user')) {
                event(new CUAuthenticated);

                // If the authenticated user is still not logged in, return a 403.
                if (! auth()->check()) {
                    return $this->forbidden();
                }
            }
        }

        if (auth()->check()) {
            $appTestersField = config('cu-auth.app_testers_field');
            $tester = auth()->user()->$appTestersField ?? '';
        } else {
            $tester = $this->identityManager->getIdentity()?->id() ?: '';
        }

        if ($this->app_testers->contains($tester)) {
            return $next($request);
        }

        return $this->forbidden();
    }

    private function forbidden(): Response
    {
        if (app()->runningInConsole()) {
            return response('Forbidden', Response::HTTP_FORBIDDEN);
        }
        abort(403);
    }
}
