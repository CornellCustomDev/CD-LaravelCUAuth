<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature;

use CornellCustomDev\LaravelStarterKit\CUAuth\Events\CUAuthenticated;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\ShibIdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Middleware\AppTesters;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;

class AppTestersTest extends FeatureTestCase
{
    /**
     * AppTesters redirects insecure requests to HTTPS, so most tests need a secure request.
     */
    private function secureRequest(): Request
    {
        return Request::create('https://localhost/test');
    }

    public function testHandleInProduction()
    {
        auth()->login($this->getTestUser());

        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers', 'test-user');
        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));
        $this->assertTrue($response->isForbidden());

        Config::set('app.env', 'production');
        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));
        $this->assertTrue($response->isOk());
    }

    public function testHandleWithAuthorizedUser()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers_field', 'id');
        Config::set('cu-auth.app_testers', 'a-user, test-user');
        Auth::shouldReceive('check')->andReturn(true);
        Auth::shouldReceive('user')->andReturn((object) ['id' => 'test-user']);

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        $this->assertTrue($response->isOk());
    }

    public function testHandleWithUnauthorizedUser()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers_field', 'id');
        Config::set('cu-auth.app_testers', 'test-user');
        Auth::shouldReceive('check')->andReturn(true);
        Auth::shouldReceive('user')->andReturn((object) ['id' => 'not-test-user']);

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        $this->assertTrue($response->isForbidden());
    }

    public function testHandleWithNoUser()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers_field', 'id');
        Config::set('cu-auth.app_testers', 'test-user');

        $request = Request::create('https://localhost/test?page=2');
        $response = (new AppTesters(new ShibIdentityManager))->handle($request, fn () => response('OK'));

        // If nobody is logged in, they are sent to log in and then back to the page they asked for.
        $this->assertTrue($response->isRedirect(
            route('cu-auth.sso-login', ['redirect_url' => 'https://localhost/test?page=2'])
        ));
    }

    public function testHandleRedirectsToHttps()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers', 'test-user');
        Config::set('cu-auth.remote_user_override', 'test-user');

        $request = Request::create('http://localhost/test?page=2');
        $response = (new AppTesters(new ShibIdentityManager))->handle($request, fn () => response('OK'));

        // An insecure request goes to HTTPS first, even for a tester, so the requested URL survives a login.
        $this->assertTrue($response->isRedirect('https://localhost/test?page=2'));
    }

    public function testHandleWithRemoteIdentityTester()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers', 'test-user');
        Config::set('cu-auth.remote_user_override', 'test-user');

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        $this->assertTrue($response->isOk());
    }

    public function testHandleWithRemoteIdentityNonTester()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers', 'test-user');
        Config::set('cu-auth.remote_user_override', 'not-test-user');

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        $this->assertTrue($response->isForbidden());
    }

    public function testHandleLogsInLocalUserBeforeCheckingTesters()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.require_local_user', true);
        Config::set('cu-auth.app_testers_field', 'email');
        Config::set('cu-auth.app_testers', 'test@example.com');
        Config::set('cu-auth.remote_user_override', 'netid');
        Event::listen(CUAuthenticated::class, fn () => auth()->login($this->getTestUser()));

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        // The remote identity is not a tester, but the local user it logs in as is.
        $this->assertTrue($response->isOk());
    }

    public function testHandleRequiresLocalUserWhenRequired()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.require_local_user', true);
        Config::set('cu-auth.app_testers', 'netid');
        Config::set('cu-auth.remote_user_override', 'netid');
        Event::fake([CUAuthenticated::class]);

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        // The remote identity is a tester, but nothing logged in the local user that is required.
        $this->assertTrue($response->isForbidden());
        Event::assertDispatched(CUAuthenticated::class);
    }

    public function testHandleDoesNotLogInLocalUserUnlessRequired()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.require_local_user', false);
        Config::set('cu-auth.app_testers', 'netid');
        Config::set('cu-auth.remote_user_override', 'netid');
        Event::fake([CUAuthenticated::class]);

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        $this->assertTrue($response->isOk());
        Event::assertNotDispatched(CUAuthenticated::class);
    }

    public function testHandleWithNoAppTesters()
    {
        Config::set('app.env', 'local');
        Config::set('cu-auth.app_testers_field', 'id');
        Config::set('cu-auth.app_testers', '');
        Auth::shouldReceive('check')->andReturn(true);
        Auth::shouldReceive('user')->andReturn((object) ['id' => 'test-user']);

        $response = (new AppTesters(new ShibIdentityManager))->handle($this->secureRequest(), fn () => response('OK'));

        // If there are no app testers, anyone can use the app.
        $this->assertTrue($response->isOk());
    }
}
