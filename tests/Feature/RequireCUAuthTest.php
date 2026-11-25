<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature;

use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\ShibIdentityManager;
use Orchestra\Testbench\Attributes\DefineEnvironment;

class RequireCUAuthTest extends FeatureTestCase
{
    protected function requireCUAuth($app): void
    {
        $app['config']->set('cu-auth.require_cu_auth', true);
    }

    protected function requireCUAuthInProduction($app): void
    {
        $this->requireCUAuth($app);
        $app['config']->set('app.env', 'production');
        $app['config']->set('cu-auth.app_testers', 'test-user');
    }

    protected function defineWebRoutes($router): void
    {
        $router->get('/public', fn () => 'OK')->name('public');
    }

    public function testWebRoutesAreOpenByDefault()
    {
        $this->get('https://localhost/public')->assertOk();
    }

    #[DefineEnvironment('requireCUAuth')]
    public function testGuestIsRedirectedToSsoLogin()
    {
        $this->get('https://localhost/public?page=2')
            ->assertRedirect(route('cu-auth.sso-login', ['redirect_url' => 'https://localhost/public?page=2']));
    }

    #[DefineEnvironment('requireCUAuth')]
    public function testRemoteIdentityIsAllowed()
    {
        config(['cu-auth.remote_user_override' => 'netid']);

        $this->get('https://localhost/public')->assertOk();
    }

    #[DefineEnvironment('requireCUAuth')]
    public function testOnlyAppTestersAreAllowed()
    {
        config(['cu-auth.app_testers' => 'test-user']);

        config(['cu-auth.remote_user_override' => 'not-test-user']);
        $this->get('https://localhost/public')->assertForbidden();

        session()->flush();
        config(['cu-auth.remote_user_override' => 'test-user']);
        $this->get('https://localhost/public')->assertOk();
    }

    #[DefineEnvironment('requireCUAuth')]
    public function testGuestCanReachSsoLoginWithAppTesters()
    {
        config(['cu-auth.app_testers' => 'test-user']);

        // The SSO login route is not forbidden, so a tester can log in.
        $response = $this->get('https://localhost/sso/login');

        $response->assertRedirect();
        $this->assertStringStartsWith('https://localhost'.ShibIdentityManager::SHIB_LOGIN_URL, $response->headers->get('Location'));
    }

    #[DefineEnvironment('requireCUAuthInProduction')]
    public function testGuestIsRedirectedToSsoLoginInProduction()
    {
        $this->get('https://localhost/public')
            ->assertRedirect(route('cu-auth.sso-login', ['redirect_url' => 'https://localhost/public']));

        // Leave production so test teardown does not ask to confirm database changes.
        config(['app.env' => 'local']);
        $this->app->detectEnvironment(fn () => 'local');
    }
}
