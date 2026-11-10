<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature;

use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\IdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\SamlIdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\ShibIdentityManager;
use Illuminate\Support\Uri;
use Illuminate\Testing\TestResponse;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * redirect_url, RelayState and the logout return URL must stay on this site (no open redirect).
 */
class RedirectUrlTest extends FeatureTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->app->singleton(IdentityManager::class, ShibIdentityManager::class);
        config(['cu-auth.apache_shib_user_variable' => 'REMOTE_USER_TEST']);
    }

    public static function redirectUrlProvider(): array
    {
        return [
            'path' => ['/home?tab=1#top', '/home?tab=1#top'],
            'same host' => ['https://localhost/home', 'https://localhost/home'],
            'same host, other case' => ['https://LOCALHOST/home', 'https://LOCALHOST/home'],
            'http' => ['http://localhost/home', '/'],
            'missing' => [null, '/'],
            'other host' => ['https://evil.test/home', '/'],
            'protocol-relative' => ['//evil.test/home', '/'],
            'tab' => ["/\t/evil.test", '/'],
            'host suffix' => ['https://localhost.evil.test/', '/'],
            'fullwidth at, local first' => ['https://localhost＠evil.test/', '/'],
            'fullwidth at, local last' => ['https://evil.test＠localhost/', '/'],
            // Not a URL on another host, so these resolve to paths on this site.
            'backslash' => ['/\\evil.test', '/\\evil.test'],
            'javascript' => ['javascript:alert(1)', 'javascript:alert(1)'],
            'bare host' => ['evil.test', 'evil.test'],
        ];
    }

    private function assertRedirectsLocally(TestResponse $response, string $expected): void
    {
        $response->assertRedirect(secure_url($expected));
        $this->assertSame('localhost', Uri::of($response->headers->get('Location'))->host());
    }

    #[DataProvider('redirectUrlProvider')]
    public function testLoginRedirectUrl(?string $url, string $expected)
    {
        $response = $this->withServerVariables(['REMOTE_USER_TEST' => 'abc123'])
            ->get(route('cu-auth.sso-login', array_filter(['redirect_url' => $url])));

        $this->assertRedirectsLocally($response, $expected);
    }

    #[DataProvider('redirectUrlProvider')]
    public function testAcsRedirectUrl(?string $url, string $expected)
    {
        $response = $this->withServerVariables(['REMOTE_USER_TEST' => 'abc123'])
            ->get(route('cu-auth.sso-acs', array_filter(['redirect_url' => $url])));

        $this->assertRedirectsLocally($response, $expected);
    }

    #[DataProvider('redirectUrlProvider')]
    public function testSamlAcsRelayState(?string $url, string $expected)
    {
        // Skip SAML response verification; this test covers only the RelayState redirect.
        $identityManager = Mockery::mock(SamlIdentityManager::class)->makePartial();
        $identityManager->shouldReceive('storeIdentity')->andReturnNull();
        $this->app->instance(IdentityManager::class, $identityManager);

        $response = $this->post(route('cu-auth.sso-acs'), array_filter(['RelayState' => $url]));

        $this->assertRedirectsLocally($response, $expected);
    }

    #[DataProvider('redirectUrlProvider')]
    public function testLogoutReturnUrl(?string $url, string $expected)
    {
        // With a remote user override, Shib's getSloUrl() returns the return URL itself.
        config(['cu-auth.remote_user_override' => 'abc123']);

        $response = $this->withServerVariables(['REMOTE_USER_TEST' => 'abc123'])
            ->get(route('cu-auth.sso-logout', array_filter(['return' => $url])));

        $this->assertRedirectsLocally($response, $expected);
    }

    public static function redirectRouteProvider(): array
    {
        return [
            'sso-login' => ['cu-auth.sso-login', 'redirect_url'],
            'sso-acs' => ['cu-auth.sso-acs', 'redirect_url'],
            'sso-logout' => ['cu-auth.sso-logout', 'return'],
        ];
    }

    #[DataProvider('redirectRouteProvider')]
    public function testArrayRedirectUrlIsBadRequest(string $route, string $parameter)
    {
        $response = $this->withServerVariables(['REMOTE_USER_TEST' => 'abc123'])
            ->get(route($route, [$parameter => ['https://evil.test/']]));

        $response->assertBadRequest();
    }

    public function testUnauthenticatedLoginDoesNotPassExternalUrlToIdp()
    {
        $response = $this->get(route('cu-auth.sso-login', ['redirect_url' => 'https://evil.test/']));

        $response->assertRedirect();
        $targetUrl = $response->headers->get('Location');
        $this->assertStringContainsString(ShibIdentityManager::SHIB_LOGIN_URL, $targetUrl);
        $this->assertStringNotContainsString('evil.test', urldecode(urldecode($targetUrl)));
    }
}
