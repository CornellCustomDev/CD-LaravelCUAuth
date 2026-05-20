<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature;

use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\ShibIdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Middleware\LivewireAuth;
use Illuminate\Http\Request;

class LivewireAuthTest extends FeatureTestCase
{
    private function getLivewireUpdateRequest(): Request
    {
        $request = Request::create('/livewire/update', 'POST');
        $request->setLaravelSession(app('session.store'));

        return $request;
    }

    public function testAllowsRequestWithRemoteIdentity()
    {
        $identityManager = $this->createStub(ShibIdentityManager::class);
        $identityManager->method('hasRemoteIdentity')->willReturn(true);

        $response = (new LivewireAuth($identityManager))
            ->handle($this->getLivewireUpdateRequest(), fn () => response('OK'));

        $this->assertTrue($response->isOk());
    }

    public function testBlocksRequestWithNoIdentity()
    {
        $identityManager = $this->createStub(ShibIdentityManager::class);
        $identityManager->method('hasRemoteIdentity')->willReturn(false);

        $response = (new LivewireAuth($identityManager))
            ->handle($this->getLivewireUpdateRequest(), fn () => response('OK'));

        $this->assertTrue($response->isForbidden());
    }

    public function testAllowsLocallyAuthenticatedUserWhenLocalLoginEnabled()
    {
        config(['cu-auth.allow_local_login' => true]);
        $identityManager = $this->createStub(ShibIdentityManager::class);
        $identityManager->method('hasRemoteIdentity')->willReturn(false);
        auth()->login($this->getTestUser());

        $response = (new LivewireAuth($identityManager))
            ->handle($this->getLivewireUpdateRequest(), fn () => response('OK'));

        $this->assertTrue($response->isOk());
    }

    public function testBlocksLocallyAuthenticatedUserWhenLocalLoginDisabled()
    {
        config(['cu-auth.allow_local_login' => false]);
        $identityManager = $this->createStub(ShibIdentityManager::class);
        $identityManager->method('hasRemoteIdentity')->willReturn(false);
        auth()->login($this->getTestUser());

        $response = (new LivewireAuth($identityManager))
            ->handle($this->getLivewireUpdateRequest(), fn () => response('OK'));

        $this->assertTrue($response->isForbidden());
    }

    public function testAllowsNonLivewireRoute()
    {
        $identityManager = $this->createStub(ShibIdentityManager::class);
        $identityManager->method('hasRemoteIdentity')->willReturn(false);
        $request = Request::create('/some/other/route', 'POST');
        $request->setLaravelSession(app('session.store'));

        $response = (new LivewireAuth($identityManager))
            ->handle($request, fn () => response('OK'));

        $this->assertTrue($response->isOk());
    }
}
