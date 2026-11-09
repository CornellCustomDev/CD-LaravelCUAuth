<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\View\Components;

use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\IdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\SamlIdentityManager;
use Exception;
use Illuminate\Contracts\View\View;
use Illuminate\View\Component;

/**
 * <x-cu-auth::idp-selection />: a heading and one sign-in button per configured IdP,
 * for showing the IdP choice in a site's own layout.
 *
 * Renders nothing in single IdP mode (or with apache-shib), since the
 * buttons' entityID links only choose an IdP in discovery or page mode.
 */
class IdpSelection extends Component
{
    /**
     * @param  string|null  $heading  Heading text, or null to leave it out (e.g. when the layout shows it)
     * @param  string|null  $redirectUrl  Where to go after login; defaults to the redirect_url query parameter, then /
     */
    public function __construct(
        public ?string $heading = 'Select Your Cornell Login',
        public ?string $redirectUrl = null,
    ) {}

    public function shouldRender(): bool
    {
        $identityManager = app(IdentityManager::class);

        return $identityManager instanceof SamlIdentityManager
            && $identityManager->selectsIdp();
    }

    /**
     * @throws Exception if any configured IdP is missing a valid settings file
     */
    public function render(): View
    {
        /** @var SamlIdentityManager $identityManager */
        $identityManager = app(IdentityManager::class);
        $redirectUrl = $this->redirectUrl ?? request()->query('redirect_url', '/');

        return view('cu-auth::components.idp-selection', [
            'idps' => $identityManager->idpChoices($redirectUrl),
        ]);
    }
}
