<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature;

use CornellCustomDev\LaravelStarterKit\CUAuth\DataObjects\RemoteIdentity;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\IdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\SamlIdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\ShibIdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature\Concerns\WritesIdpSettings;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\View;
use PHPUnit\Framework\Attributes\DataProvider;

class SamlIdpSelectionPageTest extends FeatureTestCase
{
    use WritesIdpSettings;

    private const CORNELL_IDP = 'https://cornell.test/idp';

    private const WEILL_IDP = 'https://weill.test/idp';

    protected function setUp(): void
    {
        parent::setUp();

        $this->writeIdpSettings('cornell', self::CORNELL_IDP);
        $this->writeIdpSettings('weill', self::WEILL_IDP);
        config(['cu-auth.idp_selection_mode' => 'page']);
        $this->app->singleton(IdentityManager::class, fn () => new SamlIdentityManager);
    }

    public function testLoginRedirectsToSelectionPage()
    {
        $this->get(route('cu-auth.sso-login', ['redirect_url' => '/home']))
            ->assertRedirect(route('cu-auth.sso-select', ['redirect_url' => 'https://localhost/home']));
    }

    public function testInvalidSpSettingsFailBeforeSelectionPage()
    {
        config(['php-saml-toolkit.sp.entityId' => '']);

        $this->get(route('cu-auth.sso-login', ['redirect_url' => '/home']))
            ->assertServerError();
    }

    #[DataProvider('singleModes')]
    public function testSingleModeIsTheDefault(?string $mode)
    {
        config(['cu-auth.idp_selection_mode' => $mode]);
        $manager = new SamlIdentityManager;

        $this->assertSame(SamlIdentityManager::IDP_SELECTION_SINGLE, $manager->idpSelectionMode());
        $this->assertFalse($manager->selectsIdp());
        // The single IdP from config/php-saml-toolkit.php, not the selection page.
        $this->assertStringStartsWith(config('php-saml-toolkit.idp.singleSignOnService.url').'?SAMLRequest=', $manager->getSsoUrl('/home'));
    }

    public static function singleModes(): array
    {
        return [
            'single' => ['single'],
            'unset' => [null],
            'blank' => [''],
        ];
    }

    #[DataProvider('invalidModes')]
    public function testInvalidModeFails(mixed $mode)
    {
        config(['cu-auth.idp_selection_mode' => $mode]);

        $this->get(route('cu-auth.sso-login'))
            ->assertServerError();

        $this->expectExceptionMessage('Invalid IdP selection mode.');
        (new SamlIdentityManager)->idpSelectionMode();
    }

    public static function invalidModes(): array
    {
        return [
            'typo' => ['pages'],
            // SAML_IDP_SELECTION=false is read as boolean false, which is not a mode.
            'false' => [false],
            'zero' => [0],
            'zero string' => ['0'],
        ];
    }

    public function testSelectionPageLinksToEachIdp()
    {
        $this->get(route('cu-auth.sso-select', ['redirect_url' => '/home']))
            ->assertOk()
            ->assertSee('Select Your Cornell Login')
            ->assertSeeInOrder(['Cornell NetID', 'Weill Cornell Medicine (CWID)'])
            ->assertSee(route('cu-auth.sso-login', ['entityID' => self::CORNELL_IDP, 'redirect_url' => 'https://localhost/home']))
            ->assertSee(route('cu-auth.sso-login', ['entityID' => self::WEILL_IDP, 'redirect_url' => 'https://localhost/home']))
            ->assertSee('https://netid.cornell.edu/')
            ->assertSee('More information about WCM CWID');
    }

    public function testSelectionPageUsesConfiguredIdps()
    {
        config(['cu-auth.idp_selection.idps' => [
            'weill' => ['label' => 'Weill only'],
        ]]);

        $this->get(route('cu-auth.sso-select'))
            ->assertOk()
            ->assertSee('Weill only')
            ->assertSee(route('cu-auth.sso-login', ['entityID' => self::WEILL_IDP, 'redirect_url' => 'https://localhost']))
            ->assertDontSee('Cornell NetID')
            ->assertDontSee('More information');
    }

    public function testSelectionLinkLogsInWithChosenIdp()
    {
        $this->get(route('cu-auth.sso-login', ['entityID' => self::WEILL_IDP, 'redirect_url' => '/home']))
            ->assertRedirectContains('https://weill.test/idp/sso?SAMLRequest=');
    }

    public function testSelectionPageRedirectsWhenAlreadyLoggedIn()
    {
        $this->withSession(['remoteIdentity' => RemoteIdentity::fromData(idp: 'cit.cornell.edu', uid: 'abc123')])
            ->get(route('cu-auth.sso-select', ['redirect_url' => '/home']))
            ->assertRedirect('https://localhost/home');
    }

    public function testSelectionPageRejectsExternalRedirectUrl()
    {
        $this->get(route('cu-auth.sso-select', ['redirect_url' => 'https://evil.example.com/']))
            ->assertOk()
            ->assertSee(route('cu-auth.sso-login', ['entityID' => self::CORNELL_IDP, 'redirect_url' => 'https://localhost']))
            ->assertDontSee('evil.example.com');
    }

    public function testBrokenIdpSettingsFailSelectionPage()
    {
        File::delete(config('cu-auth.cert-path').'/idp_weill.json');

        $this->get(route('cu-auth.sso-select'))
            ->assertServerError();
    }

    #[DataProvider('otherModes')]
    public function testSelectionPageNotFoundOutsidePageMode(?string $mode)
    {
        config(['cu-auth.idp_selection_mode' => $mode]);

        $this->get(route('cu-auth.sso-select'))
            ->assertNotFound();
    }

    public static function otherModes(): array
    {
        return [
            'single' => ['single'],
            'unset' => [null],
            'discovery' => ['discovery'],
        ];
    }

    public function testSelectionPageNotFoundForApacheShib()
    {
        $this->app->singleton(IdentityManager::class, fn () => new ShibIdentityManager);

        $this->get(route('cu-auth.sso-select'))
            ->assertNotFound();
    }

    public function testSelectionPageCanUseAppView()
    {
        View::addLocation(__DIR__.'/views');
        config(['cu-auth.idp_selection.view' => 'app-select']);

        $this->get(route('cu-auth.sso-select', ['redirect_url' => '/home']))
            ->assertOk()
            ->assertSee('<div id="app-layout">', false)
            ->assertSee('Choose how to sign in')
            ->assertSee(route('cu-auth.sso-login', ['entityID' => self::CORNELL_IDP, 'redirect_url' => '/home']));
    }

    public function testAcsChoosesIdpFromIssuer()
    {
        $samlResponse = base64_encode(
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            .'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            .'<saml:Issuer>https://evil.test/idp</saml:Issuer>'
            .'<saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            .'<saml:Issuer>https://evil.test/idp</saml:Issuer>'
            .'</saml:Assertion></samlp:Response>'
        );

        $this->post(route('cu-auth.sso-acs'), ['SAMLResponse' => $samlResponse])
            ->assertForbidden()
            ->assertSee('Unknown identity provider.');
    }

    public function testMetadataHasNoDiscoveryResponse()
    {
        $this->assertStringNotContainsString('DiscoveryResponse', (new SamlIdentityManager)->getMetadata());
    }

    public function testComponentRendersHeadingAndLinks()
    {
        $this->blade('<x-cu-auth::idp-selection redirect-url="/home" class="my-login" />')
            ->assertSee('<section class="cu-auth-idp-selection my-login">', false)
            ->assertSee('<h2 class="cu-auth-idp-heading">Select Your Cornell Login</h2>', false)
            ->assertSee(route('cu-auth.sso-login', ['entityID' => self::CORNELL_IDP, 'redirect_url' => '/home']));
    }

    public function testComponentHeadingCanBeChangedOrLeftOut()
    {
        $this->blade('<x-cu-auth::idp-selection heading="Sign in" />')
            ->assertSee('>Sign in</h2>', false);

        $this->blade('<x-cu-auth::idp-selection :heading="null" />')
            ->assertDontSee('<h2', false)
            ->assertSee('Cornell NetID');
    }

    public function testComponentWorksInDiscoveryMode()
    {
        config(['cu-auth.idp_selection_mode' => 'discovery']);

        $this->blade('<x-cu-auth::idp-selection />')
            ->assertSee(route('cu-auth.sso-login', ['entityID' => self::WEILL_IDP, 'redirect_url' => '/']));
    }

    public function testComponentRendersNothingInSingleMode()
    {
        config(['cu-auth.idp_selection_mode' => 'single']);
        $this->assertSame('', trim((string) $this->blade('<x-cu-auth::idp-selection />')));

        config(['cu-auth.idp_selection_mode' => 'page']);
        $this->app->singleton(IdentityManager::class, fn () => new ShibIdentityManager);
        $this->assertSame('', trim((string) $this->blade('<x-cu-auth::idp-selection />')));
    }

    public function testComponentStylesRenderOnce()
    {
        $html = (string) $this->blade('<x-cu-auth::idp-selection /><x-cu-auth::idp-selection />');

        $this->assertSame(1, substr_count($html, '<style>'));
        $this->assertSame(2, substr_count($html, 'class="cu-auth-idp-selection"'));
    }
}
