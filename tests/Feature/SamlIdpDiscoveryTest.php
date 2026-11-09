<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature;

use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\IdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Managers\SamlIdentityManager;
use CornellCustomDev\LaravelStarterKit\CUAuth\Saml\IdpDiscovery;
use CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature\Concerns\WritesIdpSettings;
use Exception;
use Illuminate\Support\Facades\File;
use OneLogin\Saml2\Settings;
use PHPUnit\Framework\Attributes\DataProvider;

class SamlIdpDiscoveryTest extends FeatureTestCase
{
    use WritesIdpSettings;

    private const CORNELL_IDP = 'https://cornell.test/idp';

    private const WEILL_IDP = 'https://weill.test/idp';

    protected function setUp(): void
    {
        parent::setUp();

        $this->writeIdpSettings('cornell', self::CORNELL_IDP);
        $this->writeIdpSettings('weill', self::WEILL_IDP);
        config(['cu-auth.idp_selection.mode' => 'discovery']);
        $this->app->singleton(IdentityManager::class, fn () => new SamlIdentityManager);
    }

    public function testIdpSettingsLookup()
    {
        $manager = new SamlIdentityManager;

        $this->assertEquals(self::CORNELL_IDP, $manager->idpSettings(self::CORNELL_IDP)['entityId']);
        $this->assertEquals(self::WEILL_IDP, $manager->idpSettings(self::WEILL_IDP)['entityId']);

        $this->expectExceptionMessage('Unknown identity provider.');
        $manager->idpSettings('https://evil.test/idp');
    }

    public function testSsoUrlIsDiscoveryServiceWithoutEntityId()
    {
        $url = (new SamlIdentityManager)->getSsoUrl('/home');

        $this->assertStringStartsWith('https://idselect-test.idm.cit.cornell.edu/idselect/select.html?', $url);
        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        $this->assertEquals('https://localhost/sso', $query['entityID']);
        $this->assertEquals(route('cu-auth.sso-login', ['redirect_url' => '/home']), $query['return']);
    }

    public function testLoginRedirectsToDiscoveryService()
    {
        $this->get(route('cu-auth.sso-login', ['redirect_url' => '/home']))
            ->assertRedirectContains('https://idselect-test.idm.cit.cornell.edu/idselect/select.html?entityID=');
    }

    public function testInvalidSpSettingsFailBeforeDiscoveryService()
    {
        config(['php-saml-toolkit.sp.entityId' => '']);

        $this->get(route('cu-auth.sso-login', ['redirect_url' => '/home']))
            ->assertServerError();

        $this->expectExceptionMessage('Invalid SAML settings');
        (new SamlIdentityManager)->getDiscoveryUrl('/home');
    }

    #[DataProvider('brokenIdpSettings')]
    public function testBrokenIdpSettingsFailAllDiscoveryLogins(?string $contents)
    {
        $file = config('cu-auth.cert-path').'/idp_weill.json';
        $contents === null ? File::delete($file) : File::put($file, $contents);

        // Fails before the user leaves for the discovery service...
        $this->get(route('cu-auth.sso-login', ['redirect_url' => '/home']))
            ->assertServerError();
        // ...and for an IdP whose own settings are fine.
        $this->get(route('cu-auth.sso-login', ['entityID' => self::CORNELL_IDP]))
            ->assertServerError();

        $this->expectExceptionMessage('Missing or invalid IdP settings for weill');
        (new SamlIdentityManager)->idpSettings(self::CORNELL_IDP);
    }

    public static function brokenIdpSettings(): array
    {
        return [
            'missing' => [null],
            'not JSON' => ['not json'],
            'no entityId' => [json_encode(['singleSignOnService' => ['url' => 'https://weill.test/idp/sso']])],
        ];
    }

    public function testLoginWithEntityIdRedirectsToChosenIdp()
    {
        $this->get(route('cu-auth.sso-login', ['redirect_url' => '/home', 'entityID' => self::WEILL_IDP]))
            ->assertRedirectContains('https://weill.test/idp/sso?SAMLRequest=');

        $this->get(route('cu-auth.sso-login', ['redirect_url' => '/home', 'entityID' => self::CORNELL_IDP]))
            ->assertRedirectContains('https://cornell.test/idp/sso?SAMLRequest=');
    }

    public function testLoginRejectsUnknownIdp()
    {
        $this->get(route('cu-auth.sso-login', ['entityID' => 'https://evil.test/idp']))
            ->assertServerError();
    }

    public function testGetResponseIssuer()
    {
        $settings = new Settings(config('php-saml-toolkit'), true);

        $this->assertEquals(self::WEILL_IDP, IdpDiscovery::getResponseIssuer($settings, self::samlResponse(self::WEILL_IDP)));
        $this->assertEquals(self::CORNELL_IDP, IdpDiscovery::getResponseIssuer($settings, self::samlResponse(null, self::CORNELL_IDP)));
    }

    #[DataProvider('invalidSamlResponses')]
    public function testGetResponseIssuerRejectsInvalidResponses(?string $samlResponse)
    {
        $this->expectException(Exception::class);
        IdpDiscovery::getResponseIssuer(new Settings(config('php-saml-toolkit'), true), $samlResponse);
    }

    public static function invalidSamlResponses(): array
    {
        return [
            'missing' => [null],
            'not base64' => ['not base64!'],
            'DOCTYPE' => [base64_encode('<!DOCTYPE x><x/>')],
            'no assertion issuer' => [self::samlResponse(self::WEILL_IDP, null)],
            'mismatched issuers' => [self::samlResponse(self::WEILL_IDP, self::CORNELL_IDP)],
        ];
    }

    public function testAcsRejectsUnknownIssuer()
    {
        $this->post(route('cu-auth.sso-acs'), ['SAMLResponse' => self::samlResponse('https://evil.test/idp')])
            ->assertForbidden()
            ->assertSee('Unknown identity provider.');
    }

    public function testAcsValidatesAllowedIssuer()
    {
        // Passes the allowlist and is then rejected by SAML validation.
        $this->post(route('cu-auth.sso-acs'), ['SAMLResponse' => self::samlResponse(self::WEILL_IDP)])
            ->assertForbidden()
            ->assertSee('SAML Response Error')
            ->assertDontSee('Unknown identity provider.');
    }

    public function testMetadataIncludesDiscoveryResponse()
    {
        $metadata = (new SamlIdentityManager)->getMetadata();

        $this->assertStringContainsString('idpdisc:DiscoveryResponse', $metadata);
        $this->assertStringContainsString('Location="'.route('cu-auth.sso-login').'"', $metadata);

        config(['cu-auth.idp_selection.mode' => 'single']);
        $this->assertStringNotContainsString('DiscoveryResponse', (new SamlIdentityManager)->getMetadata());
    }

    public function testDiscoveryMetadataRejectsSignedMetadata()
    {
        config(['php-saml-toolkit.security.signMetadata' => true]);

        $this->expectExceptionMessage('signMetadata is not supported with IdP discovery.');
        (new SamlIdentityManager)->getMetadata();
    }

    /**
     * A minimal, unsigned SAML Response; the assertion issuer defaults to the response issuer.
     */
    private static function samlResponse(?string $responseIssuer, ?string $assertionIssuer = 'same'): string
    {
        $assertionIssuer = $assertionIssuer === 'same' ? $responseIssuer : $assertionIssuer;
        $issuerXml = fn (?string $issuer) => $issuer === null ? '' : '<saml:Issuer>'.htmlspecialchars($issuer).'</saml:Issuer>';

        return base64_encode(
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            .'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            .$issuerXml($responseIssuer)
            .'<saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            .$issuerXml($assertionIssuer)
            .'</saml:Assertion></samlp:Response>'
        );
    }
}
