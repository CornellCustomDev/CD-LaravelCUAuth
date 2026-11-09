<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature;

use CornellCustomDev\LaravelStarterKit\CUAuth\CUAuthServiceProvider;
use CornellCustomDev\LaravelStarterKit\CUAuth\Tests\TestCase;
use Illuminate\Support\Facades\File;

class InstallCUAuthTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->resetInstallFiles();
    }

    protected function tearDown(): void
    {
        // Published views would override the package views in later tests.
        File::deleteDirectory($this->applicationBasePath().'/resources/views/vendor/cu-auth');
        parent::tearDown();
    }

    public function testCanInstallCUAuthConfigFiles()
    {
        $basePath = $this->applicationBasePath();
        $defaultVariable = 'REMOTE_USER';
        $testVariable = 'REDIRECT_REMOTE_USER';
        // Make sure we have config values
        $this->refreshApplication();

        $userVariable = config('cu-auth.apache_shib_user_variable');
        $this->assertEquals($defaultVariable, $userVariable);

        $this->artisan(
            command: 'vendor:publish',
            parameters: [
                '--tag' => 'starterkit:'.CUAuthServiceProvider::INSTALL_CONFIG_TAG,
                '--force' => true,
            ])
            ->assertSuccessful();

        // Update the config file with a test value for cu-auth.apache_shib_user_variable.
        File::put("$basePath/config/cu-auth.php", str_replace(
            "'$defaultVariable'",
            "'$testVariable'",
            File::get("$basePath/config/cu-auth.php")
        ));
        $this->refreshApplication();

        $userVariable = config('cu-auth.apache_shib_user_variable');
        $this->assertEquals($testVariable, $userVariable);
    }

    public function testCanInstallPhpSamlConfigFiles()
    {
        $basePath = $this->applicationBasePath();
        $defaultVariable = 'https://localhost';
        $testVariable = 'https://test.example.com';
        // Make sure we have config values
        $this->refreshApplication();

        $entityId = config('php-saml-toolkit.sp.entityId');
        $this->assertEquals($defaultVariable.'/sso', $entityId);

        $this->artisan(
            command: 'vendor:publish',
            parameters: [
                '--tag' => 'starterkit:'.CUAuthServiceProvider::INSTALL_PHP_SAML_TAG,
                '--force' => true,
            ])
            ->assertSuccessful();

        // Update the config file with a test value for php-saml-tookkit.sp.entityId.
        File::put("$basePath/config/php-saml-toolkit.php", str_replace(
            "'$defaultVariable'",
            "'$testVariable'",
            File::get("$basePath/config/php-saml-toolkit.php")
        ));
        $this->refreshApplication();

        $entityId = config('php-saml-toolkit.sp.entityId');
        $this->assertEquals($testVariable.'/sso', $entityId);
    }

    public function testCanInstallSamlCerts()
    {
        $basePath = $this->applicationBasePath();
        $idpCertPath = "$basePath/storage/app/keys/idp_cert.pem";
        $spKeyPath = "$basePath/storage/app/keys/sp_key.pem";
        $spCertPath = "$basePath/storage/app/keys/sp_cert.pem";
        $this->assertFileDoesNotExist($idpCertPath);
        $this->assertFileDoesNotExist($spKeyPath);
        $this->assertFileDoesNotExist($spCertPath);

        $this->artisan('cu-auth:generate-keys')
            ->assertSuccessful();

        $this->assertFileExists($idpCertPath);
        $this->assertStringContainsString('test-cornell-idp-cert-contents', File::get($idpCertPath));

        $this->assertFileExists($spKeyPath);
        $keyFile = File::get($spKeyPath);
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyFile);
        $this->assertStringContainsString('-----END PRIVATE KEY-----', $keyFile);

        $this->assertFileExists($spCertPath);
        $certFile = File::get($spCertPath);
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $certFile);
        $this->assertStringContainsString('-----END CERTIFICATE-----', $certFile);

        // Confirm we can get the certs via the config
        config(['php-saml-toolkit.idp.x509cert' => File::get("$basePath/storage/app/keys/idp_cert.pem")]);
        $this->assertStringContainsString('test-cornell-idp-cert-contents', config('php-saml-toolkit.idp.x509cert'));
    }

    public function testCanInstallWeillSamlCerts()
    {
        $basePath = $this->applicationBasePath();
        $idpCertPath = "$basePath/storage/app/keys/idp_cert.pem";
        $spKeyPath = "$basePath/storage/app/keys/sp_key.pem";
        $spCertPath = "$basePath/storage/app/keys/sp_cert.pem";
        $this->assertFileDoesNotExist($idpCertPath);
        $this->assertFileDoesNotExist($spKeyPath);
        $this->assertFileDoesNotExist($spCertPath);

        $this->artisan('cu-auth:generate-keys', ['--weill' => true])
            ->assertSuccessful();

        $this->assertFileExists($idpCertPath);
        $this->assertStringContainsString('test-weill-idp-cert-contents', File::get($idpCertPath));

        $this->assertFileExists($spKeyPath);
        $keyFile = File::get($spKeyPath);
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyFile);
        $this->assertStringContainsString('-----END PRIVATE KEY-----', $keyFile);

        $this->assertFileExists($spCertPath);
        $certFile = File::get($spCertPath);
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $certFile);
        $this->assertStringContainsString('-----END CERTIFICATE-----', $certFile);

        // Confirm we can get the certs via the config
        config(['php-saml-toolkit.idp.x509cert' => File::get("$basePath/storage/app/keys/idp_cert.pem")]);
        $this->assertStringContainsString('test-weill-idp-cert-contents', config('php-saml-toolkit.idp.x509cert'));
    }

    public function testCanInstallDiscoveryIdpSettings()
    {
        $basePath = $this->applicationBasePath();
        $cornellSettingsPath = "$basePath/storage/app/keys/idp_cornell.json";
        $weillSettingsPath = "$basePath/storage/app/keys/idp_weill.json";
        $idpCertPath = "$basePath/storage/app/keys/idp_cert.pem";
        $this->assertFileDoesNotExist($cornellSettingsPath);
        $this->assertFileDoesNotExist($weillSettingsPath);

        config(['cu-auth.idp_selection.mode' => 'discovery']);
        $this->artisan('cu-auth:generate-keys')
            ->assertSuccessful();

        $this->assertFileExists($cornellSettingsPath);
        $this->assertStringContainsString('test-cornell-idp-cert-contents', File::get($cornellSettingsPath));

        $this->assertFileExists($weillSettingsPath);
        $this->assertStringContainsString('test-weill-idp-cert-contents', File::get($weillSettingsPath));

        // The single-IdP cert is not used with discovery
        $this->assertFileDoesNotExist($idpCertPath);
    }

    public function testCanInstallDiscoveryIdpSettingsWhenSpKeysAreRequired()
    {
        $basePath = $this->applicationBasePath();
        $spKeyPath = "$basePath/storage/app/keys/sp_key.pem";
        $this->assertFileDoesNotExist($spKeyPath);

        // A fresh install whose SP config requires keys that do not exist yet
        config([
            'cu-auth.idp_selection.mode' => 'discovery',
            'php-saml-toolkit.security.authnRequestsSigned' => true,
            'php-saml-toolkit.sp.x509cert' => '',
            'php-saml-toolkit.sp.privateKey' => '',
        ]);
        $this->artisan('cu-auth:generate-keys')
            ->assertSuccessful();

        $this->assertFileExists("$basePath/storage/app/keys/idp_cornell.json");
        $this->assertFileExists($spKeyPath);
    }

    public function testCanPublishViews()
    {
        $viewPath = $this->applicationBasePath().'/resources/views/vendor/cu-auth';

        $this->artisan(
            command: 'vendor:publish',
            parameters: [
                '--tag' => 'starterkit:'.CUAuthServiceProvider::INSTALL_VIEWS_TAG,
                '--force' => true,
            ])
            ->assertSuccessful();

        $this->assertFileExists("$viewPath/select.blade.php");
        $this->assertFileExists("$viewPath/components/idp-selection.blade.php");
    }

    private function resetInstallFiles(): void
    {
        $basePath = $this->applicationBasePath();

        // Delete files from previous tests
        File::delete("$basePath/config/cu-auth.php");
        File::delete("$basePath/config/php-saml-toolkit.php");
        File::deleteDirectory("$basePath/storage/app/keys");
        File::deleteDirectory("$basePath/resources/views/vendor/cu-auth");
    }
}
