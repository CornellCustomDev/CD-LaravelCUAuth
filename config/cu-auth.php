<?php

$is_production = env('APP_ENV') == 'production';

return [
    /*
    |--------------------------------------------------------------------------
    | Identity Manager
    |--------------------------------------------------------------------------
    |
    | The identity manager to use for user authentication. Options are:
    | - apache-shib: Apache mod_shib
    | - php-saml: OneLogin SAML PHP Toolkit
    |
    */
    'identity_manager' => env('CU_AUTH_IDENTITY_MANAGER', 'apache-shib'),

    /*
    |--------------------------------------------------------------------------
    | Require Local User
    |--------------------------------------------------------------------------
    |
    | Require a local user account in the application for the authenticated
    | remote user. This setting controls the CUAuthenticated event to handle
    | user login.
    |
    */
    'require_local_user' => env('REQUIRE_LOCAL_USER', false),

    /*
    |--------------------------------------------------------------------------
    | ApacheShib Configuration
    |--------------------------------------------------------------------------
    |
    | ApacheShib retrieves user data from server variables populated by the
    | Apache shibboleth module (mod_shib).
    |
    | The default user variable is "REMOTE_USER", but this may differ depending
    | on how mod_shib is configured.
    |
    | For local development without shibboleth, you can add
    | REMOTE_USER=<netid> to your project .env file to log in as that user.
    |
    */
    'apache_shib_user_variable' => env('APACHE_SHIB_USER_VARIABLE', 'REMOTE_USER'),
    'remote_user_override' => env('REMOTE_USER'),

    /*
    |--------------------------------------------------------------------------
    | PHP-SAML Configuration
    |--------------------------------------------------------------------------
    |
    | Note: Configuration for the OneLogin SAML PHP Toolkit can be found
    | in config/php-saml-toolkit.php.
    |
    | The default path of storage/app/keys is ignored by git in a standard
    | Laravel installation, so typically this does not need to be changed.
    |
    */
    'cert-path' => storage_path(env('SAML_CERT_PATH', 'app/keys')),

    /*
    |--------------------------------------------------------------------------
    | PHP-SAML IdP Metadata URLs
    |--------------------------------------------------------------------------
    |
    | Metadata for the Cornell IdPs, used by `php artisan cu-auth:generate-keys`
    | to retrieve IdP settings and certificates. Defaults to the production or
    | test IdP based on APP_ENV.
    |
    */
    'idp_metadata_urls' => [
        'cornell' => env('SAML_METADATA_URL_CORNELL', $is_production
            ? 'https://shibidp.cit.cornell.edu/idp/shibboleth'
            : 'https://shibidp-test.cit.cornell.edu/idp/shibboleth'),
        'weill' => env('SAML_METADATA_URL_WEILL', $is_production
            ? 'https://login.weill.cornell.edu/idp/saml2/idp/metadata.php'
            : 'https://login-test.weill.cornell.edu/idp/saml2/idp/metadata.php'),
    ],

    /*
    |--------------------------------------------------------------------------
    | PHP-SAML IdP Discovery
    |--------------------------------------------------------------------------
    |
    | When enabled, users are sent to a SAML discovery service (CIT idselect)
    | to choose an IdP, and the 'idp' settings in config/php-saml-toolkit.php
    | are replaced by the chosen IdP's settings. Logins may also skip the
    | discovery service by linking to /sso/login?entityID=<IdP entityID>.
    |
    | 'idps' lists keys of 'idp_metadata_urls' above. Each IdP's settings
    | (entityId, SSO URL, certs) are read from idp_<key>.json in the cert path,
    | which `php artisan cu-auth:generate-keys` creates when discovery is enabled.
    | Only these IdPs are allowed, and each must have a valid settings file.
    |
    */
    'idp_discovery' => [
        'enabled' => boolval(env('SAML_IDP_DISCOVERY', false)),

        'url' => env('SAML_IDP_DISCOVERY_URL', $is_production
            ? 'https://idselect.idm.cit.cornell.edu/idselect/select.html'
            : 'https://idselect-test.idm.cit.cornell.edu/idselect/select.html'),

        'idps' => ['cornell', 'weill'],
    ],

    /*
    |--------------------------------------------------------------------------
    | AppTesters Configuration
    |--------------------------------------------------------------------------
    |
    | Comma-separated list of users to allow in development environments.
    | APP_TESTERS_FIELD is the field on the user model to compare against.
    |
    */
    'app_testers' => env('APP_TESTERS', ''),
    'app_testers_field' => env('APP_TESTERS_FIELD', 'netid'),

    /*
    |--------------------------------------------------------------------------
    | Allow Local Login
    |--------------------------------------------------------------------------
    |
    | Allow Laravel password-based login? Typically, this would only be used
    | for local or automated testing.
    |
    */
    'allow_local_login' => boolval(env('ALLOW_LOCAL_LOGIN', false)),

    /*
    |--------------------------------------------------------------------------
    | Restrict Access for Livewire Updates
    |--------------------------------------------------------------------------
    |
    | Add global middleware protection against unauthenticated posting to
    | /livewire/update.
    |
    */
    'require_livewire_auth' => boolval(env('REQUIRE_LIVEWIRE_AUTH', false)),
];
