<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Feature\Concerns;

use Illuminate\Support\Facades\File;

trait WritesIdpSettings
{
    /**
     * Write IdP settings in the shape SamlIdentityManager reads from idp_<key>.json.
     */
    protected function writeIdpSettings(string $key, string $entityId): void
    {
        $certPath = config('cu-auth.cert-path');
        File::ensureDirectoryExists($certPath);
        File::put("$certPath/idp_$key.json", json_encode([
            'entityId' => $entityId,
            'singleSignOnService' => ['url' => "$entityId/sso"],
            'x509cert' => "test-$key-idp-cert-contents",
        ]));
    }
}
