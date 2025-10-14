<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests;

use CornellCustomDev\LaravelStarterKit\CUAuth\CUAuthServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

class TestCase extends OrchestraTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // additional setup
    }

    protected function getPackageProviders($app): array
    {
        return [
            CUAuthServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // perform environment setup
    }
}
