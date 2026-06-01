<?php

namespace CornellCustomDev\LaravelStarterKit\CUAuth\Tests\Unit;

use CornellCustomDev\LaravelStarterKit\CUAuth\DataObjects\RemoteIdentity;

class RemoteIdentityTest extends UnitTestCase
{
    public function testToArrayReturnsJsonSafePrimitives(): void
    {
        $identity = RemoteIdentity::fromData(
            idp: 'https://shibidp.cit.cornell.edu/idp/shibboleth',
            uid: 'netid',
            eduPersonPrincipalName: 'netid@cornell.edu',
            displayName: 'Test User',
            mail: 'netid_alias@cornell.edu',
            data: ['uid' => 'netid', 'mail' => 'netid_alias@cornell.edu'],
        );

        $array = $identity->toArray();

        $this->assertIsArray($array);
        $this->assertEquals('https://shibidp.cit.cornell.edu/idp/shibboleth', $array['idp']);
        $this->assertEquals('netid', $array['uid']);
        $this->assertEquals('netid@cornell.edu', $array['principalName']);
        $this->assertEquals('Test User', $array['displayName']);
        $this->assertEquals(['uid' => 'netid', 'mail' => 'netid_alias@cornell.edu'], $array['data']);
        // Verify the array is JSON-round-trippable (no PHP objects)
        $this->assertEquals($array, json_decode(json_encode($array), true));
    }

    public function testFromArrayReconstructsIdentity(): void
    {
        $original = RemoteIdentity::fromData(
            idp: 'https://shibidp.cit.cornell.edu/idp/shibboleth',
            uid: 'netid',
            eduPersonPrincipalName: 'netid@cornell.edu',
            displayName: 'Test User',
            mail: 'netid_alias@cornell.edu',
            data: ['uid' => 'netid'],
        );

        $restored = RemoteIdentity::fromArray($original->toArray());

        $this->assertInstanceOf(RemoteIdentity::class, $restored);
        $this->assertEquals($original->id(), $restored->id());
        $this->assertEquals($original->principalName(), $restored->principalName());
        $this->assertEquals($original->name(), $restored->name());
        $this->assertEquals($original->primaryEmail(), $restored->primaryEmail());
        $this->assertEquals($original->emailAlias(), $restored->emailAlias());
        $this->assertEquals($original->isCornellIdP(), $restored->isCornellIdP());
        $this->assertEquals($original->data, $restored->data);
    }

    public function testToArrayIncludesPrivateMailForEmailAlias(): void
    {
        $identity = RemoteIdentity::fromData(
            idp: 'cit.cornell.edu',
            uid: 'netid',
            mail: 'alias@cornell.edu',
        );

        $array = $identity->toArray();
        $restored = RemoteIdentity::fromArray($array);

        $this->assertEquals('alias@cornell.edu', $restored->emailAlias());
    }
}
