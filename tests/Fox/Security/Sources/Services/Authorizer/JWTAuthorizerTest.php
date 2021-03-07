<?php
/*
 * MIT License
 *
 * Copyright (c) 2021 Petr Ploner <petr@ploner.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */

namespace Fox\Security\Sources\Services\Authorizer;

require 'TestingConfig.php';
require 'TestingIdentityProvider.php';
require 'dummyFunctions.php';

use Fox\Core\Http\BadRequestException;
use Fox\Security\Http\UnauthorizedException;
use PHPUnit\Framework\TestCase;


class JWTAuthorizerTest extends TestCase
{
    private \TestingConfig $config;

    protected function setUp(): void
    {
        parent::setUp();
        $this->config = new \TestingConfig();
        $_SERVER['HTTP_CLIENT_IP'] = '10.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'TestingAgent/1.0.0';
    }


    public function testAuthorizeRequestUnauthorized()
    {
        $GLOBALS['headers_empty'] = true;
        $JWTAuthorizer = new JWTAuthorizer();

        $this->expectException(UnauthorizedException::class);
        $JWTAuthorizer->authorizeRequest($this->config);
    }

    public function testAuthorizeRequestOk()
    {
        $GLOBALS['headers_empty'] = false;
        $GLOBALS['token'] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MTUxMDc4MDUsImV4cCI6MzMxNzIwMzM4MDUsInN1YiI6MTIzNCwiZGF0YSI6Ik15M2dKMlZjcm1kMnlSZmJDY014dElyOFBMK2tlNm1jVmJFelVZMWtaejFuTU9Ib1QyOU04U1Q2VEhzS2NYSDlOQXFDR1h1RVl3SUx0MlVvbzE5ejZBPT18XC9vNzNYMno5V1FoSnRoNEI1SWtjbEE9PSIsImlwIjoiMTAuMC4wLjEiLCJ1YSI6IlRlc3RpbmdBZ2VudFwvMS4wLjAifQ.EM0cE9lQhVHY1rCtVxHTC5AxbfEohZIupzHNFnVWQjA"; // Fix before 08/03/3021
        $JWTAuthorizer = new JWTAuthorizer();

        $result = $JWTAuthorizer->authorizeRequest($this->config);
        $this->assertEquals(1234, $result['id']);
        $this->assertEquals("owner@example.com", $result['email']);
        $this->assertEquals("Tester", $result['name']);
    }


    public function testDoAuthorizationEmptyCreds()
    {
        $JWTAuthorizer = new JWTAuthorizer();
        $this->expectException(UnauthorizedException::class);
        $JWTAuthorizer->doAuthorization([], new \TestingIdentityProvider($this->config), $this->config);
    }

    public function testDoAuthorization()
    {
        $JWTAuthorizer = new JWTAuthorizer();
        $res = $JWTAuthorizer->doAuthorization(['username' => 'owner@example.com', 'password' => 'dummyPassword'], new \TestingIdentityProvider($this->config), $this->config);
        $this->assertTrue(is_array($res));
        $this->assertArrayHasKey('accessToken', $res);
        $this->assertArrayHasKey('refreshToken', $res);
        [$header, $payload, $signature] = explode('.', $res['accessToken']);
        $this->assertNotEmpty($header);
        $this->assertNotEmpty($payload);
        $this->assertNotEmpty($signature);
        $payload = json_decode(base64_decode($payload), true);
        $this->assertArrayHasKey('data', $payload);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertEquals(5, $payload['exp'] - $payload['iat']);
        [$header, $payload, $signature] = explode('.', $res['refreshToken']);
        $this->assertNotEmpty($header);
        $this->assertNotEmpty($payload);
        $this->assertNotEmpty($signature);
        $payload = json_decode(base64_decode($payload), true);
        $this->assertTrue(is_array($payload));
        $this->assertEquals($payload['data'], hash('sha256', $res['accessToken']));
        $this->assertEquals(10, $payload['exp'] - $payload['iat']);
        $this->assertEquals(5, $payload['nbf'] - $payload['iat']);
    }

    public function testDoReAuthorizationTooEarly()
    {
        $JWTAuthorizer = new JWTAuthorizer();
        $res = $JWTAuthorizer->doAuthorization(['username' => 'owner@example.com', 'password' => 'dummyPassword'], new \TestingIdentityProvider($this->config), $this->config);
        $this->expectException(BadRequestException::class);
        $JWTAuthorizer->doReAuthorization($res, new \TestingIdentityProvider($this->config), $this->config);
    }

    public function testDoReAuthorization()
    {
        $JWTAuthorizer = new JWTAuthorizer();
        $res = $JWTAuthorizer->doAuthorization(['username' => 'owner@example.com', 'password' => 'dummyPassword'], new \TestingIdentityProvider($this->config), $this->config);
        sleep(5);
        $resReauth = $JWTAuthorizer->doReAuthorization($res, new \TestingIdentityProvider($this->config), $this->config);
        $this->assertTrue(is_array($resReauth));
        $this->assertArrayHasKey('accessToken', $resReauth);
        $this->assertArrayHasKey('refreshToken', $resReauth);
        [$header, $payload, $signature] = explode('.', $resReauth['accessToken']);
        [$headerAuth, $payloadAuth, $signatureAuth] = explode('.', $res['accessToken']);
        [$headerRefreshReAuth, $payloadRefreshReAuth, $signatureRefreshReAuth] = explode('.', $resReauth['refreshToken']);
        $this->assertNotEmpty($header);
        $this->assertNotEmpty($payload);
        $this->assertNotEmpty($signature);
        $payload = json_decode(base64_decode($payload), true);
        $payloadAuth = json_decode(base64_decode($payloadAuth), true);
        $payloadRefreshReAuth = json_decode(base64_decode($payloadRefreshReAuth), true);
        $this->assertArrayHasKey('data', $payload);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertEquals($payloadAuth['data'], $payload['data']);
        $this->assertEquals(hash('sha256', $resReauth['accessToken']), $payloadRefreshReAuth['data']);
    }

    public function testHandles()
    {
        $JWTAuthorizer = new JWTAuthorizer();
        $this->assertEquals("JWT", $JWTAuthorizer->handles());
    }
}
