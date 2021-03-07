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

use Fox\Security\Sources\Services\Identity;
use Fox\Security\Sources\Services\IdentityProvider;
use Fox\Security\Sources\Services\IdentityProviderInterface;

class TestingIdentityProvider extends IdentityProvider implements IdentityProviderInterface
{

    public function createIdentity(array $authorizerData): Identity
    {
        return new TestingIdentity();
    }

    public function verifyCredentials(array $credentials): ?Identity
    {
        $user = $credentials['username'] ?? null;
        $password = $credentials['password'] ?? null;

        if ($user === 'owner@example.com' && $password === 'dummyPassword') {
            return new TestingIdentity();
        }

        return null;
    }
}

class TestingIdentity implements Identity
{
    public int $id = 1234;
    public string $email = "owner@example.com";
    public string $name = "Tester";

    public function getIdentificator(): string|int
    {
        return $this->id;
    }

    public function getRoles(): array
    {
        return ['betterTester'];
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function getName(): string
    {
        return $this->name;
    }
}