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


use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Fox\Core\Helpers\Encryptor;
use Fox\Core\Helpers\Globals;
use Fox\Core\Helpers\Server;
use Fox\Core\Http\BadRequestException;
use Fox\Security\Config\FoxSecurityExtensionConfigInterface;
use Fox\Security\Http\UnauthorizedException;
use Fox\Security\Sources\Services\IdentityProviderInterface;

class JWTAuthorizer implements Authorizer
{
    const HS_256 = 'HS256';

    public function authorizeRequest(FoxSecurityExtensionConfigInterface $foxSecurityExtensionConfig): array
    {
        $authHeader = Globals::getAllHeaders()['Authorization'] ?? null;
        if (empty($authHeader)) {
            throw new UnauthorizedException();
        }

        try {
            $jwt = (array)JWT::decode(substr($authHeader, 7), $foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), [self::HS_256]);
            if ($foxSecurityExtensionConfig->foxSecurityRestrictJWTForIp()) {
                $ip = Server::getIp();
                if ($ip === null || $jwt['ip'] !== $ip) {
                    throw new UnauthorizedException();
                }
            }

            if ($foxSecurityExtensionConfig->foxSecurityRestrictJWTForUA()) {
                $ua = Server::get('HTTP_USER_AGENT');
                if ($ua === null || $jwt['ua'] !== $ua) {
                    throw new UnauthorizedException();
                }
            }

            return json_decode(Encryptor::decrypt($foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), $jwt['data']), true);
        } catch (ExpiredException | BeforeValidException $e) {
            throw new UnauthorizedException();
        }
    }

    public function handles(): string
    {
        return FoxSecurityExtensionConfigInterface::JWT_AUTH_HANDLER;
    }

    public function doAuthorization(array $credentials,
                                    IdentityProviderInterface $identityProvider,
                                    FoxSecurityExtensionConfigInterface $foxSecurityExtensionConfig): mixed
    {
        $identity = $identityProvider->verifyCredentials($credentials);
        if ($identity === null) {
            throw new UnauthorizedException();
        }

        $identityData = (array)$identity;
        $data = [
            'iat' => time(),
            'exp' => time() + $foxSecurityExtensionConfig->foxSecurityGetTokenValidityInSeconds(),
            'sub' => $identity->getIdentificator(),
            'data' => Encryptor::encrypt($foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), json_encode($identityData))
        ];

        if ($foxSecurityExtensionConfig->foxSecurityRestrictJWTForIp()) {
            $data['ip'] = Server::getIp();
        }

        if ($foxSecurityExtensionConfig->foxSecurityRestrictJWTForUA()) {
            $data['ua'] = Server::get('HTTP_USER_AGENT');
        }

        $access = JWT::encode($data, $foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), self::HS_256);
        $refreshData = $this->getRefreshTokenData($foxSecurityExtensionConfig->foxSecurityGetTokenValidityInSeconds(), $identity->getIdentificator(), $foxSecurityExtensionConfig->foxSecurityGetRefreshTokenValidityInSeconds(), $access);
        $refresh = JWT::encode($refreshData, $foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), self::HS_256);

        return [
            'accessToken' => $access,
            'refreshToken' => $refresh
        ];
    }

    public function doReAuthorization(array $credentials,
                                      IdentityProviderInterface $identityProvider,
                                      FoxSecurityExtensionConfigInterface $foxSecurityExtensionConfig): mixed
    {
        $accessToken = $credentials['accessToken'];
        $refreshToken = $credentials['refreshToken'];

        if (empty($accessToken) || empty($refreshToken)) {
            throw new BadRequestException("Missing credentials");
        }

        try {
            $jwt = (array)JWT::decode($refreshToken, $foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), [self::HS_256]);
            $hash = hash("sha256", $accessToken);

            if ($hash !== $jwt['data']) {
                throw new UnauthorizedException();
            }

            list($header, $payload, $signature) = explode('.', $accessToken);
            $payload = json_decode(base64_decode($payload), true);

            if (!is_array($payload) || $payload['sub'] !== $jwt['sub']) {
                throw new UnauthorizedException();
            }

            $payload['iat'] = time();
            $payload['exp'] = time() + $foxSecurityExtensionConfig->foxSecurityGetTokenValidityInSeconds();
            $newJWT = JWT::encode($payload, $foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), self::HS_256);

            $refreshData = $this->getRefreshTokenData($foxSecurityExtensionConfig->foxSecurityGetTokenValidityInSeconds(), $payload['sub'], $foxSecurityExtensionConfig->foxSecurityGetRefreshTokenValidityInSeconds(), $newJWT);
            $newRefresh = JWT::encode($refreshData, $foxSecurityExtensionConfig->foxSecurityGetJWTSecret(), self::HS_256);

            return [
                'accessToken' => $newJWT,
                'refreshToken' => $newRefresh
            ];

        } catch (BeforeValidException $e) {
            throw new BadRequestException("Can not refresh valid token!");
        } catch (ExpiredException $e) {
            throw new UnauthorizedException();
        }
    }


    private function getRefreshTokenData(int $tokenValidity, string|int $id, int $refreshTokenValidity, string $access): array
    {
        return [
            'iat' => time(),
            'exp' => time() + $refreshTokenValidity,
            'sub' => $id,
            'nbf' => time() + $tokenValidity,
            'data' => hash('sha256', $access)
        ];
    }
}