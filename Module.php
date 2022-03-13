<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\Keycloak;

use Aurora\Modules\OAuthIntegratorWebclient\Models\OauthAccount;
use Aurora\Modules\OAuthIntegratorWebclient\Module as OAuthIntegratorWebclientModule;
use Aurora\System\Api;
use Aurora\System\Exceptions\ApiException;
use Aurora\System\Notifications;
use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use GuzzleHttp\Client;

/**
 * Adds ability to login using Keycloak account.
 *
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing Afterlogic Software License
 * @copyright Copyright (c) 2019, Afterlogic Corp.
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractWebclientModule
{
	protected $sService = 'keycloak';

	protected $provider = null;

	protected $aRequireModules = [
		'OAuthIntegratorWebclient'
	];

	/**
	 * Initializes Keycloak Module.
	 *
	 * @ignore
	 */
	public function init()
	{
		session_start();
		$this->subscribeEvent('OAuthIntegratorAction', [$this, 'onOAuthIntegratorAction']);
		$this->subscribeEvent('Core::Logout::before', [$this, 'onBeforeLogout']);
		$this->subscribeEvent('System::RunEntry::before', array($this, 'onBeforeRunEntry'));
	}

	protected function getProvider()
	{
		if (!isset($this->provider)) {
			$sRedirectUrl = \rtrim(\MailSo\Base\Http::SingletonInstance()->GetFullUrl(), '\\/ ').'/?oauth=' . $this->sService;
			if (!\strpos($sRedirectUrl, '://localhost')) {
				$sRedirectUrl = \str_replace('http:', 'https:', $sRedirectUrl);
			}
			$authServerUrl = $this->getConfig('AuthServerUrl');
			$realm = $this->getConfig('Realm');
			$clientId = $this->getConfig('ClientId');
			$clientSecret = $this->getConfig('ClientSecret');;
		
			$this->provider = new Keycloak([
				'authServerUrl'         => $authServerUrl,
				'realm'                 => $realm,
				'clientId'              => $clientId,
				'clientSecret'          => $clientSecret,
				'redirectUri'           => $sRedirectUrl
			]);
		}

		return $this->provider;
	}

	/**
	 * Passes data to connect to service.
	 *
	 * @ignore
	 * @param string $aArgs Service type to verify if data should be passed.
	 * @param boolean|array $mResult variable passed by reference to take the result.
	 */
	public function onOAuthIntegratorAction($aArgs, &$mResult)
	{
		if ($aArgs['Service'] === $this->sService) {

			$oUser = Api::getAuthenticatedUser();
			if (!$oUser) {
			
				$provider = $this->getProvider();
				
				if (!isset($_GET['code'])) {
				
					// If we don't have an authorization code then get one
					$authUrl = $provider->getAuthorizationUrl();
					$_SESSION['oauth2state'] = $provider->getState();
					header('Location: '.$authUrl);
					exit;
				
				// Check given state against previously stored one to mitigate CSRF attack
				} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
				
					unset($_SESSION['oauth2state']);
					throw new ApiException(0, null, 'Invalid state, make sure HTTP sessions are enabled.');
				
				} else {
				
					// Try to get an access token (using the authorization coe grant)
					try {
						$token = $provider->getAccessToken('authorization_code', [
							'code' => $_GET['code']
						]);
					} catch (\Exception $e) {
						throw new ApiException(0, $e, 'Failed to get access token: '.$e->getMessage());
					}
				
					try {
				
						// We got an access token, let's now get the user's details
						$user = $provider->getResourceOwner($token);

						if ($user) {

							$aUser = $user->toArray();
							$sLogin = isset($aUser['preferred_username']) ? $aUser['preferred_username'] : $user->getId();

							$mResult = array(
								'type' => $this->sService,
								'id' => $user->getId(),
								'name' => $user->getName(),
								'email' => $sLogin,
								'access_token' => \json_encode($token->jsonSerialize()),
								'refresh_token' => '',
								'scopes' => ['auth']
							);

							$oAccount = OauthAccount::where('Type', $this->sService)->where('Email', $sLogin)->first();
							if (!isset($oAccount)) {
								$_COOKIE["oauth-redirect"] = "register";
							}
						}
										
					} catch (\Exception $e) {
						throw new ApiException(0, $e, 'Failed to get resource owner: '.$e->getMessage());
					}
				}
			} else {
				\Aurora\System\Api::Location2('./');
			}
	
			return true;
		}
	}

	public function ValidateToken() 
	{
		try {
			$oUser = Api::getAuthenticatedUser();
			if ($oUser) {

				$oAccount = OauthAccount::where('Type', $this->sService)->where('Email', $oUser->PublicId)->first();

				if ($oAccount) {
					$token = new AccessToken(
						\json_decode($oAccount->AccessToken, true)
					);
					if ($token->hasExpired()) {
						$provider = $this->getProvider();
						$token = $provider->getAccessToken('refresh_token', [
							'refresh_token' => $token->getRefreshToken()
						]);

						$oAccount->AccessToken = \json_encode($token->jsonSerialize());
						$oAccount->save();
					}
				} else {
					throw new ApiException(Notifications::AuthError);
				}
			} else {
				throw new ApiException(Notifications::AuthError);
			}
		} catch (\Exception $oEx) {
			Api::LogException($oEx);
			throw new ApiException(Notifications::AuthError);
		}

		return true;
	}

	public function onBeforeLogout()
	{
		$client = new Client([
			'verify' => false,
		]);

		$oUser = Api::getAuthenticatedUser();

		$oAccount = OauthAccount::where('Type', $this->sService)
			->where('Email', $oUser->PublicId)->first();
		if ($oAccount) {
			$accessToken = \json_decode($oAccount->AccessToken);
			if ($accessToken) {
				$client->post(
					$this->getConfig('AuthServerUrl') . '/realms/'. $this->getConfig('Realm') . '/protocol/openid-connect/logout',
					[
						'headers' => [
							'Content-Type' => 'application/x-www-form-urlencoded',
						],
						'form_params' => [
							'client_id' => $this->getConfig('ClientId'),
							'client_secret' => $this->getConfig('ClientSecret'),
							'refresh_token' => $accessToken->refresh_token
						],
						'http_errors' => false
					]
				);
			}
		}
	}

	public function onBeforeRunEntry(&$aArgs, &$mResult)
	{
		$oAuthenticatedUser = \Aurora\System\Api::getAuthenticatedUser();
		if (!$oAuthenticatedUser && isset($aArgs['EntryName']) && strtolower($aArgs['EntryName']) === 'default') {
			\Aurora\System\Api::Location2('./?oauth=' . $this->sService);
		}
	}
}
