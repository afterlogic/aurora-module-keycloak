<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\Keycloak;

use Aurora\System\SettingsProperty;

/**
 * @property bool $Disabled"
 * @property string $AuthServerUrl"
 * @property string $Realm"
 * @property string $ClientId"
 * @property string $clientSecret"
 */

class Settings extends \Aurora\System\Module\Settings
{
    protected function initDefaults()
    {
        $this->aContainer = [
            "Disabled" => new SettingsProperty(
                false,
                "bool",
                null,
                ""
            ),
            "AuthServerUrl" => new SettingsProperty(
                "",
                "string",
                null,
                ""
            ),
            "Realm" => new SettingsProperty(
                "",
                "string",
                null,
                ""
            ),
            "ClientId" => new SettingsProperty(
                "",
                "string",
                null,
                ""
            ),
            "clientSecret" => new SettingsProperty(
                "",
                "string",
                null,
                ""
            ),
        ];
    }
}
