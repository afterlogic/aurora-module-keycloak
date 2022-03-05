'use strict';

const
	App = require('%PathToCoreWebclientModule%/js/App.js'),
	Ajax = require('%PathToCoreWebclientModule%/js/Ajax.js')
;

module.exports = function (appData) {
	if (App.isUserNormalOrTenant()) {

		return {
			start: (ModulesManager) => {
				Ajax.send('%ModuleName%', 'ValidateToken');
			}
		};
	}

	return null;
};
