/*! semantic ui integration for DataTables' SearchBuilder
 * © SpryMedia Ltd - datatables.net/license
 */

(function( factory ){
	if ( typeof define === 'function' && define.amd ) {
		// AMD
		define( ['jquery', 'datatables.net-se', 'datatables.net-searchbuilder'], function ( $ ) {
			return factory( $, window, document );
		} );
	}
	else if ( typeof exports === 'object' ) {
		// CommonJS
		var jq = require('jquery');
		var cjsRequires = function (root, $) {
			if ( ! $.fn.dataTable ) {
				require('datatables.net-se')(root, $);
			}

			if ( ! $.fn.dataTable.SearchBuilder ) {
				require('datatables.net-searchbuilder')(root, $);
			}
		};

		if (typeof window !== 'undefined') {
			module.exports = function (root, $) {
				if ( ! root ) {
					// CommonJS environments without a window global must pass a
					// root. This will give an error otherwise
					root = window;
				}

				if ( ! $ ) {
					$ = jq( root );
				}

				cjsRequires( root, $ );
				return factory( $, root, root.document );
			};
		}
		else {
			cjsRequires( window, jq );
			module.exports = factory( jq, window, window.document );
		}
	}
	else {
		// Browser
		factory( jQuery, window, document );
	}
}(function( $, window, document, undefined ) {
'use strict';
var DataTable = $.fn.dataTable;


$.extend(true, DataTable.SearchBuilder.classes, {
    clearAll: 'basic ui button dtsb-clearAll'
});
$.extend(true, DataTable.Group.classes, {
    add: 'basic ui button dtsb-add',
    clearGroup: 'basic ui button dtsb-clearGroup',
    logic: 'basic ui button dtsb-logic'
});
$.extend(true, DataTable.Criteria.classes, {
    condition: 'ui selection dropdown dtsb-condition',
    data: 'ui selection dropdown dtsb-data',
    "delete": 'basic ui button dtsb-delete',
    left: 'basic ui button dtsb-left',
    right: 'basic ui button dtsb-right',
    value: 'basic ui selection dropdown dtsb-value'
});
DataTable.ext.buttons.searchBuilder.action = function (e, dt, node, config) {
    e.stopPropagation();
    this.popover(config._searchBuilder.getNode(), {
        align: 'container',
        span: 'container'
    });
    // Need to redraw the contents to calculate the correct positions for the elements
    if (config._searchBuilder.s.topGroup !== undefined) {
        config._searchBuilder.s.topGroup.dom.container.trigger('dtsb-redrawContents');
    }
    $('div.dtsb-searchBuilder').removeClass('ui basic vertical buttons');
};


return DataTable;
}));
