/*! DateTime picker for DataTables.net v1.4.0
 *
 * © SpryMedia Ltd, all rights reserved.
 * License: MIT datatables.net/license/mit
 */

(function( factory ){
	if ( typeof define === 'function' && define.amd ) {
		// AMD
		define( ['jquery'], function ( $ ) {
			return factory( $, window, document );
		} );
	}
	else if ( typeof exports === 'object' ) {
		// CommonJS
		var jq = require('jquery');
		var cjsRequires = function (root, $) {		};

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



/**
 * @summary     DateTime picker for DataTables.net
 * @version     1.4.0
 * @file        dataTables.dateTime.js
 * @author      SpryMedia Ltd
 * @contact     www.datatables.net/contact
 */

// Supported formatting and parsing libraries:
// * Moment
// * Luxon
// * DayJS
var dateLib;

/*
 * This file provides a DateTime GUI picker (calendar and time input). Only the
 * format YYYY-MM-DD is supported without additional software, but the end user
 * experience can be greatly enhanced by including the momentjs, dayjs or luxon library
 * which provide date / time parsing and formatting options.
 *
 * This functionality is required because the HTML5 date and datetime input
 * types are not widely supported in desktop browsers.
 *
 * Constructed by using:
 *
 *     new DateTime( input, opts )
 *
 * where `input` is the HTML input element to use and `opts` is an object of
 * options based on the `DateTime.defaults` object.
 */
var DateTime = function ( input, opts ) {
	// Check if called with a window or jQuery object for DOM less applications
	// This is for backwards compatibility with CommonJS loader
	if (DateTime.factory(input, opts)) {
		return DateTime;
	}

	// Attempt to auto detect the formatting library (if there is one). Having it in
	// the constructor allows load order independence.
	if (typeof dateLib === 'undefined') {
		dateLib = window.moment
			? window.moment
			: window.dayjs
				? window.dayjs
				: window.luxon
					? window.luxon
					: null;
	}

	this.c = $.extend( true, {}, DateTime.defaults, opts );
	var classPrefix = this.c.classPrefix;
	var i18n = this.c.i18n;

	// Only IS8601 dates are supported without moment, dayjs or luxon
	if ( ! dateLib && this.c.format !== 'YYYY-MM-DD' ) {
		throw "DateTime: Without momentjs, dayjs or luxon only the format 'YYYY-MM-DD' can be used";
	}

	// Min and max need to be `Date` objects in the config
	if (typeof this.c.minDate === 'string') {
		this.c.minDate = new Date(this.c.minDate);
	}
	if (typeof this.c.maxDate === 'string') {
		this.c.maxDate = new Date(this.c.maxDate);
	}

	// DOM structure
	var structure = $(
		'<div class="'+classPrefix+'">'+
			'<div class="'+classPrefix+'-date">'+
				'<div class="'+classPrefix+'-title">'+
					'<div class="'+classPrefix+'-iconLeft">'+
						'<button type="button"></button>'+
					'</div>'+
					'<div class="'+classPrefix+'-iconRight">'+
						'<button type="button"></button>'+
					'</div>'+
					'<div class="'+classPrefix+'-label">'+
						'<span></span>'+
						'<select class="'+classPrefix+'-month"></select>'+
					'</div>'+
					'<div class="'+classPrefix+'-label">'+
						'<span></span>'+
						'<select class="'+classPrefix+'-year"></select>'+
					'</div>'+
				'</div>'+
				'<div class="'+classPrefix+'-buttons">'+
					'<a class="'+classPrefix+'-clear"></a>'+
					'<a class="'+classPrefix+'-today"></a>'+
				'</div>'+
				'<div class="'+classPrefix+'-calendar"></div>'+
			'</div>'+
			'<div class="'+classPrefix+'-time">'+
				'<div class="'+classPrefix+'-hours"></div>'+
				'<div class="'+classPrefix+'-minutes"></div>'+
				'<div class="'+classPrefix+'-seconds"></div>'+
			'</div>'+
			'<div class="'+classPrefix+'-error"></div>'+
		'</div>'
	);

	this.dom = {
		container: structure,
		date:      structure.find( '.'+classPrefix+'-date' ),
		title:     structure.find( '.'+classPrefix+'-title' ),
		calendar:  structure.find( '.'+classPrefix+'-calendar' ),
		time:      structure.find( '.'+classPrefix+'-time' ),
		error:     structure.find( '.'+classPrefix+'-error' ),
		buttons:   structure.find( '.'+classPrefix+'-buttons' ),
		clear:     structure.find( '.'+classPrefix+'-clear' ),
		today:     structure.find( '.'+classPrefix+'-today' ),
		previous:  structure.find( '.'+classPrefix+'-iconLeft' ),
		next:      structure.find( '.'+classPrefix+'-iconRight' ),
		input:     $(input)
	};

	this.s = {
		/** @type {Date} Date value that the picker has currently selected */
		d: null,

		/** @type {Date} Date of the calendar - might not match the value */
		display: null,

		/** @type {number} Used to select minutes in a range where the range base is itself unavailable */
		minutesRange: null,

		/** @type {number} Used to select minutes in a range where the range base is itself unavailable */
		secondsRange: null,

		/** @type {String} Unique namespace string for this instance */
		namespace: 'dateime-'+(DateTime._instance++),

		/** @type {Object} Parts of the picker that should be shown */
		parts: {
			date:    this.c.format.match( /[YMD]|L(?!T)|l/ ) !== null,
			time:    this.c.format.match( /[Hhm]|LT|LTS/ ) !== null,
			seconds: this.c.format.indexOf( 's' )   !== -1,
			hours12: this.c.format.match( /[haA]/ ) !== null
		}
	};

	this.dom.container
		.append( this.dom.date )
		.append( this.dom.time )
		.append( this.dom.error );

	this.dom.date
		.append( this.dom.title )
		.append( this.dom.buttons )
		.append( this.dom.calendar );

	this._constructor();
};

$.extend( DateTime.prototype, {
	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Public
	 */

	/**
	 * Destroy the control
	 */
	destroy: function () {
		this._hide(true);
		this.dom.container.off().empty();
		this.dom.input
			.removeAttr('autocomplete')
			.off('.datetime');
	},

	errorMsg: function ( msg ) {
		var error = this.dom.error;

		if ( msg ) {
			error.html( msg );
		}
		else {
			error.empty();
		}

		return this;
	},

	hide: function () {
		this._hide();

		return this;
	},

	max: function ( date ) {
		this.c.maxDate = typeof date === 'string'
			? new Date(date)
			: date;

		this._optionsTitle();
		this._setCalander();

		return this;
	},

	min: function ( date ) {
		this.c.minDate = typeof date === 'string'
			? new Date(date)
			: date;

		this._optionsTitle();
		this._setCalander();

		return this;
	},

	/**
	 * Check if an element belongs to this control
	 *
	 * @param  {node} node Element to check
	 * @return {boolean}   true if owned by this control, false otherwise
	 */
	owns: function ( node ) {
		return $(node).parents().filter( this.dom.container ).length > 0;
	},

	/**
	 * Get / set the value
	 *
	 * @param  {string|Date} set   Value to set
	 * @param  {boolean} [write=true] Flag to indicate if the formatted value
	 *   should be written into the input element
	 */
	val: function ( set, write ) {
		if ( set === undefined ) {
			return this.s.d;
		}

		if ( set instanceof Date ) {
			this.s.d = this._dateToUtc( set );
		}
		else if ( set === null || set === '' ) {
			this.s.d = null;
		}
		else if ( set === '--now' ) {
			this.s.d = this._dateToUtc(new Date());
		}
		else if ( typeof set === 'string' ) {
			this.s.d = this._dateToUtc(
				this._convert(set, this.c.format, null)
			);
		}

		if ( write || write === undefined ) {
			if ( this.s.d ) {
				this._writeOutput();
			}
			else {
				// The input value was not valid...
				this.dom.input.val( set );
			}
		}

		// Need something to display
		this.s.display = this.s.d
			? new Date( this.s.d.toString() )
			: new Date();

		// Set the day of the month to be 1 so changing between months doesn't
        // run into issues when going from day 31 to 28 (for example)
		this.s.display.setUTCDate( 1 );

		// Update the display elements for the new value
		this._setTitle();
		this._setCalander();
		this._setTime();

		return this;
	},

	/**
	 * Similar to `val()` but uses a given date / time format
	 *
	 * @param format Format to get the data as (getter) or that is input (setter)
	 * @param val Value to write (if undefined, used as a getter)
	 * @returns
	 */
	valFormat: function (format, val) {
		if (! val) {
			return this._convert(this.val(), null, format);
		}

		// Convert from the format given here to the instance's configured format
		this.val(
			this._convert(val, format, null)
		);

		return this;
	},

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Constructor
	 */

	/**
	 * Build the control and assign initial event handlers
	 *
	 * @private
	 */
	_constructor: function () {
		var that = this;
		var classPrefix = this.c.classPrefix;
		var last = this.dom.input.val();

		var onChange = function () {
			var curr = that.dom.input.val();

			if (curr !== last) {
				that.c.onChange.call( that, curr, that.s.d, that.dom.input );
				last = curr;
			}
		};

		if ( ! this.s.parts.date ) {
			this.dom.date.css( 'display', 'none' );
		}

		if ( ! this.s.parts.time ) {
			this.dom.time.css( 'display', 'none' );
		}

		if ( ! this.s.parts.seconds ) {
			this.dom.time.children('div.'+classPrefix+'-seconds').remove();
			this.dom.time.children('span').eq(1).remove();
		}

		if ( ! this.c.buttons.clear ) {
			this.dom.clear.css( 'display', 'none' );
		}

		if ( ! this.c.buttons.today ) {
			this.dom.today.css( 'display', 'none' );
		}

		// Render the options
		this._optionsTitle();

		$(document).on('i18n.dt', function (e, settings) {
			if (settings.oLanguage.datetime) {
				$.extend(true, that.c.i18n, settings.oLanguage.datetime);
				that._optionsTitle();
			}
		});

		// When attached to a hidden input, we always show the input picker, and
		// do so inline
		if (this.dom.input.attr('type') === 'hidden') {
			this.dom.container.addClass('inline');
			this.c.attachTo = 'input';

			this.val( this.dom.input.val(), false );
			this._show();
		}

		// Set the initial value
		if (last) {
			this.val( last, false );
		}

		// Trigger the display of the widget when clicking or focusing on the
		// input element
		this.dom.input
			.attr('autocomplete', 'off')
			.on('focus.datetime click.datetime', function () {
				// If already visible - don't do anything
				if ( that.dom.container.is(':visible') || that.dom.input.is(':disabled') ) {
					return;
				}

				// In case the value has changed by text
				that.val( that.dom.input.val(), false );

				that._show();
			} )
			.on('keyup.datetime', function () {
				// Update the calendar's displayed value as the user types
				if ( that.dom.container.is(':visible') ) {
					that.val( that.dom.input.val(), false );
				}
			} );

		// Main event handlers for input in the widget
		this.dom.container
			.on( 'change', 'select', function () {
				var select = $(this);
				var val = select.val();

				if ( select.hasClass(classPrefix+'-month') ) {
					// Month select
					that._correctMonth( that.s.display, val );
					that._setTitle();
					that._setCalander();
				}
				else if ( select.hasClass(classPrefix+'-year') ) {
					// Year select
					that.s.display.setUTCFullYear( val );
					that._setTitle();
					that._setCalander();
				}
				else if ( select.hasClass(classPrefix+'-hours') || select.hasClass(classPrefix+'-ampm') ) {
					// Hours - need to take account of AM/PM input if present
					if ( that.s.parts.hours12 ) {
						var hours = $(that.dom.container).find('.'+classPrefix+'-hours').val() * 1;
						var pm = $(that.dom.container).find('.'+classPrefix+'-ampm').val() === 'pm';

						that.s.d.setUTCHours( hours === 12 && !pm ?
							0 :
							pm && hours !== 12 ?
								hours + 12 :
								hours
						);
					}
					else {
						that.s.d.setUTCHours( val );
					}

					that._setTime();
					that._writeOutput( true );

					onChange();
				}
				else if ( select.hasClass(classPrefix+'-minutes') ) {
					// Minutes select
					that.s.d.setUTCMinutes( val );
					that._setTime();
					that._writeOutput( true );

					onChange();
				}
				else if ( select.hasClass(classPrefix+'-seconds') ) {
					// Seconds select
					that.s.d.setSeconds( val );
					that._setTime();
					that._writeOutput( true );

					onChange();
				}

				that.dom.input.focus();
				that._position();
			} )
			.on( 'click', function (e) {
				var d = that.s.d;
				var nodeName = e.target.nodeName.toLowerCase();
				var target = nodeName === 'span' ?
					e.target.parentNode :
					e.target;

				nodeName = target.nodeName.toLowerCase();

				if ( nodeName === 'select' ) {
					return;
				}

				e.stopPropagation();

				if ( nodeName === 'a' ) {
					e.preventDefault();

					if ($(target).hasClass(classPrefix+'-clear')) {
						// Clear the value and don't change the display
						that.s.d = null;
						that.dom.input.val('');
						that._writeOutput();
						that._setCalander();
						that._setTime();

						onChange();
					}
					else if ($(target).hasClass(classPrefix+'-today')) {
						// Don't change the value, but jump to the month
						// containing today
						that.s.display = new Date();

						that._setTitle();
						that._setCalander();
					}
				}
				if ( nodeName === 'button' ) {
					var button = $(target);
					var parent = button.parent();

					if ( parent.hasClass('disabled') && ! parent.hasClass('range') ) {
						button.blur();
						return;
					}

					if ( parent.hasClass(classPrefix+'-iconLeft') ) {
						// Previous month
						that.s.display.setUTCMonth( that.s.display.getUTCMonth()-1 );
						that._setTitle();
						that._setCalander();

						that.dom.input.focus();
					}
					else if ( parent.hasClass(classPrefix+'-iconRight') ) {
						// Next month
						that._correctMonth( that.s.display, that.s.display.getUTCMonth()+1 );
						that._setTitle();
						that._setCalander();

						that.dom.input.focus();
					}
					else if ( button.parents('.'+classPrefix+'-time').length ) {
						var val = button.data('value');
						var unit = button.data('unit');

						d = that._needValue();

						if ( unit === 'minutes' ) {
							if ( parent.hasClass('disabled') && parent.hasClass('range') ) {
								that.s.minutesRange = val;
								that._setTime();
								return;
							}
							else {
								that.s.minutesRange = null;
							}
						}

						if ( unit === 'seconds' ) {
							if ( parent.hasClass('disabled') && parent.hasClass('range') ) {
								that.s.secondsRange = val;
								that._setTime();
								return;
							}
							else {
								that.s.secondsRange = null;
							}
						}

						// Specific to hours for 12h clock
						if ( val === 'am' ) {
							if ( d.getUTCHours() >= 12 ) {
								val = d.getUTCHours() - 12;
							}
							else {
								return;
							}
						}
						else if ( val === 'pm' ) {
							if ( d.getUTCHours() < 12 ) {
								val = d.getUTCHours() + 12;
							}
							else {
								return;
							}
						}

						var set = unit === 'hours' ?
							'setUTCHours' :
							unit === 'minutes' ?
								'setUTCMinutes' :
								'setSeconds';

						d[set]( val );
						that._setCalander();
						that._setTime();
						that._writeOutput( true );
						onChange();
					}
					else {
						// Calendar click
						d = that._needValue();

						// Can't be certain that the current day will exist in
						// the new month, and likewise don't know that the
						// new day will exist in the old month, But 1 always
						// does, so we can change the month without worry of a
						// recalculation being done automatically by `Date`
						d.setUTCDate( 1 );
						d.setUTCFullYear( button.data('year') );
						d.setUTCMonth( button.data('month') );
						d.setUTCDate( button.data('day') );

						that._writeOutput( true );

						// Don't hide if there is a time picker, since we want to
						// be able to select a time as well.
						if ( ! that.s.parts.time ) {
							// This is annoying but IE has some kind of async
							// behaviour with focus and the focus from the above
							// write would occur after this hide - resulting in the
							// calendar opening immediately
							setTimeout( function () {
								that._hide();
							}, 10 );
						}
						else {
							that._setCalander();
							that._setTime();
						}

						onChange();
					}
				}
				else {
					// Click anywhere else in the widget - return focus to the
					// input element
					that.dom.input.focus();
				}
			} );
	},


	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Private
	 */

	/**
	 * Compare the date part only of two dates - this is made super easy by the
	 * toDateString method!
	 *
	 * @param  {Date} a Date 1
	 * @param  {Date} b Date 2
	 * @private
	 */
	_compareDates: function( a, b ) {
		// Can't use toDateString as that converts to local time
		// luxon uses different method names so need to be able to call them
		return this._isLuxon()
			? dateLib.DateTime.fromJSDate(a).toUTC().toISODate() === dateLib.DateTime.fromJSDate(b).toUTC().toISODate()
			: this._dateToUtcString(a) === this._dateToUtcString(b);
	},

	/**
	 * Convert from one format to another
	 *
	 * @param {string|Date} val Value
	 * @param {string|null} from Format to convert from. If null a `Date` must be given
	 * @param {string|null} to Format to convert to. If null a `Date` will be returned
	 * @returns {string|Date} Converted value
	 */
	_convert(val, from, to) {
		if (! val) {
			return val;
		}

		if (! dateLib) {
			// Note that in here from and to can either be null or YYYY-MM-DD
			// They cannot be anything else
			if ((! from && ! to) || (from && to)) {
				// No conversion
				return val;
			}
			else if (! from) {
				// Date in, string back
				return val.getUTCFullYear() +'-'+
					this._pad(val.getUTCMonth() + 1) +'-'+
					this._pad(val.getUTCDate());
			}
			else { // (! to)
				// String in, date back
				var match = val.match(/(\d{4})\-(\d{2})\-(\d{2})/ );
				return match ?
					new Date( match[1], match[2]-1, match[3] ) :
					null;
			}
		}
		else if (this._isLuxon()) {
			// Luxon
			var dtLux = val instanceof Date
				? dateLib.DateTime.fromJSDate(val).toUTC()
				: dateLib.DateTime.fromFormat(val, from);

			if (! dtLux.isValid) {
				return null;
			}

			return to
				? dtLux.toFormat(to)
				: dtLux.toJSDate();
		}
		else {
			// Moment / DayJS
			var dtMo = val instanceof Date
				? dateLib.utc( val, undefined, this.c.locale, this.c.strict )
				: dateLib( val, from, this.c.locale, this.c.strict );

			if (! dtMo.isValid()) {
				return null;
			}

			return to
				? dtMo.format(to)
				: dtMo.toDate();
		}
	},

	/**
	 * When changing month, take account of the fact that some months don't have
	 * the same number of days. For example going from January to February you
	 * can have the 31st of Jan selected and just add a month since the date
	 * would still be 31, and thus drop you into March.
	 *
	 * @param  {Date} date  Date - will be modified
	 * @param  {integer} month Month to set
	 * @private
	 */
	_correctMonth: function ( date, month ) {
		var days = this._daysInMonth( date.getUTCFullYear(), month );
		var correctDays = date.getUTCDate() > days;

		date.setUTCMonth( month );

		if ( correctDays ) {
			date.setUTCDate( days );
			date.setUTCMonth( month );
		}
	},

	/**
	 * Get the number of days in a method. Based on
	 * http://stackoverflow.com/a/4881951 by Matti Virkkunen
	 *
	 * @param  {integer} year  Year
	 * @param  {integer} month Month (starting at 0)
	 * @private
	 */
	_daysInMonth: function ( year, month ) {
		//
		var isLeap = ((year % 4) === 0 && ((year % 100) !== 0 || (year % 400) === 0));
		var months = [31, (isLeap ? 29 : 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

		return months[month];
	},

	/**
	 * Create a new date object which has the UTC values set to the local time.
	 * This allows the local time to be used directly for the library which
	 * always bases its calculations and display on UTC.
	 *
	 * @param  {Date} s Date to "convert"
	 * @return {Date}   Shifted date
	 */
	_dateToUtc: function ( s ) {
		if (! s) {
			return s;
		}

		return new Date( Date.UTC(
			s.getFullYear(), s.getMonth(), s.getDate(),
			s.getHours(), s.getMinutes(), s.getSeconds()
		) );
	},

	/**
	 * Create a UTC ISO8601 date part from a date object
	 *
	 * @param  {Date} d Date to "convert"
	 * @return {string} ISO formatted date
	 */
	_dateToUtcString: function ( d ) {
		// luxon uses different method names so need to be able to call them
		return this._isLuxon()
			? dateLib.DateTime.fromJSDate(d).toUTC().toISODate()
			: d.getUTCFullYear()+'-'+
				this._pad(d.getUTCMonth()+1)+'-'+
				this._pad(d.getUTCDate());
	},

	/**
	 * Hide the control and remove events related to its display
	 *
	 * @private
	 */
	_hide: function (destroy) {
		if (! destroy && this.dom.input.attr('type') === 'hidden') {
			return;
		}

		var namespace = this.s.namespace;

		this.dom.container.detach();

		$(window).off( '.'+namespace );
		$(document).off( 'keydown.'+namespace );
		$('div.dataTables_scrollBody').off( 'scroll.'+namespace );
		$('div.DTE_Body_Content').off( 'scroll.'+namespace );
		$('body').off( 'click.'+namespace );
		$(this.dom.input[0].offsetParent).off('.'+namespace);
	},

	/**
	 * Convert a 24 hour value to a 12 hour value
	 *
	 * @param  {integer} val 24 hour value
	 * @return {integer}     12 hour value
	 * @private
	 */
	_hours24To12: function ( val ) {
		return val === 0 ?
			12 :
			val > 12 ?
				val - 12 :
				val;
	},

	/**
	 * Generate the HTML for a single day in the calendar - this is basically
	 * and HTML cell with a button that has data attributes so we know what was
	 * clicked on (if it is clicked on) and a bunch of classes for styling.
	 *
	 * @param  {object} day Day object from the `_htmlMonth` method
	 * @return {string}     HTML cell
	 */
	_htmlDay: function( day )
	{
		if ( day.empty ) {
			return '<td class="empty"></td>';
		}

		var classes = [ 'selectable' ];
		var classPrefix = this.c.classPrefix;

		if ( day.disabled ) {
			classes.push( 'disabled' );
		}

		if ( day.today ) {
			classes.push( 'now' );
		}

		if ( day.selected ) {
			classes.push( 'selected' );
		}

		return '<td data-day="' + day.day + '" class="' + classes.join(' ') + '">' +
				'<button class="'+classPrefix+'-button '+classPrefix+'-day" type="button" ' +'data-year="' + day.year + '" data-month="' + day.month + '" data-day="' + day.day + '">' +
					'<span>'+day.day+'</span>'+
				'</button>' +
			'</td>';
	},


	/**
	 * Create the HTML for a month to be displayed in the calendar table.
	 *
	 * Based upon the logic used in Pikaday - MIT licensed
	 * Copyright (c) 2014 David Bushell
	 * https://github.com/dbushell/Pikaday
	 *
	 * @param  {integer} year  Year
	 * @param  {integer} month Month (starting at 0)
	 * @return {string} Calendar month HTML
	 * @private
	 */
	_htmlMonth: function ( year, month ) {
		var now    = this._dateToUtc( new Date() ),
			days   = this._daysInMonth( year, month ),
			before = new Date( Date.UTC(year, month, 1) ).getUTCDay(),
			data   = [],
			row    = [];

		if ( this.c.firstDay > 0 ) {
			before -= this.c.firstDay;

			if (before < 0) {
				before += 7;
			}
		}

		var cells = days + before,
			after = cells;

		while ( after > 7 ) {
			after -= 7;
		}

		cells += 7 - after;

		var minDate = this.c.minDate;
		var maxDate = this.c.maxDate;

		if ( minDate ) {
			minDate.setUTCHours(0);
			minDate.setUTCMinutes(0);
			minDate.setSeconds(0);
		}

		if ( maxDate ) {
			maxDate.setUTCHours(23);
			maxDate.setUTCMinutes(59);
			maxDate.setSeconds(59);
		}

		for ( var i=0, r=0 ; i<cells ; i++ ) {
			var day      = new Date( Date.UTC(year, month, 1 + (i - before)) ),
				selected = this.s.d ? this._compareDates(day, this.s.d) : false,
				today    = this._compareDates(day, now),
				empty    = i < before || i >= (days + before),
				disabled = (minDate && day < minDate) ||
				           (maxDate && day > maxDate);

			var disableDays = this.c.disableDays;
			if ( Array.isArray( disableDays ) && $.inArray( day.getUTCDay(), disableDays ) !== -1 ) {
				disabled = true;
			}
			else if ( typeof disableDays === 'function' && disableDays( day ) === true ) {
				disabled = true;
			}

			var dayConfig = {
				day:      1 + (i - before),
				month:    month,
				year:     year,
				selected: selected,
				today:    today,
				disabled: disabled,
				empty:    empty
			};

			row.push( this._htmlDay(dayConfig) );

			if ( ++r === 7 ) {
				if ( this.c.showWeekNumber ) {
					row.unshift( this._htmlWeekOfYear(i - before, month, year) );
				}

				data.push( '<tr>'+row.join('')+'</tr>' );
				row = [];
				r = 0;
			}
		}

		var classPrefix = this.c.classPrefix;
		var className = classPrefix+'-table';
		if ( this.c.showWeekNumber ) {
			className += ' weekNumber';
		}

		// Show / hide month icons based on min/max
		if ( minDate ) {
			var underMin = minDate >= new Date( Date.UTC(year, month, 1, 0, 0, 0 ) );

			this.dom.title.find('div.'+classPrefix+'-iconLeft')
				.css( 'display', underMin ? 'none' : 'block' );
		}

		if ( maxDate ) {
			var overMax = maxDate < new Date( Date.UTC(year, month+1, 1, 0, 0, 0 ) );

			this.dom.title.find('div.'+classPrefix+'-iconRight')
				.css( 'display', overMax ? 'none' : 'block' );
		}

		return '<table class="'+className+'">' +
				'<thead>'+
					this._htmlMonthHead() +
				'</thead>'+
				'<tbody>'+
					data.join('') +
				'</tbody>'+
			'</table>';
	},

	/**
	 * Create the calendar table's header (week days)
	 *
	 * @return {string} HTML cells for the row
	 * @private
	 */
	_htmlMonthHead: function () {
		var a = [];
		var firstDay = this.c.firstDay;
		var i18n = this.c.i18n;

		// Take account of the first day shift
		var dayName = function ( day ) {
			day += firstDay;

			while (day >= 7) {
				day -= 7;
			}

			return i18n.weekdays[day];
		};

		// Empty cell in the header
		if ( this.c.showWeekNumber ) {
			a.push( '<th></th>' );
		}

		for ( var i=0 ; i<7 ; i++ ) {
			a.push( '<th>'+dayName( i )+'</th>' );
		}

		return a.join('');
	},

	/**
	 * Create a cell that contains week of the year - ISO8601
	 *
	 * Based on https://stackoverflow.com/questions/6117814/ and
	 * http://techblog.procurios.nl/k/n618/news/view/33796/14863/
	 *
	 * @param  {integer} d Day of month
	 * @param  {integer} m Month of year (zero index)
	 * @param  {integer} y Year
	 * @return {string}
	 * @private
	 */
	_htmlWeekOfYear: function ( d, m, y ) {
		var date = new Date( y, m, d, 0, 0, 0, 0 );

		// First week of the year always has 4th January in it
		date.setDate( date.getDate() + 4 - (date.getDay() || 7) );

		var oneJan = new Date( y, 0, 1 );
		var weekNum = Math.ceil( ( ( (date - oneJan) / 86400000) + 1)/7 );

		return '<td class="'+this.c.classPrefix+'-week">' + weekNum + '</td>';
	},

	/**
	 * Determine if Luxon is being used
	 *
	 * @returns Flag for Luxon
	 */
	_isLuxon: function () {
		return dateLib && dateLib.DateTime && dateLib.Duration && dateLib.Settings
			? true
			: false;
	},

	/**
	 * Check if the instance has a date object value - it might be null.
	 * If is doesn't set one to now.
	 * @returns A Date object
	 * @private
	 */
	_needValue: function () {
		if ( ! this.s.d ) {
			this.s.d = this._dateToUtc( new Date() );

			if (! this.s.parts.time) {
				this.s.d.setUTCHours(0);
				this.s.d.setUTCMinutes(0);
				this.s.d.setSeconds(0);
				this.s.d.setMilliseconds(0);
			}
		}

		return this.s.d;
	},

	/**
	 * Create option elements from a range in an array
	 *
	 * @param  {string} selector Class name unique to the select element to use
	 * @param  {array} values   Array of values
	 * @param  {array} [labels] Array of labels. If given must be the same
	 *   length as the values parameter.
	 * @private
	 */
	_options: function ( selector, values, labels ) {
		if ( ! labels ) {
			labels = values;
		}

		var select = this.dom.container.find('select.'+this.c.classPrefix+'-'+selector);
		select.empty();

		for ( var i=0, ien=values.length ; i<ien ; i++ ) {
			select.append( '<option value="'+values[i]+'">'+labels[i]+'</option>' );
		}
	},

	/**
	 * Set an option and update the option's span pair (since the select element
	 * has opacity 0 for styling)
	 *
	 * @param  {string} selector Class name unique to the select element to use
	 * @param  {*}      val      Value to set
	 * @private
	 */
	_optionSet: function ( selector, val ) {
		var select = this.dom.container.find('select.'+this.c.classPrefix+'-'+selector);
		var span = select.parent().children('span');

		select.val( val );

		var selected = select.find('option:selected');
		span.html( selected.length !== 0 ?
			selected.text() :
			this.c.i18n.unknown
		);
	},

	/**
	 * Create time options list.
	 *
	 * @param  {string} unit Time unit - hours, minutes or seconds
	 * @param  {integer} count Count range - 12, 24 or 60
	 * @param  {integer} val Existing value for this unit
	 * @param  {integer[]} allowed Values allow for selection
	 * @param  {integer} range Override range
	 * @private
	 */
	_optionsTime: function ( unit, count, val, allowed, range ) {
		var classPrefix = this.c.classPrefix;
		var container = this.dom.container.find('div.'+classPrefix+'-'+unit);
		var i, j;
		var render = count === 12 ?
			function (i) { return i; } :
			this._pad;
		var classPrefix = this.c.classPrefix;
		var className = classPrefix+'-table';
		var i18n = this.c.i18n;

		if ( ! container.length ) {
			return;
		}

		var a = '';
		var span = 10;
		var button = function (value, label, className) {
			// Shift the value for PM
			if ( count === 12 && typeof value === 'number' ) {
				if (val >= 12 ) {
					value += 12;
				}

				if (value == 12) {
					value = 0;
				}
				else if (value == 24) {
					value = 12;
				}
			}

			var selected = val === value || (value === 'am' && val < 12) || (value === 'pm' && val >= 12) ?
				'selected' :
				'';

			if (typeof value === 'number' && allowed && $.inArray(value, allowed) === -1) {
				selected += ' disabled';
			}

			if ( className ) {
				selected += ' '+className;
			}

			return '<td class="selectable '+selected+'">' +
				'<button class="'+classPrefix+'-button '+classPrefix+'-day" type="button" data-unit="'+unit+'" data-value="'+value+ '">' +
					'<span>'+label+'</span>'+
				'</button>' +
			'</td>';
		}

		if ( count === 12 ) {
			// Hours with AM/PM
			a += '<tr>';

			for ( i=1 ; i<=6 ; i++ ) {
				a += button(i, render(i));
			}
			a += button('am', i18n.amPm[0]);

			a += '</tr>';
			a += '<tr>';

			for ( i=7 ; i<=12 ; i++ ) {
				a += button(i, render(i));
			}
			a += button('pm', i18n.amPm[1]);
			a += '</tr>';

			span = 7;
		}
		else if ( count === 24 ) {
			// Hours - 24
			var c = 0;
			for (j=0 ; j<4 ; j++ ) {
				a += '<tr>';
				for ( i=0 ; i<6 ; i++ ) {
					a += button(c, render(c));
					c++;
				}
				a += '</tr>';
			}

			span = 6;
		}
		else {
			// Minutes and seconds
			a += '<tr>';
			for (j=0 ; j<60 ; j+=10 ) {
				a += button(j, render(j), 'range');
			}
			a += '</tr>';

			// Slight hack to allow for the different number of columns
			a += '</tbody></thead><table class="'+className+' '+className+'-nospace"><tbody>';

			var start = range !== null
				? range
				: val === -1
					? 0
					: Math.floor( val / 10 )*10;

			a += '<tr>';
			for (j=start+1 ; j<start+10 ; j++ ) {
				a += button(j, render(j));
			}
			a += '</tr>';

			span = 6;
		}

		container
			.empty()
			.append(
				'<table class="'+className+'">'+
					'<thead><tr><th colspan="'+span+'">'+
						i18n[unit] +
					'</th></tr></thead>'+
					'<tbody>'+
						a+
					'</tbody>'+
				'</table>'
			);
	},

	/**
	 * Create the options for the month and year
	 *
	 * @param  {integer} year  Year
	 * @param  {integer} month Month (starting at 0)
	 * @private
	 */
	_optionsTitle: function () {
		var i18n = this.c.i18n;
		var min = this.c.minDate;
		var max = this.c.maxDate;
		var minYear = min ? min.getFullYear() : null;
		var maxYear = max ? max.getFullYear() : null;

		var i = minYear !== null ? minYear : new Date().getFullYear() - this.c.yearRange;
		var j = maxYear !== null ? maxYear : new Date().getFullYear() + this.c.yearRange;

		this._options( 'month', this._range( 0, 11 ), i18n.months );
		this._options( 'year', this._range( i, j ) );

		// Set the language strings in case any have changed
		this.dom.today.text(i18n.today).text(i18n.today);
		this.dom.clear.text(i18n.clear).text(i18n.clear);
		this.dom.previous
			.attr('title', i18n.previous)
			.children('button')
			.text(i18n.previous);
		this.dom.next
			.attr('title', i18n.next)
			.children('button')
			.text(i18n.next);
	},

	/**
	 * Simple two digit pad
	 *
	 * @param  {integer} i      Value that might need padding
	 * @return {string|integer} Padded value
	 * @private
	 */
	_pad: function ( i ) {
		return i<10 ? '0'+i : i;
	},

	/**
	 * Position the calendar to look attached to the input element
	 * @private
	 */
	_position: function () {
		var offset = this.c.attachTo === 'input' ? this.dom.input.position() : this.dom.input.offset();
		var container = this.dom.container;
		var inputHeight = this.dom.input.outerHeight();

		if (container.hasClass('inline')) {
			container.insertAfter( this.dom.input );
			return;
		}

		if ( this.s.parts.date && this.s.parts.time && $(window).width() > 550 ) {
			container.addClass('horizontal');
		}
		else {
			container.removeClass('horizontal');
		}

		if(this.c.attachTo === 'input') {
			container
				.css( {
					top: offset.top + inputHeight,
					left: offset.left
				} )
				.insertAfter( this.dom.input );
		}
		else {
			container
				.css( {
					top: offset.top + inputHeight,
					left: offset.left
				} )
				.appendTo( 'body' );
		}

		var calHeight = container.outerHeight();
		var calWidth = container.outerWidth();
		var scrollTop = $(window).scrollTop();

		// Correct to the bottom
		if ( offset.top + inputHeight + calHeight - scrollTop > $(window).height() ) {
			var newTop = offset.top - calHeight;

			container.css( 'top', newTop < 0 ? 0 : newTop );
		}

		// Correct to the right
		if ( calWidth + offset.left > $(window).width() ) {
			var newLeft = $(window).width() - calWidth;

			// Account for elements which are inside a position absolute element
			if (this.c.attachTo === 'input') {
				newLeft -= $(container).offsetParent().offset().left;
			}

			container.css( 'left', newLeft < 0 ? 0 : newLeft );
		}
	},

	/**
	 * Create a simple array with a range of values
	 *
	 * @param  {integer} start   Start value (inclusive)
	 * @param  {integer} end     End value (inclusive)
	 * @param  {integer} [inc=1] Increment value
	 * @return {array}           Created array
	 * @private
	 */
	_range: function ( start, end, inc ) {
		var a = [];

		if ( ! inc ) {
			inc = 1;
		}

		for ( var i=start ; i<=end ; i+=inc ) {
			a.push( i );
		}

		return a;
	},

	/**
	 * Redraw the calendar based on the display date - this is a destructive
	 * operation
	 *
	 * @private
	 */
	_setCalander: function () {
		if ( this.s.display ) {
			this.dom.calendar
				.empty()
				.append( this._htmlMonth(
					this.s.display.getUTCFullYear(),
					this.s.display.getUTCMonth()
				) );
		}
	},

	/**
	 * Set the month and year for the calendar based on the current display date
	 *
	 * @private
	 */
	_setTitle: function () {
		this._optionSet( 'month', this.s.display.getUTCMonth() );
		this._optionSet( 'year', this.s.display.getUTCFullYear() );
	},

	/**
	 * Set the time based on the current value of the widget
	 *
	 * @private
	 */
	_setTime: function () {
		var that = this;
		var d = this.s.d;

		// luxon uses different method names so need to be able to call them. This happens a few time later in this method too
		var luxDT = null
		if (this._isLuxon()) {
			luxDT = dateLib.DateTime.fromJSDate(d).toUTC();
		}

		var hours = luxDT != null
			? luxDT.hour
			: d
				? d.getUTCHours()
				: -1;

		var allowed = function ( prop ) { // Backwards compt with `Increment` option
			return that.c[prop+'Available'] ?
				that.c[prop+'Available'] :
				that._range( 0, 59, that.c[prop+'Increment'] );
		}

		this._optionsTime( 'hours', this.s.parts.hours12 ? 12 : 24, hours, this.c.hoursAvailable )
		this._optionsTime(
			'minutes',
			60,
			luxDT != null
				? luxDT.minute
				: d
					? d.getUTCMinutes()
					: -1,
			allowed('minutes'),
			this.s.minutesRange
		);
		this._optionsTime(
			'seconds',
			60,
			luxDT != null
				? luxDT.second
				: d
					? d.getSeconds()
					: -1,
			allowed('seconds'),
			this.s.secondsRange
		);
	},

	/**
	 * Show the widget and add events to the document required only while it
	 * is displayed
	 *
	 * @private
	 */
	_show: function () {
		var that = this;
		var namespace = this.s.namespace;

		this._position();

		// Need to reposition on scroll
		$(window).on( 'scroll.'+namespace+' resize.'+namespace, function () {
			that._position();
		} );

		$('div.DTE_Body_Content').on( 'scroll.'+namespace, function () {
			that._position();
		} );

		$('div.dataTables_scrollBody').on( 'scroll.'+namespace, function () {
			that._position();
		} );

		var offsetParent = this.dom.input[0].offsetParent;

		if ( offsetParent !== document.body ) {
			$(offsetParent).on( 'scroll.'+namespace, function () {
				that._position();
			} );
		}

		// On tab focus will move to a different field (no keyboard navigation
		// in the date picker - this might need to be changed).
		$(document).on( 'keydown.'+namespace, function (e) {
			if (
				e.keyCode === 9  || // tab
				e.keyCode === 27 || // esc
				e.keyCode === 13    // return
			) {
				that._hide();
			}
		} );

		// Hide if clicking outside of the widget - but in a different click
		// event from the one that was used to trigger the show (bubble and
		// inline)
		setTimeout( function () {
			$('body').on( 'click.'+namespace, function (e) {
				var parents = $(e.target).parents();

				if ( ! parents.filter( that.dom.container ).length && e.target !== that.dom.input[0] ) {
					that._hide();
				}
			} );
		}, 10 );
	},

	/**
	 * Write the formatted string to the input element this control is attached
	 * to
	 *
	 * @private
	 */
	_writeOutput: function ( focus ) {
		var date = this.s.d;
		var out = '';

		if (date) {
			out = this._convert(date, null, this.c.format);
		}

		this.dom.input
			.val( out )
			.trigger('change', {write: date});

		if ( this.dom.input.attr('type') === 'hidden' ) {
			this.val(out, false);
		}

		if ( focus ) {
			this.dom.input.focus();
		}
	}
} );

/**
 * Use a specificmoment compatible date library
 */
DateTime.use = function (lib) {
	dateLib = lib;
};

/**
 * For generating unique namespaces
 *
 * @type {Number}
 * @private
 */
DateTime._instance = 0;

/**
 * Defaults for the date time picker
 *
 * @type {Object}
 */
DateTime.defaults = {
	attachTo: 'body',

	buttons: {
		clear: false,
		today: false
	},

	// Not documented - could be an internal property
	classPrefix: 'dt-datetime',

	// function or array of ints
	disableDays: null,

	// first day of the week (0: Sunday, 1: Monday, etc)
	firstDay: 1,

	format: 'YYYY-MM-DD',

	hoursAvailable: null,

	i18n: {
		clear:    'Clear',
		previous: 'Previous',
		next:     'Next',
		months:   [ 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December' ],
		weekdays: [ 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat' ],
		amPm:     [ 'am', 'pm' ],
		hours:    'Hour',
		minutes:  'Minute',
		seconds:  'Second',
		unknown:  '-',
		today:    'Today'
	},

	maxDate: null,

	minDate: null,

	minutesAvailable: null,

	minutesIncrement: 1, // deprecated

	strict: true,

	locale: 'en',

	onChange: function () {},

	secondsAvailable: null,

	secondsIncrement: 1, // deprecated

	// show the ISO week number at the head of the row
	showWeekNumber: false,

	// overruled by max / min date
	yearRange: 25
};

DateTime.version = '1.4.0';

/**
 * CommonJS factory function pass through. Matches DataTables.
 * @param {*} root Window
 * @param {*} jq jQUery
 * @returns {boolean} Indicator
 */
DateTime.factory = function (root, jq) {
	var is = false;

	// Test if the first parameter is a window object
	if (root && root.document) {
		window = root;
		document = root.document;
	}

	// Test if the second parameter is a jQuery object
	if (jq && jq.fn && jq.fn.jquery) {
		$ = jq;
		is = true;
	}

	return is;
}

// Global export - if no conflicts
if (! window.DateTime) {
	window.DateTime = DateTime;
}

// Global DataTable
if (window.DataTable) {
	window.DataTable.DateTime = DateTime;
}

// Make available via jQuery
$.fn.dtDateTime = function (options) {
	return this.each(function() {
		new DateTime(this, options);
	});
}

// Attach to DataTables if present
if ($.fn.dataTable) {
	$.fn.dataTable.DateTime = DateTime;
	$.fn.DataTable.DateTime = DateTime;

	if ($.fn.dataTable.Editor) {
		$.fn.dataTable.Editor.DateTime = DateTime;
	}
}


return DateTime;
}));
