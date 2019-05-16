( function( $ ) {

	$.fn.multicheck = function( $checkboxes ) {
		$checkboxes = $checkboxes.filter( 'input[type=checkbox]' );
		if( $checkboxes.length > 0 ) {
			this.each( function() {
				var $this = $( this );
				$this.click( function() {
					$checkboxes.prop( 'checked', this.checked );
					$this.trigger( this.checked ? 'multicheck.allchecked' : 'multicheck.nonechecked' );
				});
				$checkboxes.on( 'click change', function() {
					var checkedItems = $checkboxes.filter( ':checked' ).length;
					if( checkedItems == 0 ) {
						$this[ 0 ].indeterminate = false;
						$this[ 0 ].checked = false;
						$this.trigger( 'multicheck.nonechecked' );
					} else if( checkedItems == $checkboxes.length ) {
						$this[ 0 ].indeterminate = false;
						$this[ 0 ].checked = true;
						$this.trigger( 'multicheck.allchecked' );
					} else {
						$this[ 0 ].checked = false;
						$this[ 0 ].indeterminate = true;
						$this.trigger( 'multicheck.somechecked' );
					}
				});
			});
		}
		return this;
	};

})( jQuery );