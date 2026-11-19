( function () {
	'use strict';

	Array.prototype.slice.call( document.querySelectorAll( 'div[id="message"].inline' ) ).forEach( function ( notice ) {
		var button = document.createElement( 'button' );
		var label = document.createElement( 'span' );

		button.type = 'button';
		button.className = 'notice-dismiss';
		label.className = 'screen-reader-text';
		label.textContent = ( window.paylumoSettings || {} ).dismiss || 'Dismiss this notice.';
		button.appendChild( label );

		button.addEventListener( 'click', function () {
			notice.parentNode.removeChild( notice );
		} );

		notice.classList.add( 'notice', 'is-dismissible' );
		notice.appendChild( button );
	} );

	var root = document.querySelector( '.paylumo-keys' );
	if ( ! root ) {
		return;
	}

	var text = window.paylumoSettings || {};
	var tabs = Array.prototype.slice.call( root.querySelectorAll( '[role="tab"]' ) );
	var panels = Array.prototype.slice.call( root.querySelectorAll( '[role="tabpanel"]' ) );
	var storageKey = 'paylumoSettingsTab';

	function selectTab( mode, moveFocus, syncRadio ) {
		var found = false;

		tabs.forEach( function ( tab ) {
			var isOn = tab.getAttribute( 'data-mode' ) === mode;
			tab.setAttribute( 'aria-selected', isOn ? 'true' : 'false' );
			tab.tabIndex = isOn ? 0 : -1;
			if ( isOn ) {
				found = true;
				if ( moveFocus ) {
					tab.focus();
				}
			}
		} );

		if ( ! found ) {
			return;
		}

		panels.forEach( function ( panel ) {
			panel.hidden = panel.getAttribute( 'data-mode' ) !== mode;
		} );

		if ( syncRadio ) {
			radios.forEach( function ( radio ) {
				radio.checked = radio.value === mode;
			} );
			syncLiveNote();
		}

		try {
			window.sessionStorage.setItem( storageKey, mode );
		} catch ( e ) {
		}
	}

	var startMode = root.getAttribute( 'data-active-mode' ) || 'test';
	try {
		var remembered = window.sessionStorage.getItem( storageKey );
		if ( 'test' === remembered || 'live' === remembered ) {
			startMode = remembered;
		}
	} catch ( e ) {
	}

	root.classList.add( 'is-enhanced' );
	selectTab( startMode, false );

	tabs.forEach( function ( tab, index ) {
		tab.addEventListener( 'click', function () {
			selectTab( tab.getAttribute( 'data-mode' ), false, true );
		} );

		tab.addEventListener( 'keydown', function ( event ) {
			var next = null;
			if ( 'ArrowRight' === event.key ) {
				next = tabs[ ( index + 1 ) % tabs.length ];
			} else if ( 'ArrowLeft' === event.key ) {
				next = tabs[ ( index - 1 + tabs.length ) % tabs.length ];
			} else if ( 'Home' === event.key ) {
				next = tabs[ 0 ];
			} else if ( 'End' === event.key ) {
				next = tabs[ tabs.length - 1 ];
			}

			if ( next ) {
				event.preventDefault();
				selectTab( next.getAttribute( 'data-mode' ), true, true );
			}
		} );
	} );

	var radios = Array.prototype.slice.call( document.querySelectorAll( '.paylumo-mode-choice input[type="radio"]' ) );
	var liveNote = document.querySelector( '.paylumo-mode-live-note' );

	function syncLiveNote() {
		var liveChecked = radios.some( function ( radio ) {
			return radio.checked && 'live' === radio.value;
		} );
		if ( liveNote ) {
			liveNote.hidden = ! liveChecked;
		}
	}

	radios.forEach( function ( radio ) {
		radio.addEventListener( 'change', function () {
			if ( radio.checked ) {
				selectTab( radio.value, false );
			}
			syncLiveNote();
		} );
	} );
	syncLiveNote();

	Array.prototype.slice.call( root.querySelectorAll( '.paylumo-copy-button' ) ).forEach( function ( button ) {
		var input = document.getElementById( button.getAttribute( 'data-copy-target' ) );
		var status = button.parentNode.querySelector( '.paylumo-copy-status' );
		var timer = null;

		if ( ! input ) {
			return;
		}

		function say( message ) {
			if ( ! status ) {
				return;
			}
			status.textContent = message;
			window.clearTimeout( timer );
			timer = window.setTimeout( function () {
				status.textContent = '';
			}, 3000 );
		}

		function fallbackCopy() {
			input.focus();
			input.select();
			var ok = false;
			try {
				ok = document.execCommand( 'copy' );
			} catch ( e ) {
				ok = false;
			}
			say( ok ? ( text.copied || 'Copied' ) : ( text.copyFailed || 'Press Ctrl+C to copy' ) );
		}

		button.hidden = false;
		button.addEventListener( 'click', function () {
			if ( navigator.clipboard && window.isSecureContext ) {
				navigator.clipboard.writeText( input.value ).then( function () {
					say( text.copied || 'Copied' );
				}, fallbackCopy );
			} else {
				fallbackCopy();
			}
		} );
	} );
	Array.prototype.slice.call( document.querySelectorAll( '.paylumo-settings input[type="password"]' ) ).forEach( function ( input ) {
		var wrap = document.createElement( 'div' );
		var button = document.createElement( 'button' );

		wrap.className = 'paylumo-secret-wrap';
		button.type = 'button';
		button.className = 'button paylumo-reveal-button';
		button.textContent = text.show || 'Show';
		button.setAttribute( 'aria-controls', input.id );
		button.setAttribute( 'aria-pressed', 'false' );

		input.parentNode.insertBefore( wrap, input );
		wrap.appendChild( input );
		wrap.appendChild( button );

		button.addEventListener( 'click', function () {
			var show = 'password' === input.type;
			input.type = show ? 'text' : 'password';
			button.textContent = show ? ( text.hide || 'Hide' ) : ( text.show || 'Show' );
			button.setAttribute( 'aria-pressed', show ? 'true' : 'false' );
		} );
	} );

	var form = root.closest( 'form' );
	if ( form ) {
		form.addEventListener( 'submit', function () {
			Array.prototype.slice.call( form.querySelectorAll( '.paylumo-secret-wrap input' ) ).forEach( function ( input ) {
				input.type = 'password';
			} );
		} );
	}
}() );
