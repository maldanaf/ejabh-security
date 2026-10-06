/**
 * Ejabh Security — scan driver.
 *
 * Runs the scanner in a loop of short AJAX calls so a very large install can be
 * walked without ever hitting a PHP or gateway timeout.
 */
( function () {
	'use strict';

	var box = document.querySelector( '.ejabh-scanbox' );
	if ( ! box || 'undefined' === typeof window.ejabhSec ) {
		return;
	}

	var kind      = box.getAttribute( 'data-kind' );
	var startBtn  = box.querySelector( '.ejabh-scan-start' );
	var cancelBtn = box.querySelector( '.ejabh-scan-cancel' );
	var spinner   = box.querySelector( '.ejabh-spinner' );
	var progress  = box.querySelector( '.ejabh-progress' );
	var i18n      = window.ejabhSec.i18n;
	var aborted   = false;

	function setBusy( busy ) {
		startBtn.disabled  = busy;
		cancelBtn.disabled = ! busy;
		spinner.classList.toggle( 'is-active', busy );
	}

	function say( text ) {
		progress.textContent = text;
	}

	function request( op ) {
		var body = new URLSearchParams();
		body.append( 'action', 'dys_sec_scan' );
		body.append( '_ajax_nonce', window.ejabhSec.nonce );
		body.append( 'kind', kind );
		body.append( 'op', op );

		return fetch( window.ejabhSec.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		} ).then( function ( response ) {
			if ( ! response.ok ) {
				throw new Error( 'HTTP ' + response.status );
			}
			return response.json();
		} ).then( function ( payload ) {
			if ( ! payload || ! payload.success ) {
				throw new Error( ( payload && payload.data && payload.data.message ) || 'error' );
			}
			return payload.data;
		} );
	}

	function loop() {
		if ( aborted ) {
			return;
		}

		request( 'step' ).then( function ( data ) {
			say( data.progress );

			if ( data.done ) {
				setBusy( false );
				say( data.progress + ' ' + i18n.reload );
				window.location.reload();
				return;
			}

			if ( ! data.running ) {
				setBusy( false );
				say( i18n.cancelled );
				return;
			}

			// Yield to the browser so the UI stays responsive between batches.
			window.setTimeout( loop, 250 );
		} ).catch( function ( error ) {
			setBusy( false );
			say( i18n.failed + ' (' + error.message + ')' );
		} );
	}

	startBtn.addEventListener( 'click', function () {
		if ( ! window.confirm( i18n.confirm ) ) {
			return;
		}

		aborted = false;
		setBusy( true );
		say( i18n.starting );

		request( 'start' ).then( function ( data ) {
			say( data.progress || i18n.scanning );
			loop();
		} ).catch( function ( error ) {
			setBusy( false );
			say( i18n.failed + ' (' + error.message + ')' );
		} );
	} );

	cancelBtn.addEventListener( 'click', function () {
		aborted = true;
		request( 'cancel' ).then( function () {
			setBusy( false );
			say( i18n.cancelled );
		} ).catch( function () {
			setBusy( false );
			say( i18n.cancelled );
		} );
	} );
} )();
