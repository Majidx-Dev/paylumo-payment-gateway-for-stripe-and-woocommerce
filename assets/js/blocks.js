( function () {
	'use strict';

	var wc = window.wc;
	var wp = window.wp;

	if ( ! wc || ! wc.wcBlocksRegistry || ! wc.wcSettings || ! wp || ! wp.element || ! wp.htmlEntities || ! wp.i18n ) {
		return;
	}

	var registerPaymentMethod = wc.wcBlocksRegistry.registerPaymentMethod;
	var getSetting = wc.wcSettings.getSetting;
	var createElement = wp.element.createElement;
	var decodeEntities = wp.htmlEntities.decodeEntities;
	var __ = wp.i18n.__;

	var settings = getSetting( 'paylumo_data', {} );

	var title = decodeEntities( settings.title || __( 'Credit / Debit Card (Stripe)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
	var description = decodeEntities( settings.description || '' );

	var features = Array.isArray( settings.supports ) ? settings.supports : [ 'products' ];

	function Content() {
		return createElement( 'div', null, description );
	}

	function Label( props ) {
		var components = props && props.components;
		var PaymentMethodLabel = components && components.PaymentMethodLabel;

		if ( PaymentMethodLabel ) {
			return createElement( PaymentMethodLabel, { text: title } );
		}

		return createElement( 'span', null, title );
	}

	registerPaymentMethod( {
		name: 'paylumo',
		label: createElement( Label ),
		content: createElement( Content ),
		edit: createElement( Content ),
		canMakePayment: function () {
			return true;
		},
		ariaLabel: title,
		supports: {
			features: features
		}
	} );
} )();
