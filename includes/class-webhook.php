<?php

namespace Paylumo\StripeGateway;

defined( 'ABSPATH' ) || exit;

use WC_Order;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

class Webhook {
	const TOLERANCE = 300;

	const MAX_REMEMBERED_EVENTS = 20;

	const PROCESSED_EVENTS_META = '_paylumo_processed_events';

	const LOCK_PREFIX = 'paylumo_lock_order_';

	const LOCK_STALE_SECONDS = 60;

	const REJECTION_LOG_INTERVAL = 60;

	const CLOCK_SKEW_SECONDS = 60;

	const RECENT_ACTIVITY_SECONDS = 300;

	private static $held_lock = null;

	private static $shutdown_registered = false;

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_route' ) );
	}

	public static function register_route() {
		$routes = array(
			'/webhook'      => 'handle',
			'/webhook/test' => 'handle',
			'/webhook/live' => 'handle_live',
		);

		foreach ( $routes as $route => $callback ) {
			register_rest_route(
				'paylumo/v1',
				$route,
				array(
					'methods'             => 'POST',
					'callback'            => array( __CLASS__, $callback ),
					'permission_callback' => '__return_true',
				)
			);
		}
	}

	public static function handle_live( WP_REST_Request $request ) {
		return self::handle( $request, 'live' );
	}

	public static function handle( WP_REST_Request $request, $mode = 'test' ) {
		$mode = Gateway::normalize_mode( $mode );
		$raw = (string) $request->get_body();

		$header = $request->get_header( 'stripe_signature' );

		$secret = Gateway::get_saved_key( $mode, 'webhook' );

		if ( '' === $secret ) {
			self::log_rejection( $mode . ' webhook signing secret is missing or invalid in the gateway settings.' );
			return self::reject();
		}

		$verified = self::verify_signature( $raw, $header, $secret );

		if ( true !== $verified ) {
			self::log_rejection( 'signature check failed: ' . $verified );
			return self::reject();
		}

		self::log( 'webhook: signature verified.' );

		$event = json_decode( $raw, true );

		if ( ! self::is_valid_event( $event ) ) {
			self::log_rejection( 'body is not a valid Stripe event.' );
			return self::reject();
		}

		$event_id   = self::clean_id( $event['id'] );
		$event_type = self::clean_id( $event['type'] );

		$livemode = array_key_exists( 'livemode', $event ) ? $event['livemode'] : null;

		$expected_livemode = 'live' === $mode;

		if ( $expected_livemode !== $livemode ) {
			Gateway::log( sprintf( 'webhook: event %s (%s) does not match the %s webhook URL (livemode is %s). It was NOT processed and no order was changed.', $event_id, $event_type, $mode, wp_json_encode( $livemode ) ), 'error', true );
			return self::reject();
		}

		self::log( sprintf( 'webhook: event %s (%s) accepted for processing.', $event_id, $event_type ) );

		$object = $event['data']['object'];

		switch ( $event_type ) {
			case 'checkout.session.completed':
			case 'checkout.session.async_payment_succeeded':
				$result = self::handle_session_completed( $object, $event_id, $mode );
				if ( is_wp_error( $result ) ) {
					return $result;
				}
				break;
			case 'checkout.session.expired':
				self::handle_session_expired( $object, $event_id, $mode );
				break;
			case 'checkout.session.async_payment_failed':
				self::handle_async_payment_failed( $object, $event_id, $mode );
				break;
			case 'charge.refunded':
				self::handle_charge_refunded( $object, $event_id, $mode );
				break;
			default:
				self::log( sprintf( 'webhook: event %s of type %s ignored.', $event_id, $event_type ) );
				break;
		}

		return new WP_REST_Response( array( 'received' => true ), 200 );
	}

	public static function verify_signature( $raw_body, $header, $secret ) {
		if ( ! is_string( $secret ) || '' === $secret ) {
			return 'webhook signing secret is empty';
		}

		if ( ! is_string( $header ) || '' === trim( $header ) ) {
			return 'missing Stripe-Signature header';
		}

		$timestamp  = null;
		$signatures = array();

		foreach ( explode( ',', $header ) as $item ) {
			$parts = explode( '=', trim( $item ), 2 );

			if ( 2 !== count( $parts ) ) {
				continue;
			}

			if ( 't' === $parts[0] && null === $timestamp ) {
				$timestamp = $parts[1];
			} elseif ( 'v1' === $parts[0] && '' !== $parts[1] ) {
				$signatures[] = $parts[1];
			}
		}

		if ( null === $timestamp || 1 !== preg_match( '/^\d{1,12}\z/', $timestamp ) ) {
			return 'malformed header: no valid timestamp';
		}

		if ( empty( $signatures ) ) {
			return 'malformed header: no v1 signature';
		}

		if ( abs( time() - (int) $timestamp ) > self::TOLERANCE ) {
			return 'timestamp outside the tolerance window';
		}

		$signed_payload = $timestamp . '.' . $raw_body;
		$expected       = hash_hmac( 'sha256', $signed_payload, $secret );

		foreach ( $signatures as $signature ) {
			if ( hash_equals( $expected, $signature ) ) {
				return true;
			}
		}

		return 'no v1 signature matched';
	}

	private static function handle_session_completed( array $session, $event_id, $mode ) {
		$session_id     = self::clean_id( $session['id'] ?? '' );
		$payment_status = self::clean_id( $session['payment_status'] ?? '' );

		$order_id = absint( $session['metadata']['order_id'] ?? 0 );

		if ( 'paid' !== $payment_status ) {
			self::log( sprintf( 'webhook: %s: session %s has payment_status "%s"; not marked paid (an async payment waits for checkout.session.async_payment_succeeded).', $event_id, $session_id, $payment_status ) );
			if ( 'unpaid' !== $payment_status || 0 === $order_id ) {
				return true;
			}
			return self::run_locked( $order_id, $event_id, static function () use ( $session, $event_id, $order_id, $session_id, $mode ) {
				self::mark_awaiting_async_payment( $session, $event_id, $order_id, $session_id, $mode );
			} );
		}

		$payment_intent_id = self::get_payment_intent_id( $session );

		if ( 0 === $order_id ) {
			self::report_missing_order( $order_id, $payment_intent_id, $event_id );
			return true;
		}

		return self::run_locked( $order_id, $event_id, static function () use ( $session, $event_id, $order_id, $session_id, $payment_intent_id, $mode ) {
			self::process_paid_session( $session, $event_id, $order_id, $session_id, $payment_intent_id, $mode );
		} );
	}

	private static function run_locked( $order_id, $event_id, callable $work ) {
		$lock = self::acquire_order_lock( $order_id );

		if ( '' === $lock ) {
			Gateway::log( sprintf( 'webhook: %s: order %d is locked by another request (or the lock row could not be written); returning 409 so Stripe retries later.', $event_id, $order_id ), 'warning', true );
			return new WP_Error( 'paylumo_webhook_busy', 'Webhook busy, retry later.', array( 'status' => 409 ) );
		}

		self::hold_lock( $order_id, $lock );

		try {
			$work();
		} finally {
			self::release_order_lock( $order_id, $lock );
		}

		return true;
	}

	private static function mark_awaiting_async_payment( array $session, $event_id, $order_id, $session_id, $mode ) {
		$order = wc_get_order( $order_id );
		if ( ! $order instanceof WC_Order || 'paylumo' !== $order->get_payment_method() || Gateway::get_order_mode( $order ) !== $mode ) {
			return;
		}
		if ( self::already_processed( $order, $event_id ) || $order->is_paid() || ! $order->has_status( 'pending' ) ) {
			return;
		}
		if ( '' === $session_id ) {
			return;
		}
		self::remember_event( $order, $event_id );
		$note = sprintf( __( 'The customer started a delayed payment with Stripe Checkout Session %s. The order will be marked paid when Stripe confirms the payment.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $session_id );
		if ( (string) $order->get_meta( '_paylumo_session_id' ) !== $session_id ) {
			$note .= ' ' . __( 'This is an older session than the one saved on the order; if both are paid, the order goes to MANUAL REVIEW.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
		}
		$order->update_status( 'on-hold', $note );
		self::log( sprintf( 'webhook: %s: order %d set on-hold while the async payment for session %s is pending.', $event_id, $order->get_id(), $session_id ) );
	}

	private static function process_paid_session( array $session, $event_id, $order_id, $session_id, $payment_intent_id, $mode ) {
		$order = wc_get_order( $order_id );

		if ( ! $order instanceof WC_Order ) {
			self::report_missing_order( $order_id, $payment_intent_id, $event_id );
			return;
		}

		if ( self::already_processed( $order, $event_id ) ) {
			self::log( sprintf( 'webhook: %s already processed for order %d; skipped.', $event_id, $order->get_id() ) );
			return;
		}

		$order_mode = Gateway::get_order_mode( $order );
		if ( $order_mode !== $mode ) {
			$reason = sprintf( __( 'Mode mismatch: the payment was made in %1$s mode but the order was created in %2$s mode.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $mode, $order_mode );
			self::manual_review( $order, $reason, $payment_intent_id, $event_id, false );
			return;
		}

		$expected_session_id = (string) $order->get_meta( '_paylumo_session_id' );
		$payment_method      = (string) $order->get_payment_method();

		if ( $order->is_paid() ) {
			$stored_intent = (string) $order->get_meta( '_paylumo_payment_intent_id' );

			$same_payment = 'paylumo' === $payment_method && '' !== $payment_intent_id && ( $stored_intent === $payment_intent_id || (string) $order->get_transaction_id() === $payment_intent_id );

			if ( $same_payment ) {
				self::remember_event( $order, $event_id );
				$order->save();
				self::log( sprintf( 'webhook: %s: order %d is already paid by this same payment intent; duplicate ignored.', $event_id, $order->get_id() ) );
				return;
			}

			$reason = sprintf( __( 'The order is already paid by another payment; possible double payment. Checkout Session: %1$s. Order payment method: %2$s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $session_id, '' !== $payment_method ? self::clean_id( $payment_method ) : '-' );
			self::manual_review( $order, $reason, $payment_intent_id, $event_id );
			return;
		}

		if ( '' === $session_id || $session_id !== $expected_session_id ) {
			$expected_text = '' !== $expected_session_id ? $expected_session_id : '-';
			$reason = sprintf( __( 'Checkout Session ID mismatch: the order expects %1$s but Stripe sent %2$s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $expected_text, $session_id );
			self::manual_review( $order, $reason, $payment_intent_id, $event_id );
			return;
		}

		if ( 'paylumo' !== $payment_method ) {
			$reason = sprintf( __( 'The order payment method is "%s", not Stripe, so it was not marked paid automatically. The customer may have paid twice.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), '' !== $payment_method ? self::clean_id( $payment_method ) : '-' );
			self::manual_review( $order, $reason, $payment_intent_id, $event_id );
			return;
		}

		if ( '' === $payment_intent_id ) {
			self::manual_review( $order, __( 'Stripe did not send a payment intent ID for this paid Checkout Session.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), '', $event_id );
			return;
		}

		$expected_amount   = Gateway::get_stripe_amount( $order->get_total(), $order->get_currency() );
		$received_amount   = (int) ( $session['amount_total'] ?? 0 );
		$expected_currency = strtolower( (string) $order->get_currency() );
		$received_currency = strtolower( self::clean_id( $session['currency'] ?? '' ) );

		if ( $received_amount !== $expected_amount || $received_currency !== $expected_currency ) {
			$reason = sprintf( __( 'Amount or currency mismatch: the order expects %1$d %2$s (minor units) but Stripe charged %3$d %4$s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $expected_amount, strtoupper( $expected_currency ), $received_amount, strtoupper( $received_currency ) );
			self::manual_review( $order, $reason, $payment_intent_id, $event_id );
			return;
		}

		if ( ! $order->has_status( array( 'pending', 'failed', 'on-hold' ) ) ) {
			$reason = sprintf( __( 'The order status is "%s", so it was not marked paid automatically.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $order->get_status() );
			self::manual_review( $order, $reason, $payment_intent_id, $event_id );
			return;
		}

		$order->update_meta_data( '_paylumo_payment_intent_id', $payment_intent_id );
		self::remember_event( $order, $event_id );

		$completed = $order->payment_complete( $payment_intent_id );

		if ( ! $completed || ! $order->is_paid() ) {
			$reason = __( 'WooCommerce could not mark the order paid (payment_complete() did not complete).', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			self::manual_review( $order, $reason, $payment_intent_id, $event_id );
			return;
		}

		$note = sprintf( __( 'Stripe payment confirmed by a verified webhook. Payment intent: %1$s. Checkout Session: %2$s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $payment_intent_id, $session_id );
		$order->add_order_note( $note );
		self::log( sprintf( 'webhook: %s: order %d marked paid (payment intent %s).', $event_id, $order->get_id(), $payment_intent_id ) );
	}

	private static function report_missing_order( $order_id, $payment_intent_id, $event_id ) {
		$reason = sprintf( __( 'A paid Checkout Session points to an order that was not found (order ID from metadata: %d).', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $order_id );
		self::manual_review( null, $reason, $payment_intent_id, $event_id );
	}

	private static function handle_session_expired( array $session, $event_id, $mode ) {
		$session_id = self::clean_id( $session['id'] ?? '' );
		$order      = wc_get_order( absint( $session['metadata']['order_id'] ?? 0 ) );

		if ( ! $order instanceof WC_Order ) {
			self::log( sprintf( 'webhook: %s: expired session %s has no matching order; ignored.', $event_id, $session_id ) );
			return;
		}

		if ( 'paylumo' !== $order->get_payment_method() ) {
			self::log( sprintf( 'webhook: %s: order %d payment method is not paylumo; expired session %s ignored.', $event_id, $order->get_id(), $session_id ) );
			return;
		}

		if ( Gateway::get_order_mode( $order ) !== $mode ) {
			self::log( sprintf( 'webhook: %s: order %d was created in another mode; %s-mode expired session %s ignored.', $event_id, $order->get_id(), $mode, $session_id ) );
			return;
		}

		if ( self::already_processed( $order, $event_id ) ) {
			self::log( sprintf( 'webhook: %s already processed for order %d; skipped.', $event_id, $order->get_id() ) );
			return;
		}

		if ( $order->is_paid() ) {
			self::log( sprintf( 'webhook: %s: order %d is already paid; expired session %s ignored.', $event_id, $order->get_id(), $session_id ) );
			return;
		}

		$note            = sprintf( __( 'Stripe Checkout Session %s expired; the customer did not pay with it.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $session_id );
		$current_session = (string) $order->get_meta( '_paylumo_session_id' );

		if ( '' !== $current_session && $current_session !== $session_id ) {
			$note .= ' ' . sprintf( __( 'This was an older session; the order\'s current session is %s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $current_session );
		}

		if ( self::should_cancel_on_expiry( $order, $session, $session_id ) ) {
			$lock = self::acquire_order_lock( $order->get_id() );
			if ( '' !== $lock ) {
				try {
					$fresh = wc_get_order( $order->get_id() );
					if ( $fresh instanceof WC_Order && self::should_cancel_on_expiry( $fresh, $session, $session_id ) && Order_Guard::stripe_allows_cancel( $fresh ) ) {
						self::remember_event( $fresh, $event_id );
						$fresh->update_status( 'cancelled', $note . ' ' . __( 'The order was cancelled because it was not paid.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
						self::log( sprintf( 'webhook: %s: order %d cancelled after Checkout Session %s expired unpaid.', $event_id, $fresh->get_id(), $session_id ) );
						return;
					}
				} finally {
					self::release_order_lock( $order->get_id(), $lock );
				}
			}
		}
		$order = wc_get_order( $order->get_id() );
		if ( ! $order instanceof WC_Order || $order->is_paid() || self::already_processed( $order, $event_id ) ) {
			return;
		}
		self::remember_event( $order, $event_id );
		$order->add_order_note( $note );
		$order->save();
		self::log( sprintf( 'webhook: %s: expiry note added to order %d.', $event_id, $order->get_id() ) );
	}

	private static function should_cancel_on_expiry( WC_Order $order, array $session, $session_id ) {
		if ( ! Order_Guard::can_auto_cancel( $order ) ) {
			return false;
		}
		if ( '' === $session_id || (string) $order->get_meta( '_paylumo_session_id' ) !== $session_id ) {
			return false;
		}
		$expires_at = absint( $session['expires_at'] ?? 0 );
		if ( 0 === $expires_at || time() < $expires_at - self::CLOCK_SKEW_SECONDS ) {
			return false;
		}
		$modified = $order->get_date_modified();
		if ( $modified && time() - $modified->getTimestamp() < self::RECENT_ACTIVITY_SECONDS ) {
			return false;
		}
		return true;
	}

	private static function handle_async_payment_failed( array $session, $event_id, $mode ) {
		$session_id = self::clean_id( $session['id'] ?? '' );
		$order      = wc_get_order( absint( $session['metadata']['order_id'] ?? 0 ) );

		if ( ! $order instanceof WC_Order ) {
			self::log( sprintf( 'webhook: %s: failed async session %s has no matching order; ignored.', $event_id, $session_id ) );
			return;
		}

		if ( 'paylumo' !== $order->get_payment_method() ) {
			self::log( sprintf( 'webhook: %s: order %d payment method is not paylumo; failed async session %s ignored.', $event_id, $order->get_id(), $session_id ) );
			return;
		}

		if ( Gateway::get_order_mode( $order ) !== $mode ) {
			self::log( sprintf( 'webhook: %s: order %d was created in another mode; %s-mode failed async session %s ignored.', $event_id, $order->get_id(), $mode, $session_id ) );
			return;
		}

		if ( self::already_processed( $order, $event_id ) ) {
			self::log( sprintf( 'webhook: %s already processed for order %d; skipped.', $event_id, $order->get_id() ) );
			return;
		}

		if ( $order->is_paid() ) {
			self::log( sprintf( 'webhook: %s: order %d is already paid; failed async session %s ignored.', $event_id, $order->get_id(), $session_id ) );
			return;
		}

		$note            = sprintf( __( 'Stripe could not collect the delayed payment for Checkout Session %s; no money was received.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $session_id );
		$current_session = (string) $order->get_meta( '_paylumo_session_id' );
		$is_current      = '' !== $session_id && $current_session === $session_id;

		self::remember_event( $order, $event_id );

		if ( $is_current && $order->has_status( array( 'pending', 'on-hold' ) ) ) {
			$order->update_status( 'failed', $note );
		} else {
			$order->add_order_note( $note );
			$order->save();
		}

		self::log( sprintf( 'webhook: %s: order %d: async payment failed for session %s (status %s).', $event_id, $order->get_id(), $session_id, $order->get_status() ) );
	}

	private static function handle_charge_refunded( array $charge, $event_id, $mode ) {
		$charge_id         = self::clean_id( $charge['id'] ?? '' );
		$payment_intent_id = self::get_payment_intent_id( $charge );
		$order             = self::find_order_for_charge( $charge, $payment_intent_id );

		if ( ! $order instanceof WC_Order ) {
			self::log( sprintf( 'webhook: %s: no order found for refunded charge %s; ignored.', $event_id, $charge_id ) );
			return;
		}

		if ( Gateway::get_order_mode( $order ) !== $mode ) {
			self::log( sprintf( 'webhook: %s: order %d was created in another mode; %s-mode refund of charge %s ignored.', $event_id, $order->get_id(), $mode, $charge_id ) );
			return;
		}

		if ( self::already_processed( $order, $event_id ) ) {
			self::log( sprintf( 'webhook: %s already processed for order %d; skipped.', $event_id, $order->get_id() ) );
			return;
		}

		$amount_refunded = (int) ( $charge['amount_refunded'] ?? 0 );
		$currency        = strtoupper( self::clean_id( $charge['currency'] ?? '' ) );

		$note = sprintf( __( 'Stripe reports that charge %1$s was refunded. Total refunded so far: %2$d %3$s (minor units). No WooCommerce refund was created by this webhook. Event: %4$s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $charge_id, $amount_refunded, $currency, $event_id );
		$order->add_order_note( $note );
		self::remember_event( $order, $event_id );
		$order->save();
		self::log( sprintf( 'webhook: %s: refund note added to order %d for charge %s.', $event_id, $order->get_id(), $charge_id ) );
	}

	private static function find_order_for_charge( array $charge, $payment_intent_id ) {
		$order = wc_get_order( absint( $charge['metadata']['order_id'] ?? 0 ) );

		if ( $order instanceof WC_Order && 'paylumo' === $order->get_payment_method() ) {
			$stored_intent = (string) $order->get_meta( '_paylumo_payment_intent_id' );

			if ( '' === $stored_intent || $stored_intent === $payment_intent_id ) {
				return $order;
			}
		}

		if ( '' === $payment_intent_id ) {
			return null;
		}

		$orders = wc_get_orders(
			array(
				'limit'          => 1,
				'payment_method' => 'paylumo',
				'meta_key'       => '_paylumo_payment_intent_id',
				'meta_value'     => $payment_intent_id,
				'return'         => 'objects',
			)
		);

		$order = is_array( $orders ) ? reset( $orders ) : false;

		return ( $order instanceof WC_Order && 'paylumo' === $order->get_payment_method() ) ? $order : null;
	}

	private static function manual_review( $order, $reason, $payment_intent_id, $event_id, $unlocks_manual_paid = true ) {
		$intent_text = '' !== $payment_intent_id ? $payment_intent_id : '-';

		$details = sprintf( __( '%1$s Payment intent: %2$s. Event: %3$s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $reason, $intent_text, $event_id );

		if ( $order instanceof WC_Order ) {
			$order->add_order_note( 'MANUAL REVIEW: ' . $details );
			if ( '' !== $payment_intent_id && $unlocks_manual_paid ) {
				$order->update_meta_data( '_paylumo_review_payment_intent_id', $payment_intent_id );
			}
			self::remember_event( $order, $event_id );
			$order->save();
		}

		$order_text = $order instanceof WC_Order ? (string) $order->get_id() : 'none';

		Gateway::log( sprintf( 'MANUAL REVIEW: order %s: %s', $order_text, $details ), 'error', true );
	}

	private static function already_processed( WC_Order $order, $event_id ) {
		return in_array( $event_id, self::get_processed_events( $order ), true );
	}

	private static function remember_event( WC_Order $order, $event_id ) {
		$events = self::get_processed_events( $order );

		if ( ! in_array( $event_id, $events, true ) ) {
			$events[] = $event_id;
		}

		$events = array_slice( $events, -self::MAX_REMEMBERED_EVENTS );

		$order->update_meta_data( self::PROCESSED_EVENTS_META, array_values( $events ) );
	}

	private static function get_processed_events( WC_Order $order ) {
		$events = $order->get_meta( self::PROCESSED_EVENTS_META );

		if ( ! is_array( $events ) ) {
			return array();
		}

		return array_values( array_filter( $events, 'is_string' ) );
	}

	private static function get_payment_intent_id( array $stripe_object ) {
		$value = $stripe_object['payment_intent'] ?? '';

		if ( is_array( $value ) ) {
			$value = $value['id'] ?? '';
		}

		return self::clean_id( $value );
	}

	private static function is_valid_event( $event ) {
		return is_array( $event )
			&& isset( $event['id'], $event['type'] ) && is_string( $event['id'] ) && is_string( $event['type'] )
			&& '' !== $event['id'] && '' !== $event['type']
			&& isset( $event['data']['object'] ) && is_array( $event['data']['object'] );
	}

	private static function clean_id( $value ) {
		if ( ! is_string( $value ) && ! is_int( $value ) ) {
			return '';
		}

		return substr( sanitize_text_field( (string) $value ), 0, 255 );
	}

	private static function reject() {
		return new WP_Error( 'paylumo_webhook_rejected', 'Webhook rejected.', array( 'status' => 400 ) );
	}

	private static function log_rejection( $reason ) {
		if ( ! Gateway::is_debug_enabled() ) {
			return;
		}

		$transient = 'paylumo_webhook_rejlog_' . md5( $reason );

		if ( false !== get_transient( $transient ) ) {
			return;
		}

		set_transient( $transient, time(), self::REJECTION_LOG_INTERVAL );
		self::log( 'webhook: rejected: ' . $reason, 'error' );
	}

	public static function acquire_order_lock( $order_id ) {
		global $wpdb;

		$name  = self::LOCK_PREFIX . absint( $order_id );
		$token = time() . '|' . wp_generate_uuid4();

		for ( $attempt = 1; $attempt <= 2; $attempt++ ) {
			$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO `{$wpdb->options}` (`option_name`, `option_value`, `autoload`) VALUES (%s, %s, 'off')", $name, $token ) );

			if ( 0 < (int) $inserted ) {
				return $token;
			}

			if ( 2 === $attempt ) {
				break;
			}

			$current = $wpdb->get_var( $wpdb->prepare( "SELECT `option_value` FROM `{$wpdb->options}` WHERE `option_name` = %s LIMIT 1", $name ) );

			if ( null === $current ) {
				continue;
			}

			$locked_at = (int) explode( '|', (string) $current, 2 )[0];

			if ( abs( time() - $locked_at ) < self::LOCK_STALE_SECONDS ) {
				return '';
			}

			$wpdb->query( $wpdb->prepare( "DELETE FROM `{$wpdb->options}` WHERE `option_name` = %s AND `option_value` = %s", $name, $current ) );
		}

		return '';
	}

	public static function release_order_lock( $order_id, $token ) {
		global $wpdb;

		$name = self::LOCK_PREFIX . absint( $order_id );
		$wpdb->query( $wpdb->prepare( "DELETE FROM `{$wpdb->options}` WHERE `option_name` = %s AND `option_value` = %s", $name, $token ) );

		if ( is_array( self::$held_lock ) && self::$held_lock['token'] === $token ) {
			self::$held_lock = null;
		}
	}

	private static function hold_lock( $order_id, $token ) {
		self::$held_lock = array(
			'order_id' => absint( $order_id ),
			'token'    => (string) $token,
		);

		if ( ! self::$shutdown_registered ) {
			register_shutdown_function( array( __CLASS__, 'release_held_lock_on_shutdown' ) );
			self::$shutdown_registered = true;
		}
	}

	public static function release_held_lock_on_shutdown() {
		if ( ! is_array( self::$held_lock ) || ! isset( $GLOBALS['wpdb'] ) ) {
			return;
		}

		self::release_order_lock( self::$held_lock['order_id'], self::$held_lock['token'] );
	}

	private static function log( $message, $level = 'info' ) {
		Gateway::log( $message, $level );
	}
}
