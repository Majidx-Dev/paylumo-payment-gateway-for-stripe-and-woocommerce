<?php

namespace Paylumo\StripeGateway;

defined( 'ABSPATH' ) || exit;

use WC_Order;
use WP_Error;

class Order_Guard {
	const GROUP = 'paylumo-payment-gateway-for-stripe-and-woocommerce';

	const BATCH_SIZE = 50;

	const CANCELLABLE_CREATED_VIA = array( 'checkout', 'store-api' );

	const SCHEDULE_CHECK_TRANSIENT = 'paylumo_cleanup_scheduled';

	private static $reverted_orders = array();

	public static function init() {
		add_filter( 'woocommerce_valid_order_statuses_for_payment_complete', array( __CLASS__, 'filter_payment_complete_statuses' ), 1000, 2 );
		add_filter( 'woocommerce_rest_pre_insert_shop_order_object', array( __CLASS__, 'filter_rest_pre_insert' ), 999, 2 );
		add_action( 'woocommerce_before_order_object_save', array( __CLASS__, 'block_unpaid_paid_status' ), 999 );
		add_filter( 'woocommerce_email_enabled_customer_failed_order', array( __CLASS__, 'filter_reverted_order_email' ), 999, 2 );
		add_filter( 'woocommerce_email_enabled_failed_order', array( __CLASS__, 'filter_reverted_order_email' ), 999, 2 );
		add_action( 'woocommerce_order_status_changed', array( __CLASS__, 'forget_reverted_order' ), PHP_INT_MAX );
		add_action( PAYLUMO_CLEANUP_HOOK, array( __CLASS__, 'cancel_unpaid_orders' ) );
		add_filter( 'woocommerce_cancel_unpaid_order', array( __CLASS__, 'filter_core_unpaid_cancel' ), 999, 2 );
		add_action( 'admin_init', array( __CLASS__, 'schedule_cleanup' ) );
	}

	private static function has_verified_payment( WC_Order $order ) {
		return '' !== (string) $order->get_meta( '_paylumo_payment_intent_id' ) || '' !== (string) $order->get_meta( '_paylumo_review_payment_intent_id' );
	}

	private static function needs_guard( WC_Order $order ) {
		return 'paylumo' === $order->get_payment_method() && ! self::has_verified_payment( $order );
	}

	private static function blocked_status_change( WC_Order $order ) {
		if ( ! array_key_exists( 'status', $order->get_changes() ) ) {
			return null;
		}
		$paid_statuses = wc_get_is_paid_statuses();
		$new_status    = $order->get_status( 'edit' );
		$data          = $order->get_data();
		$old_status    = (string) $data['status'];
		if ( ! in_array( $new_status, $paid_statuses, true ) || in_array( $old_status, $paid_statuses, true ) ) {
			return null;
		}
		return self::needs_guard( $order ) ? array( $old_status, $new_status ) : null;
	}

	private static function blocked_method_switch( WC_Order $order ) {
		if ( ! $order->get_id() || ! array_key_exists( 'payment_method', $order->get_changes() ) || 'paylumo' !== $order->get_payment_method( 'edit' ) ) {
			return null;
		}
		$data       = $order->get_data();
		$old_method = (string) $data['payment_method'];
		if ( 'paylumo' === $old_method || ! in_array( $order->get_status( 'edit' ), wc_get_is_paid_statuses(), true ) || ! self::needs_guard( $order ) ) {
			return null;
		}
		return $old_method;
	}

	public static function filter_payment_complete_statuses( $statuses, $order = null ) {
		if ( ! $order instanceof WC_Order || ! self::needs_guard( $order ) ) {
			return $statuses;
		}
		Gateway::log( sprintf( 'order guard: order %d: blocked payment_complete() (no verified Stripe payment); user %d.', $order->get_id(), get_current_user_id() ), 'error', true );
		return array();
	}

	public static function filter_rest_pre_insert( $order, $request ) {
		if ( ! $order instanceof WC_Order ) {
			return $order;
		}
		$meta_data = isset( $request['meta_data'] ) && is_array( $request['meta_data'] ) ? $request['meta_data'] : array();
		$stored    = null;
		foreach ( $meta_data as $meta ) {
			$key     = is_array( $meta ) && isset( $meta['key'] ) ? (string) $meta['key'] : '';
			$meta_id = is_array( $meta ) && ! empty( $meta['id'] ) ? absint( $meta['id'] ) : 0;
			if ( null === $stored && ( 0 === stripos( $key, '_paylumo_' ) || $meta_id > 0 ) ) {
				$stored = $order->get_id() ? wc_get_order( $order->get_id() ) : false;
			}
			$stored_key = '';
			if ( $meta_id > 0 && $stored instanceof WC_Order ) {
				foreach ( $stored->get_meta_data() as $row ) {
					if ( (int) $row->id === $meta_id ) {
						$stored_key = (string) $row->key;
						break;
					}
				}
			}
			if ( 0 === stripos( $stored_key, '_paylumo_' ) && $stored_key !== $key ) {
				return new WP_Error( 'paylumo_protected_meta', __( 'Meta keys starting with _paylumo_ are managed by Paylumo Payment Gateway for Stripe and WooCommerce and cannot be changed through the REST API.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), array( 'status' => 400 ) );
			}
			if ( 0 !== stripos( $key, '_paylumo_' ) ) {
				continue;
			}
			$current = $stored instanceof WC_Order ? $stored->get_meta( $key ) : '';
			if ( ! array_key_exists( 'value', $meta ) || $meta['value'] != $current ) {
				return new WP_Error( 'paylumo_protected_meta', __( 'Meta keys starting with _paylumo_ are managed by Paylumo Payment Gateway for Stripe and WooCommerce and cannot be changed through the REST API.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), array( 'status' => 400 ) );
			}
		}
		$paid_statuses = wc_get_is_paid_statuses();
		$req_status  = isset( $request['status'] ) && is_string( $request['status'] ) ? \Automattic\WooCommerce\Utilities\OrderUtil::remove_status_prefix( $request['status'] ) : '';
		$status_paid = in_array( $req_status, $paid_statuses, true ) && ! in_array( $order->get_status( 'edit' ), $paid_statuses, true ) && self::needs_guard( $order );
		$wants_paid  = ! empty( $request['set_paid'] ) && self::needs_guard( $order );
		if ( $wants_paid || $status_paid || null !== self::blocked_status_change( $order ) ) {
			return new WP_Error( 'paylumo_unpaid_order', __( 'This order cannot be marked paid because Stripe has not confirmed a payment for it.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), array( 'status' => 400 ) );
		}
		if ( null !== self::blocked_method_switch( $order ) ) {
			return new WP_Error( 'paylumo_unpaid_order', __( 'This order cannot be marked paid because Stripe has not confirmed a payment for it.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), array( 'status' => 400 ) );
		}
		return $order;
	}

	public static function block_unpaid_paid_status( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$old_method = self::blocked_method_switch( $order );
		if ( null !== $old_method ) {
			$order->set_payment_method( $old_method );
			if ( $order->get_id() ) {
				$order->add_order_note( __( 'Blocked: the payment method of this paid order cannot be changed to Stripe because Stripe has not confirmed a payment for it.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
			}
			Gateway::log( sprintf( 'order guard: order %d: blocked payment method change to paylumo on a paid order (no verified Stripe payment); user %d.', $order->get_id(), get_current_user_id() ), 'error', true );
		}

		$change = self::blocked_status_change( $order );
		if ( null === $change ) {
			return;
		}
		list( $old_status, $new_status ) = $change;

		$original = $order->get_data();
		if ( $order->get_id() ) {
			self::$reverted_orders[ $order->get_id() ] = true;
		}
		$order->set_status( $old_status, false );
		$order->set_date_paid( $original['date_paid'] );
		$order->set_date_completed( $original['date_completed'] );

		if ( $order->get_id() ) {
			$note = sprintf( __( 'Blocked: the order cannot be set to %1$s because Stripe has not confirmed a payment for it. The status was kept. If the customer paid another way, change the payment method first.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), wc_get_order_status_name( $new_status ) );
			$order->add_order_note( $note );
		}

		Gateway::log( sprintf( 'order guard: order %d: blocked status change %s -> %s (no verified Stripe payment); user %d.', $order->get_id(), $old_status, $new_status, get_current_user_id() ), 'error', true );
	}

	public static function filter_reverted_order_email( $enabled, $object = null ) {
		if ( $object instanceof WC_Order && isset( self::$reverted_orders[ $object->get_id() ] ) ) {
			return false;
		}
		return $enabled;
	}

	public static function forget_reverted_order( $order_id ) {
		unset( self::$reverted_orders[ absint( $order_id ) ] );
	}

	public static function filter_core_unpaid_cancel( $cancel, $order = null ) {
		if ( $order instanceof WC_Order && 'paylumo' === $order->get_payment_method() ) {
			return false;
		}
		return $cancel;
	}

	public static function stripe_allows_cancel( WC_Order $order ) {
		$expired  = $order->get_meta( '_paylumo_expired_sessions' );
		$sessions = array_merge( array( (string) $order->get_meta( '_paylumo_session_id' ) ), is_array( $expired ) ? $expired : array() );
		$sessions = array_values( array_unique( array_filter( array_map( 'strval', $sessions ) ) ) );

		if ( empty( $sessions ) ) {
			return true;
		}

		$mode   = Gateway::get_order_mode( $order );
		$secret = Gateway::get_saved_key( $mode, 'secret' );
		if ( '' === $secret ) {
			Gateway::log( sprintf( 'order guard: order %d not cancelled: the %s secret key is missing, so Stripe could not be asked.', $order->get_id(), $mode ), 'warning', true );
			return false;
		}

		$api = new Stripe_API( $secret );
		foreach ( $sessions as $session_id ) {
			$session = $api->retrieve_checkout_session( $session_id );
			if ( is_wp_error( $session ) || ! is_array( $session ) ) {
				Gateway::log( sprintf( 'order guard: order %d not cancelled: could not check Checkout Session %s with Stripe (%s).', $order->get_id(), $session_id, is_wp_error( $session ) ? $session->get_error_code() : 'invalid' ), 'warning', true );
				return false;
			}
			$status         = isset( $session['status'] ) ? (string) $session['status'] : '';
			$payment_status = isset( $session['payment_status'] ) ? (string) $session['payment_status'] : '';
			if ( 'expired' !== $status || 'paid' === $payment_status ) {
				Gateway::log( sprintf( 'order guard: order %d not cancelled: Checkout Session %s has status "%s" and payment_status "%s" on Stripe.', $order->get_id(), $session_id, $status, $payment_status ), 'complete' === $status ? 'error' : 'info', 'complete' === $status );
				return false;
			}
		}

		return true;
	}

	public static function can_auto_cancel( WC_Order $order ) {
		return 'paylumo' === $order->get_payment_method()
			&& $order->has_status( 'pending' )
			&& ! $order->is_paid()
			&& ! self::has_verified_payment( $order )
			&& in_array( $order->get_created_via(), self::CANCELLABLE_CREATED_VIA, true );
	}

	public static function schedule_cleanup() {
		if ( get_transient( self::SCHEDULE_CHECK_TRANSIENT ) ) {
			return;
		}
		if ( ! function_exists( 'as_has_scheduled_action' ) || ! function_exists( 'as_schedule_recurring_action' ) ) {
			return;
		}
		if ( ! as_has_scheduled_action( PAYLUMO_CLEANUP_HOOK, array(), self::GROUP ) ) {
			$action_id = as_schedule_recurring_action( time() + 5 * MINUTE_IN_SECONDS, HOUR_IN_SECONDS, PAYLUMO_CLEANUP_HOOK, array(), self::GROUP, true );
			if ( ! $action_id ) {
				return;
			}
		}
		set_transient( self::SCHEDULE_CHECK_TRANSIENT, 1, DAY_IN_SECONDS );
	}

	public static function cancel_unpaid_orders() {
		$cutoff = time() - PAYLUMO_UNPAID_ORDER_TIMEOUT_MINUTES * MINUTE_IN_SECONDS;

		$order_ids = wc_get_orders(
			array(
				'status'         => array( 'pending' ),
				'payment_method' => 'paylumo',
				'created_via'    => self::CANCELLABLE_CREATED_VIA,
				'date_modified'  => '<' . $cutoff,
				'meta_query'     => array(
					'relation' => 'AND',
					array(
						'key'     => '_paylumo_review_payment_intent_id',
						'compare' => 'NOT EXISTS',
					),
					array(
						'key'     => '_paylumo_payment_intent_id',
						'compare' => 'NOT EXISTS',
					),
				),
				'limit'          => self::BATCH_SIZE,
				'orderby'        => 'date',
				'order'          => 'ASC',
				'return'         => 'ids',
			)
		);

		$cancelled = 0;
		foreach ( $order_ids as $order_id ) {
			$lock = Webhook::acquire_order_lock( $order_id );
			if ( '' === $lock ) {
				continue;
			}
			try {
				if ( self::cancel_if_stale( $order_id, $cutoff ) ) {
					++$cancelled;
				}
			} finally {
				Webhook::release_order_lock( $order_id, $lock );
			}
		}

		if ( $cancelled > 0 ) {
			Gateway::log( sprintf( 'order guard: cancelled %d unpaid order(s) older than %d minutes.', $cancelled, PAYLUMO_UNPAID_ORDER_TIMEOUT_MINUTES ), 'info' );
		}
	}

	private static function cancel_if_stale( $order_id, $cutoff ) {
		$order = wc_get_order( $order_id );
		if ( ! $order instanceof WC_Order || ! self::can_auto_cancel( $order ) ) {
			return false;
		}
		$modified = $order->get_date_modified();
		if ( $modified && $modified->getTimestamp() >= $cutoff ) {
			return false;
		}
		if ( ! self::stripe_allows_cancel( $order ) ) {
			return false;
		}
		$note = sprintf( __( 'Order cancelled automatically: no Stripe payment was confirmed within %d minutes.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), PAYLUMO_UNPAID_ORDER_TIMEOUT_MINUTES );
		return (bool) $order->update_status( 'cancelled', $note );
	}
}
