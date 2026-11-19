<?php

namespace Paylumo\StripeGateway;

defined( 'ABSPATH' ) || exit;

use WP_Error;

class Stripe_API {
	const BASE_URL = 'https://api.stripe.com/v1/';

	const DEFAULT_TIMEOUT = 30;

	private $secret_key;

	public function __construct( $secret_key ) {
		$this->secret_key = (string) $secret_key;
	}

	public function create_checkout_session( array $params, $idempotency_key ) {
		return $this->request( 'POST', 'checkout/sessions', $params, $idempotency_key );
	}

	public function create_refund( array $params, $idempotency_key ) {
		return $this->request( 'POST', 'refunds', $params, $idempotency_key );
	}

	public function expire_checkout_session( $session_id ) {
		$session_id = (string) $session_id;

		if ( 1 !== preg_match( '/^cs_(?:test_|live_)?[A-Za-z0-9]+\z/', $session_id ) ) {
			return new WP_Error( 'paylumo_session_id', 'Invalid Checkout Session id; expire request not sent.' );
		}

		return $this->request( 'POST', 'checkout/sessions/' . $session_id . '/expire' );
	}

	public function retrieve_checkout_session( $session_id ) {
		$session_id = (string) $session_id;

		if ( 1 !== preg_match( '/^cs_(?:test_|live_)?[A-Za-z0-9]+\z/', $session_id ) ) {
			return new WP_Error( 'paylumo_session_id', 'Invalid Checkout Session id; retrieve request not sent.' );
		}

		return $this->request( 'GET', 'checkout/sessions/' . $session_id );
	}

	public function check_access() {
		$checks = array(
			array( 'GET', 'checkout/sessions?limit=1', array(), 'Checkout Sessions' ),
			array( 'GET', 'refunds?limit=1', array(), 'Refunds' ),
			array( 'POST', 'checkout/sessions', array( 'mode' => 'paylumo_access_check' ), 'Checkout Sessions (Write)' ),
			array( 'POST', 'refunds', array(), 'Refunds (Write)' ),
		);

		foreach ( $checks as $check ) {
			list( $method, $path, $body, $resource ) = $check;
			$result = $this->request( $method, $path, $body );
			if ( 'POST' === $method && self::is_validation_error( $result ) ) {
				continue;
			}
			if ( is_wp_error( $result ) ) {
				$data = $result->get_error_data();
				$data = is_array( $data ) ? $data : array();
				$data['paylumo_resource'] = $resource;
				return new WP_Error( $result->get_error_code(), $result->get_error_message(), $data );
			}
		}

		return true;
	}

	private static function is_validation_error( $result ) {
		if ( ! is_wp_error( $result ) || 'paylumo_api' !== $result->get_error_code() ) {
			return false;
		}
		$data = $result->get_error_data();
		return is_array( $data ) && 400 === ( $data['status'] ?? 0 ) && 'invalid_request_error' === ( $data['type'] ?? '' );
	}

	private function request( $method, $path, $body = array(), $idempotency_key = '' ) {
		$headers = array(
			'Authorization'  => 'Bearer ' . $this->secret_key,
			'Stripe-Version' => PAYLUMO_STRIPE_API_VERSION,
			'Content-Type'   => 'application/x-www-form-urlencoded',
		);

		if ( '' !== (string) $idempotency_key ) {
			$headers['Idempotency-Key'] = (string) $idempotency_key;
		}

		$args = array(
			'method'  => $method,
			'headers' => $headers,
			'timeout' => self::DEFAULT_TIMEOUT,
		);

		if ( ! empty( $body ) ) {
			$args['body'] = http_build_query( $body, '', '&' );
		}

		$response = wp_remote_request( self::BASE_URL . $path, $args );

		if ( is_wp_error( $response ) ) {
			Gateway::log( sprintf( 'Stripe %s %s failed: transport error: %s', $method, $path, self::redact( $response->get_error_message() ) ), 'error' );
			return new WP_Error(
				'paylumo_http',
				self::redact( $response->get_error_message() ),
				array( 'transport_code' => $response->get_error_code() )
			);
		}

		$status     = (int) wp_remote_retrieve_response_code( $response );
		$request_id = wp_remote_retrieve_header( $response, 'request-id' );
		$request_id = is_string( $request_id ) ? $request_id : '';
		$data       = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $status < 200 || $status >= 300 ) {
			$error         = ( is_array( $data ) && isset( $data['error'] ) && is_array( $data['error'] ) ) ? $data['error'] : array();
			$error_type    = isset( $error['type'] ) ? (string) $error['type'] : '';
			$error_code    = isset( $error['code'] ) ? (string) $error['code'] : '';
			$error_message = isset( $error['message'] ) ? self::redact( (string) $error['message'] ) : '';

			Gateway::log( sprintf( 'Stripe %s %s failed: HTTP %d, request-id %s, %s: %s', $method, $path, $status, $request_id, $error_type, $error_message ), 'error' );

			return new WP_Error(
				'paylumo_api',
				$error_message,
				array(
					'status'     => $status,
					'type'       => $error_type,
					'code'       => $error_code,
					'request_id' => $request_id,
				)
			);
		}

		if ( ! is_array( $data ) ) {
			Gateway::log( sprintf( 'Stripe %s %s failed: HTTP %d, request-id %s, invalid JSON response', $method, $path, $status, $request_id ), 'error' );
			return new WP_Error(
				'paylumo_json',
				'Invalid JSON in Stripe response.',
				array(
					'status'     => $status,
					'request_id' => $request_id,
				)
			);
		}

		Gateway::log( sprintf( 'Stripe %s %s OK: HTTP %d, request-id %s', $method, $path, $status, $request_id ), 'info' );

		return $data;
	}

	private static function redact( $text ) {
		return (string) preg_replace( '/\b(?:(?:sk|pk|rk)_(?:test|live)_|whsec_)[A-Za-z0-9*]*/', '[redacted key]', (string) $text );
	}
}
