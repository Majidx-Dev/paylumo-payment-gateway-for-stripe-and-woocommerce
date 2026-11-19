<?php

namespace Paylumo\StripeGateway;

defined( 'ABSPATH' ) || exit;

use Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType;

final class Blocks_Support extends AbstractPaymentMethodType {
	protected $name = 'paylumo';

	private const SCRIPT_HANDLE = 'paylumo-blocks';

	public function initialize() {
		$settings       = get_option( 'woocommerce_paylumo_settings', array() );
		$this->settings = is_array( $settings ) ? $settings : array();
	}

	public function is_active() {
		$gateway = $this->get_gateway();

		return null !== $gateway && $gateway->is_available();
	}

	public function get_payment_method_script_handles() {
		if ( ! wp_script_is( self::SCRIPT_HANDLE, 'registered' ) ) {
			wp_register_script(
				self::SCRIPT_HANDLE,
				PAYLUMO_PLUGIN_URL . 'assets/js/blocks.js',
				array( 'wc-blocks-registry', 'wc-settings', 'wp-element', 'wp-html-entities', 'wp-i18n' ),
				PAYLUMO_VERSION,
				true
			);
			wp_set_script_translations( self::SCRIPT_HANDLE, 'paylumo-payment-gateway-for-stripe-and-woocommerce', PAYLUMO_PLUGIN_DIR . 'languages' );
		}

		return array( self::SCRIPT_HANDLE );
	}

	public function get_supported_features() {
		$gateway = $this->get_gateway();

		if ( null === $gateway ) {
			return parent::get_supported_features();
		}

		return array_values( array_filter( $gateway->supports, array( $gateway, 'supports' ) ) );
	}

	public function get_payment_method_data() {
		$gateway = $this->get_gateway();

		$title       = null !== $gateway ? $gateway->get_title() : $this->get_setting( 'title' );
		$description = null !== $gateway ? $gateway->get_description() : $this->get_setting( 'description' );

		return array(
			'title'       => self::to_plain_text( $title ),
			'description' => self::to_plain_text( $description ),
			'supports'    => $this->get_supported_features(),
		);
	}

	private function get_gateway() {
		if ( ! function_exists( 'WC' ) ) {
			return null;
		}

		$gateways = WC()->payment_gateways()->payment_gateways();

		if ( isset( $gateways['paylumo'] ) && $gateways['paylumo'] instanceof Gateway ) {
			return $gateways['paylumo'];
		}

		return null;
	}

	private static function to_plain_text( $value ) {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		return trim( wp_strip_all_tags( (string) $value ) );
	}
}
