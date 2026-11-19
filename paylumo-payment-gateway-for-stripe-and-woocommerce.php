<?php

/**
 * Plugin Name:          Paylumo Payment Gateway for Stripe and WooCommerce
 * Description:          A WooCommerce payment gateway for Stripe Checkout, with Test and Live mode.
 * Version:              1.0.0
 * Requires at least:    6.4
 * Requires PHP:         8.1
 * Requires Plugins:     woocommerce
 * WC requires at least: 8.0
 * Text Domain:          paylumo-payment-gateway-for-stripe-and-woocommerce
 * Domain Path:          /languages
 * License:              GPL-2.0-or-later
 * License URI:          https://www.gnu.org/licenses/gpl-2.0.html
 */

namespace Paylumo\StripeGateway;

defined( 'ABSPATH' ) || exit;

define( 'PAYLUMO_VERSION', '1.0.0' );
define( 'PAYLUMO_PLUGIN_FILE', __FILE__ );
define( 'PAYLUMO_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'PAYLUMO_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'PAYLUMO_STRIPE_API_VERSION', '2026-10-28.endive' );
define( 'PAYLUMO_LOG_SOURCE', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );

define( 'PAYLUMO_SESSION_EXPIRY_MINUTES', 31 );

define( 'PAYLUMO_UNPAID_ORDER_TIMEOUT_MINUTES', 60 );
define( 'PAYLUMO_CLEANUP_HOOK', 'paylumo_cancel_unpaid_orders' );

add_action( 'before_woocommerce_init', __NAMESPACE__ . '\\declare_wc_compatibility' );
add_action( 'plugins_loaded', __NAMESPACE__ . '\\init' );
add_action( 'init', __NAMESPACE__ . '\\load_textdomain' );
register_deactivation_hook( __FILE__, __NAMESPACE__ . '\\deactivate' );

function declare_wc_compatibility() {
	if ( ! class_exists( \Automattic\WooCommerce\Utilities\FeaturesUtil::class ) ) {
		return;
	}

	\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', PAYLUMO_PLUGIN_FILE, true );
	\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'cart_checkout_blocks', PAYLUMO_PLUGIN_FILE, true );
}

function init() {
	if ( ! class_exists( 'WC_Payment_Gateway' ) ) {
		add_action( 'admin_notices', __NAMESPACE__ . '\\missing_wc_notice' );
		return;
	}

	require_once PAYLUMO_PLUGIN_DIR . 'includes/class-secrets.php';
	require_once PAYLUMO_PLUGIN_DIR . 'includes/class-gateway.php';
	require_once PAYLUMO_PLUGIN_DIR . 'includes/class-stripe-api.php';
	require_once PAYLUMO_PLUGIN_DIR . 'includes/class-webhook.php';
	require_once PAYLUMO_PLUGIN_DIR . 'includes/class-order-guard.php';
	add_filter( 'woocommerce_payment_gateways', __NAMESPACE__ . '\\add_gateway' );
	Webhook::init();
	Order_Guard::init();
	add_filter( 'woocommerce_rest_prepare_payment_gateway', array( Gateway::class, 'filter_rest_gateway_response' ), 10, 3 );
	add_filter( 'woocommerce_gateway_paylumo_settings_values', array( Gateway::class, 'filter_rest_settings_values' ), 10, 2 );
	add_action( 'woocommerce_create_refund', array( Gateway::class, 'capture_current_refund' ), 10, 2 );
	add_action( 'admin_enqueue_scripts', array( Gateway::class, 'enqueue_settings_assets' ) );
	add_action( 'admin_init', array( Gateway::class, 'cleanup_db_secrets' ) );
	add_action( 'admin_notices', array( Gateway::class, 'admin_notice_db_secrets' ) );
	add_filter( 'plugin_action_links_' . plugin_basename( PAYLUMO_PLUGIN_FILE ), __NAMESPACE__ . '\\add_settings_link' );

	if ( class_exists( 'Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType' ) ) {
		require_once PAYLUMO_PLUGIN_DIR . 'includes/class-blocks-support.php';
		add_action( 'woocommerce_blocks_payment_method_type_registration', __NAMESPACE__ . '\\register_blocks_support' );
	}
}

function register_blocks_support( $registry ) {
	if ( ! is_object( $registry ) || ! method_exists( $registry, 'register' ) ) {
		return;
	}

	$registry->register( new Blocks_Support() );
}

function missing_wc_notice() {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}

	echo '<div class="notice notice-error"><p>';
	echo esc_html__( 'Paylumo Payment Gateway for Stripe and WooCommerce requires WooCommerce to be installed and active.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
	echo '</p></div>';
}

function add_gateway( $gateways ) {
	$gateways[] = Gateway::class;
	return $gateways;
}

function add_settings_link( $links ) {
	$url = admin_url( 'admin.php?page=wc-settings&tab=checkout&section=paylumo' );

	array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</a>' );

	return $links;
}

function load_textdomain() {
	load_plugin_textdomain( 'paylumo-payment-gateway-for-stripe-and-woocommerce', false, dirname( plugin_basename( PAYLUMO_PLUGIN_FILE ) ) . '/languages' );
}

function deactivate() {
	if ( function_exists( 'as_unschedule_all_actions' ) ) {
		as_unschedule_all_actions( PAYLUMO_CLEANUP_HOOK );
	}
	delete_transient( 'paylumo_cleanup_scheduled' );
}
