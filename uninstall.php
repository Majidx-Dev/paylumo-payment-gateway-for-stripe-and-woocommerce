<?php

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'paylumo_webhook_log' ) );

delete_option( 'paylumo_db_version' );

wp_clear_scheduled_hook( 'paylumo_webhook_log_cleanup' );
if ( function_exists( 'as_unschedule_all_actions' ) ) {
	as_unschedule_all_actions( 'paylumo_cancel_unpaid_orders' );
}
delete_transient( 'paylumo_cleanup_scheduled' );

$paylumo_lock_like    = $wpdb->esc_like( 'paylumo_lock_order_' ) . '%';
$paylumo_rejlog_like  = $wpdb->esc_like( '_transient_paylumo_webhook_rejlog_' ) . '%';
$paylumo_timeout_like = $wpdb->esc_like( '_transient_timeout_paylumo_webhook_rejlog_' ) . '%';
$paylumo_dash_like    = $wpdb->esc_like( '_transient_paylumo_dash_' ) . '%';
$paylumo_dash_timeout = $wpdb->esc_like( '_transient_timeout_paylumo_dash_' ) . '%';

$wpdb->query( $wpdb->prepare( "DELETE FROM `{$wpdb->options}` WHERE `option_name` LIKE %s OR `option_name` LIKE %s OR `option_name` LIKE %s OR `option_name` LIKE %s OR `option_name` LIKE %s", $paylumo_lock_like, $paylumo_rejlog_like, $paylumo_timeout_like, $paylumo_dash_like, $paylumo_dash_timeout ) );

$paylumo_secrets = get_option( 'paylumo_secrets_file' );
if ( is_array( $paylumo_secrets ) && ! empty( $paylumo_secrets['path'] ) && is_string( $paylumo_secrets['path'] ) ) {
	$paylumo_path     = $paylumo_secrets['path'];
	$paylumo_explicit = defined( 'PAYLUMO_ENV_FILE' ) && PAYLUMO_ENV_FILE === $paylumo_path;
	$paylumo_ours     = 1 === preg_match( '/(?:-stripe\.env|\/paylumo-secrets-[a-z0-9]+\.php)\z/', $paylumo_path );
	if ( ! $paylumo_explicit && $paylumo_ours && is_file( $paylumo_path ) && ! is_link( $paylumo_path ) ) {
		unlink( $paylumo_path );
	}
}
delete_option( 'paylumo_secrets_file' );
delete_option( 'paylumo_secrets_vault' );
delete_option( 'paylumo_active_key' );
delete_transient( 'paylumo_secrets_public_check' );
