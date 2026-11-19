<?php

namespace Paylumo\StripeGateway;

defined( 'ABSPATH' ) || exit;

use WC_Admin_Settings;
use WC_Order;
use WC_Order_Refund;
use WC_Payment_Gateway;
use WP_Error;
use WP_REST_Response;

class Gateway extends WC_Payment_Gateway {
	private const KEY_PATTERNS = array(
		'test_publishable_key' => '/^pk_test_[A-Za-z0-9]{8,}\z/',
		'test_secret_key'      => '/^sk_test_[A-Za-z0-9]{8,}\z/',
		'test_restricted_key'  => '/^rk_test_[A-Za-z0-9]{8,}\z/',
		'webhook_secret'       => '/^whsec_[A-Za-z0-9]{8,}\z/',
		'live_publishable_key' => '/^pk_live_[A-Za-z0-9]{8,}\z/',
		'live_secret_key'      => '/^sk_live_[A-Za-z0-9]{8,}\z/',
		'live_restricted_key'  => '/^rk_live_[A-Za-z0-9]{8,}\z/',
		'live_webhook_secret'  => '/^whsec_[A-Za-z0-9]{8,}\z/',
	);

	private const SECRET_ENV_NAMES = array(
		'test_secret_key'     => 'PAYLUMO_TEST_SECRET_KEY',
		'test_restricted_key' => 'PAYLUMO_TEST_RESTRICTED_KEY',
		'webhook_secret'      => 'PAYLUMO_TEST_WEBHOOK_SECRET',
		'live_secret_key'     => 'PAYLUMO_LIVE_SECRET_KEY',
		'live_restricted_key' => 'PAYLUMO_LIVE_RESTRICTED_KEY',
		'live_webhook_secret' => 'PAYLUMO_LIVE_WEBHOOK_SECRET',
	);

	private const KEY_PREFIXES = array(
		'test_publishable_key' => 'pk_test_',
		'test_secret_key'      => 'sk_test_',
		'test_restricted_key'  => 'rk_test_',
		'webhook_secret'       => 'whsec_',
		'live_publishable_key' => 'pk_live_',
		'live_secret_key'      => 'sk_live_',
		'live_restricted_key'  => 'rk_live_',
		'live_webhook_secret'  => 'whsec_',
	);

	private const MODE_FIELDS = array(
		'test' => array(
			'publishable' => 'test_publishable_key',
			'secret'      => 'test_secret_key',
			'webhook'     => 'webhook_secret',
		),
		'live' => array(
			'publishable' => 'live_publishable_key',
			'secret'      => 'live_secret_key',
			'webhook'     => 'live_webhook_secret',
		),
	);

	private const RESTRICTED_FIELDS = array(
		'test' => 'test_restricted_key',
		'live' => 'live_restricted_key',
	);

	private const ACTIVE_KEY_OPTION = 'paylumo_active_key';

	private static $notice_hooked = false;

	private static $reported_errors = array();

	private static $pending_secrets = array();

	private static $current_wc_refund = null;

	private const EXPIRED_SESSIONS_MAX = 10;

	public function __construct() {
		$this->id                 = 'paylumo';
		$this->has_fields         = false;
		$this->method_title       = __( 'Paylumo Payment Gateway for Stripe and WooCommerce', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
		$this->method_description = __( 'Sends the customer to a Stripe-hosted Checkout page. Choose Test or Live mode below; each mode has its own keys.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );

		$this->supports = array( 'products', 'refunds' );

		$this->init_form_fields();
		$this->init_settings();

		$this->title       = $this->get_option( 'title' );
		$this->description = $this->get_option( 'description' );
		$this->enabled     = $this->get_option( 'enabled' );

		add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( $this, 'process_admin_options' ) );

		if ( ! self::$notice_hooked ) {
			add_action( 'admin_notices', array( $this, 'admin_notice_invalid_keys' ) );
			self::$notice_hooked = true;
		}
	}

	public function init_form_fields() {
		$this->form_fields = array(
			'enabled'              => array(
				'title'   => __( 'Enable/Disable', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'    => 'checkbox',
				'label'   => __( 'Enable Stripe', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default' => 'no',
			),
			'title'                => array(
				'title'       => __( 'Title', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'text',
				'description' => __( 'The payment method name the customer sees at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => __( 'Credit / Debit Card (Stripe)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'desc_tip'    => true,
			),
			'description'          => array(
				'title'       => __( 'Description', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'textarea',
				'description' => __( 'Shown under the payment method name at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => __( 'You will be redirected to Stripe to pay securely with your card.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'desc_tip'    => true,
			),
			'mode'                 => array(
				'title'   => __( 'Active mode', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'    => 'paylumo_mode',
				'default' => 'test',
			),
			'debug'                => array(
				'title'       => __( 'Debug log', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'checkbox',
				'label'       => __( 'Log events to WooCommerce > Status > Logs, source paylumo-payment-gateway-for-stripe-and-woocommerce', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => 'no',
				'description' => __( 'Keys and secrets are never written to the log. Keep it off in live mode unless you are fixing a problem.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
			),
			'test_publishable_key' => array(
				'title'       => __( 'Test publishable key', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'text',
				'description' => __( 'Starts with pk_test_. Leave empty to remove it.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
			'test_secret_key'      => array(
				'title'       => __( 'Test secret key', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'paylumo_env_secret',
				'description' => __( 'Starts with sk_test_. Not needed if you use a test restricted key below. Only one key is kept: saving a secret key deletes the saved restricted key of this mode.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
			'test_restricted_key'  => array(
				'title'       => __( 'Test restricted key (optional)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'paylumo_env_secret',
				'description' => __( 'A safer alternative to the secret key. A restricted key (rk_test_) can only do what you allow, so if it is ever stolen it cannot be used for anything else in your Stripe account. Create it in the Stripe Dashboard with Write access to Checkout Sessions and Refunds. Only one key is kept: saving a restricted key deletes the saved secret key of this mode.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
			'webhook_secret'       => array(
				'title'       => __( 'Test webhook signing secret', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'paylumo_env_secret',
				'description' => __( 'Starts with whsec_. Copy it from the test-mode webhook endpoint in Stripe, or from stripe listen.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
			'live_publishable_key' => array(
				'title'       => __( 'Live publishable key', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'text',
				'description' => __( 'Starts with pk_live_. Leave empty to remove it.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
			'live_secret_key'      => array(
				'title'       => __( 'Live secret key', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'paylumo_env_secret',
				'description' => __( 'Starts with sk_live_. Not needed if you use a live restricted key below. Only one key is kept: saving a secret key deletes the saved restricted key of this mode.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
			'live_restricted_key'  => array(
				'title'       => __( 'Live restricted key (optional)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'paylumo_env_secret',
				'description' => __( 'A safer alternative to the secret key. A restricted key (rk_live_) can only do what you allow, so if it is ever stolen it cannot be used for anything else in your Stripe account. Create it in the Stripe Dashboard (live mode) with Write access to Checkout Sessions and Refunds. Only one key is kept: saving a restricted key deletes the saved secret key of this mode.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
			'live_webhook_secret'  => array(
				'title'       => __( 'Live webhook signing secret', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'type'        => 'paylumo_env_secret',
				'description' => __( 'Starts with whsec_. Copy it from the live-mode webhook endpoint in Stripe.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'default'     => '',
			),
		);
	}

	public function admin_options() {
		$all_fields  = $this->form_fields;
		$active_mode = $this->get_mode();

		$this->form_fields = array();
		ob_start();
		parent::admin_options();
		$header = (string) ob_get_clean();
		$this->form_fields = $all_fields;
		echo str_replace( '<table class="form-table"></table>', '', $header );

		echo '<div class="paylumo-settings">';
		$this->render_overview( $active_mode );

		$this->render_card_open( 'general', __( 'Checkout display', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), __( 'Turn the gateway on and choose what customers see at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		echo $this->fields_table_html( array( 'enabled', 'title', 'description' ) );
		echo '</div></section>';

		$this->render_card_open( 'mode', __( 'Payment mode', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), __( 'Decides which keys take payments at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		echo $this->fields_table_html( array( 'mode' ) );
		echo '</div></section>';

		$this->render_card_open( 'keys', __( 'Keys and webhooks', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), __( 'Each mode has its own keys. Switching tabs also selects that mode in "Active mode" above; the change applies after you click "Save changes".', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		$this->render_secrets_notice();
		echo '<div class="paylumo-keys" data-active-mode="' . esc_attr( $active_mode ) . '">';
		echo '<div class="paylumo-mode-tabs" role="tablist" aria-label="' . esc_attr__( 'Keys by mode', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '">';
		foreach ( array( 'test', 'live' ) as $mode ) {
			$selected = $mode === $active_mode;
			echo '<button type="button" role="tab" class="paylumo-mode-tab paylumo-mode-tab--' . esc_attr( $mode ) . '" id="paylumo-tab-' . esc_attr( $mode ) . '" aria-controls="paylumo-panel-' . esc_attr( $mode ) . '" aria-selected="' . ( $selected ? 'true' : 'false' ) . '" tabindex="' . ( $selected ? '0' : '-1' ) . '" data-mode="' . esc_attr( $mode ) . '">';
			echo '<span class="paylumo-mode-tab__label">' . esc_html( self::mode_tab_title( $mode ) ) . '</span>';
			echo $this->mode_status_html( $mode, $active_mode );
			echo '</button>';
		}
		echo '</div>';

		foreach ( array( 'test', 'live' ) as $mode ) {
			$fields = self::MODE_FIELDS[ $mode ];
			echo '<div class="paylumo-mode-panel paylumo-mode-panel--' . esc_attr( $mode ) . '" role="tabpanel" id="paylumo-panel-' . esc_attr( $mode ) . '" aria-labelledby="paylumo-tab-' . esc_attr( $mode ) . '" data-mode="' . esc_attr( $mode ) . '">';
			echo '<h3 class="paylumo-mode-panel__title">' . esc_html( self::mode_tab_title( $mode ) ) . '</h3>';
			$this->render_mode_panel_notices( $mode );

			$this->render_subsection_head( __( 'API keys', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), __( 'Get keys from Stripe', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), self::stripe_dashboard_url( $mode, 'apikeys' ) );
			echo $this->fields_table_html( array( $fields['publishable'], $fields['secret'], self::RESTRICTED_FIELDS[ $mode ] ) );

			$this->render_subsection_head( __( 'Webhook', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), __( 'Open Stripe webhooks', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), self::stripe_dashboard_url( $mode, 'webhooks' ) );
			$this->render_webhook_steps( $mode );
			echo '<table class="form-table">';
			echo $this->webhook_url_row_html( $mode );
			echo $this->generate_settings_html( array_intersect_key( $this->get_form_fields(), array_flip( array( $fields['webhook'] ) ) ), false );
			echo '</table>';
			echo '</div>';
		}
		echo '</div>';
		echo '</div></section>';

		$this->render_card_open( 'advanced', __( 'Advanced', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), '' );
		echo $this->fields_table_html( array( 'debug' ) );
		echo '</div></section>';

		echo '</div>';
	}

	private function fields_table_html( array $keys ) {
		$all    = $this->get_form_fields();
		$subset = array();
		foreach ( $keys as $key ) {
			if ( isset( $all[ $key ] ) ) {
				$subset[ $key ] = $all[ $key ];
			}
		}

		return '<table class="form-table">' . $this->generate_settings_html( $subset, false ) . '</table>';
	}

	private function render_card_open( $slug, $title, $intro ) {
		$heading_id = 'paylumo-card-' . $slug;
		echo '<section class="paylumo-card paylumo-card--' . esc_attr( $slug ) . '" aria-labelledby="' . esc_attr( $heading_id ) . '">';
		echo '<header class="paylumo-card__head"><h2 class="paylumo-card__title" id="' . esc_attr( $heading_id ) . '">' . esc_html( $title ) . '</h2>';
		if ( '' !== $intro ) {
			echo '<p class="paylumo-card__intro">' . esc_html( $intro ) . '</p>';
		}
		echo '</header><div class="paylumo-card__body">';
	}

	private function render_subsection_head( $title, $link_text, $url ) {
		echo '<div class="paylumo-subhead"><h3 class="paylumo-subhead__title">' . esc_html( $title ) . '</h3>';
		echo '<a class="paylumo-subhead__link" href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $link_text );
		echo '<span class="screen-reader-text"> ' . esc_html__( '(opens in a new tab)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</span>';
		echo '<span class="paylumo-subhead__icon" aria-hidden="true">&#8599;</span></a></div>';
	}

	private function render_webhook_steps( $mode ) {
		$steps = array(
			__( 'Copy the webhook URL below.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
			'live' === $mode ? __( 'In Stripe live mode, add a webhook endpoint with this URL and the events listed.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'In Stripe test mode, add a webhook endpoint with this URL and the events listed (or use stripe listen).', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
			__( 'Paste the endpoint\'s signing secret (whsec_...) below and save.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
		);

		echo '<ol class="paylumo-steps">';
		foreach ( $steps as $step ) {
			echo '<li>' . esc_html( $step ) . '</li>';
		}
		echo '</ol>';
	}

	private static function stripe_dashboard_url( $mode, $page ) {
		$page = 'webhooks' === $page ? 'webhooks' : 'apikeys';
		return 'https://dashboard.stripe.com/' . ( 'live' === $mode ? '' : 'test/' ) . $page;
	}

	private function render_overview( $active_mode ) {
		$enabled = 'yes' === $this->get_option( 'enabled' );
		$ready   = $this->mode_is_ready( $active_mode );
		$items   = array(
			array( __( 'Gateway', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $enabled ? __( 'Enabled', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Disabled', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $enabled ? 'good' : 'neutral' ),
			array( __( 'Active mode', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), 'live' === $active_mode ? __( 'Live', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Test', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), 'live' === $active_mode ? 'live' : 'test' ),
			array( __( 'Test keys', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $this->keys_are_valid( 'test' ) ? __( 'Complete', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Missing', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $this->keys_are_valid( 'test' ) ? 'good' : 'bad' ),
			array( __( 'Live keys', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $this->keys_are_valid( 'live' ) ? __( 'Complete', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Missing', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $this->keys_are_valid( 'live' ) ? 'good' : ( 'live' === $active_mode ? 'bad' : 'neutral' ) ),
			array( __( 'HTTPS', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), is_ssl() ? __( 'Secure', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Not secure', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), is_ssl() ? 'good' : ( 'live' === $active_mode ? 'bad' : 'warn' ) ),
		);

		echo '<section class="paylumo-overview" aria-labelledby="paylumo-overview-title">';
		echo '<div class="paylumo-overview__head"><h2 class="paylumo-overview__title" id="paylumo-overview-title">' . esc_html__( 'Status', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</h2>';
		if ( $enabled && $ready ) {
			echo '<p class="paylumo-overview__summary is-good">' . esc_html__( 'Ready to take payments at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p>';
		} elseif ( $enabled ) {
			echo '<p class="paylumo-overview__summary is-bad">' . esc_html__( 'Enabled, but hidden at checkout until the active mode has all three keys (and HTTPS for Live).', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p>';
		} else {
			echo '<p class="paylumo-overview__summary">' . esc_html__( 'The gateway is turned off. Customers will not see it at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p>';
		}
		echo '</div><dl class="paylumo-overview__list">';
		foreach ( $items as $item ) {
			echo '<div class="paylumo-stat"><dt class="paylumo-stat__label">' . esc_html( $item[0] ) . '</dt>';
			echo '<dd class="paylumo-stat__value"><span class="paylumo-pill is-' . esc_attr( $item[2] ) . '">' . esc_html( $item[1] ) . '</span></dd></div>';
		}
		echo '</dl></section>';
	}

	private static function mode_tab_title( $mode ) {
		return 'live' === $mode ? __( 'Live settings', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Test settings', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
	}

	private function mode_status_html( $mode, $active_mode ) {
		$complete = $this->keys_are_valid( $mode );
		$html     = '<span class="paylumo-mode-tab__status ' . ( $complete ? 'is-complete' : 'is-missing' ) . '">';
		$html    .= esc_html( $complete ? __( 'Keys complete', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Keys missing', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		$html    .= '</span>';

		if ( $mode === $active_mode ) {
			$html .= '<span class="paylumo-mode-tab__active">' . esc_html__( 'Active', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</span>';
		}

		return $html;
	}

	private function render_secrets_notice() {
		echo '<div class="paylumo-callout paylumo-callout--info"><p>' . esc_html__( 'Secret keys and webhook signing secrets are saved encrypted in the database, never as plain text and never in a file. The encryption key comes from the security keys in wp-config.php and is never stored in the database. If you move the site without its wp-config.php, or change those security keys, enter the secret keys again.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p></div>';

		if ( Secrets::vault_is_broken() ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'The encrypted secret keys cannot be decrypted, usually because the security keys in wp-config.php were changed or the site was moved. Enter the secret keys and webhook signing secrets again and save.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p></div>';
		}
	}

	public static function cleanup_db_secrets() {
		Secrets::migrate_legacy_store();

		foreach ( self::RESTRICTED_FIELDS as $mode => $restricted_field ) {
			$secret_name     = self::SECRET_ENV_NAMES[ self::MODE_FIELDS[ $mode ]['secret'] ];
			$restricted_name = self::SECRET_ENV_NAMES[ $restricted_field ];
			$old             = Secrets::get( $secret_name );
			if ( self::is_valid_key( $restricted_field, $old ) && '' === Secrets::get( $restricted_name ) && true === Secrets::write( array( $restricted_name => $old ) ) ) {
				Secrets::remove( array( $secret_name ) );
				self::set_key_kind_in_use( $mode, 'restricted' );
			}

			$secret_ok = self::is_valid_key( self::MODE_FIELDS[ $mode ]['secret'], Secrets::get( $secret_name ) );
			if ( $secret_ok && self::is_valid_key( $restricted_field, Secrets::get( $restricted_name ) ) ) {
				self::drop_other_payment_key( $mode, self::key_kind_in_use( $mode ) );
			}
		}

		$settings = get_option( 'woocommerce_paylumo_settings', array() );
		if ( ! is_array( $settings ) ) {
			return;
		}

		$to_file = array();
		foreach ( self::SECRET_ENV_NAMES as $field => $env_name ) {
			$old = isset( $settings[ $field ] ) ? (string) $settings[ $field ] : '';
			if ( '' !== $old && self::is_valid_key( $field, $old ) && ! self::is_valid_key( $field, Secrets::get( $env_name ) ) ) {
				$to_file[ $env_name ] = $old;
			}
		}

		if ( ! empty( $to_file ) && true === Secrets::write( $to_file ) ) {
			self::log( sprintf( 'settings: moved %d secret(s) from the database to secure storage.', count( $to_file ) ), 'info' );
		}

		$changed = false;
		foreach ( self::SECRET_ENV_NAMES as $field => $env_name ) {
			if ( ! empty( $settings[ $field ] ) && self::is_valid_key( $field, Secrets::get( $env_name ) ) ) {
				$settings[ $field ] = '';
				$changed            = true;
			}
		}

		if ( $changed ) {
			update_option( 'woocommerce_paylumo_settings', $settings );
		}
	}

	public static function admin_notice_db_secrets() {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}

		$settings = get_option( 'woocommerce_paylumo_settings', array() );
		$left     = false;
		foreach ( array_keys( self::SECRET_ENV_NAMES ) as $field ) {
			if ( is_array( $settings ) && ! empty( $settings[ $field ] ) ) {
				$left = true;
			}
		}

		$settings_url = admin_url( 'admin.php?page=wc-settings&tab=checkout&section=paylumo' );

		if ( Secrets::vault_is_broken() ) {
			echo '<div class="notice notice-error"><p>';
			echo esc_html__( 'Stripe: the encrypted secret keys cannot be decrypted, usually because the security keys in wp-config.php were changed or the site was moved. Payments with Stripe are off until you enter the secret keys again.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			echo ' <a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Open the gateway settings', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</a>';
			echo '</p></div>';
		}

		$ignored = Secrets::ignored_sources();
		if ( ! empty( $ignored ) ) {
			echo '<div class="notice notice-warning"><p>';
			echo esc_html( sprintf( __( 'Stripe: %s is set in wp-config.php or the server environment, but this plugin no longer reads it. Paste the secret keys in the gateway settings (they are saved encrypted in the database), then remove these settings from wp-config.php or the server.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), implode( ', ', $ignored ) ) );
			echo ' <a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Open the gateway settings', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</a>';
			echo '</p></div>';
		}

		if ( ! $left ) {
			return;
		}

		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'Stripe: old secret keys are still stored as plain text in the database and could not be moved to secure storage, so they are not used. Open the Stripe settings to see why.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
		echo ' <a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Open the gateway settings', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</a>';
		echo '</p></div>';
	}

	private function render_mode_panel_notices( $mode ) {
		if ( 'live' !== $mode ) {
			echo '<p class="paylumo-callout paylumo-callout--info">' . esc_html__( 'Test mode uses Stripe test keys and test cards. No real money moves.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p>';
			return;
		}

		echo '<div class="paylumo-callout paylumo-callout--danger"><p><strong>' . esc_html__( 'Live mode charges real cards.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</strong> ' . esc_html__( 'Your Stripe account must be activated for live payments. Test with one small real payment and refund it before you open the store.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p></div>';

		if ( ! is_ssl() ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'This site is not using HTTPS. Live mode only works over HTTPS, so the gateway stays hidden at checkout while Live is active.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p></div>';
		}
	}

	private function webhook_url_row_html( $mode ) {
		$url      = rest_url( 'paylumo/v1/webhook/' . $mode );
		$field_id = 'paylumo-webhook-url-' . $mode;
		$label    = 'live' === $mode ? __( 'Live webhook URL', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Test webhook URL', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );

		$html  = '<tr valign="top"><th scope="row" class="titledesc"><label for="' . esc_attr( $field_id ) . '">' . esc_html( $label ) . '</label></th>';
		$html .= '<td class="forminp"><div class="paylumo-webhook-url">';
		$html .= '<input type="text" id="' . esc_attr( $field_id ) . '" class="regular-text code" value="' . esc_attr( $url ) . '" readonly>';
		$html .= '<button type="button" class="button paylumo-copy-button" data-copy-target="' . esc_attr( $field_id ) . '" hidden>' . esc_html__( 'Copy', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</button>';
		$html .= '<span class="paylumo-copy-status" role="status" aria-live="polite"></span>';
		$html .= '</div><p class="description">' . esc_html__( 'Events to send:', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p>';
		$html .= '<ul class="paylumo-events"><li><code>checkout.session.completed</code></li><li><code>checkout.session.async_payment_succeeded</code></li><li><code>checkout.session.async_payment_failed</code></li><li><code>checkout.session.expired</code></li><li><code>charge.refunded</code></li></ul></td></tr>';

		return $html;
	}

	public function generate_paylumo_mode_html( $key, $data ) {
		$field_key = $this->get_field_key( $key );
		$current   = self::normalize_mode( $this->get_option( $key ) );
		$choices   = array(
			'test' => array( __( 'Test', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), __( 'No real money. Use Stripe test cards.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) ),
			'live' => array( __( 'Live', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), __( 'Real cards are charged. Needs live keys and HTTPS.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) ),
		);

		$html  = '<tr valign="top"><th scope="row" class="titledesc">' . esc_html( $data['title'] ) . '</th>';
		$html .= '<td class="forminp"><fieldset class="paylumo-mode-choice">';
		$html .= '<legend class="screen-reader-text"><span>' . esc_html( $data['title'] ) . '</span></legend>';

		foreach ( $choices as $value => $text ) {
			$html .= '<label class="paylumo-mode-choice__option paylumo-mode-choice__option--' . esc_attr( $value ) . '">';
			$html .= '<input type="radio" class="paylumo-mode-choice__input" name="' . esc_attr( $field_key ) . '" value="' . esc_attr( $value ) . '"' . checked( $current, $value, false ) . '>';
			$html .= '<span class="paylumo-mode-choice__text"><span class="paylumo-mode-choice__name">' . esc_html( $text[0] ) . '</span>';
			$html .= '<span class="paylumo-mode-choice__desc">' . esc_html( $text[1] ) . '</span></span></label>';
		}

		$html .= '<p class="description paylumo-mode-live-note">' . esc_html__( 'Live needs all three live keys and HTTPS. The change applies after you click "Save changes".', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</p>';
		$html .= '</fieldset></td></tr>';

		return $html;
	}

	private static function drop_other_payment_key( $mode, $kind ) {
		$mode  = self::normalize_mode( $mode );
		$other = 'restricted' === $kind ? self::MODE_FIELDS[ $mode ]['secret'] : self::RESTRICTED_FIELDS[ $mode ];
		self::set_key_kind_in_use( $mode, $kind );
		return Secrets::remove( array( self::SECRET_ENV_NAMES[ $other ] ) );
	}

	public function generate_paylumo_env_secret_html( $key, $data ) {
		$env_name  = self::SECRET_ENV_NAMES[ $key ] ?? '';
		$value     = Secrets::get( $env_name );
		$field_key = $this->get_field_key( $key );

		$mode       = str_starts_with( $key, 'live_' ) ? 'live' : 'test';
		$restricted = in_array( $key, self::RESTRICTED_FIELDS, true );
		$payment    = $restricted || self::MODE_FIELDS[ $mode ]['secret'] === $key;
		$in_use     = self::key_kind_in_use( $mode );

		if ( '' === $value && $restricted ) {
			$status = __( 'Not set (optional)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			$tone   = 'is-neutral';
		} elseif ( '' === $value && $payment && 'restricted' === $in_use ) {
			$status = __( 'Not needed (restricted key in use)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			$tone   = 'is-neutral';
		} elseif ( '' === $value ) {
			$status = __( 'Missing', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			$tone   = 'is-missing';
		} elseif ( $payment && self::is_valid_key( $key, $value ) ) {
			$is_used = ( $restricted ? 'restricted' : 'secret' ) === $in_use;
			$status  = $is_used ? __( 'Saved, in use', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Saved, not in use', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			$tone    = $is_used ? 'is-complete' : 'is-neutral';
		} elseif ( ! self::is_valid_key( $key, $value ) ) {
			$status = sprintf( __( 'Invalid: must start with %s', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), self::KEY_PREFIXES[ $key ] );
			$tone   = 'is-missing';
		} else {
			$status = __( 'Saved', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			$tone   = 'is-complete';
		}

		$html  = '<tr valign="top"><th scope="row" class="titledesc"><label for="' . esc_attr( $field_key ) . '">' . esc_html( $data['title'] ) . '</label></th>';
		$html .= '<td class="forminp"><fieldset>';
		$html .= '<input class="input-text regular-input" type="password" name="' . esc_attr( $field_key ) . '" id="' . esc_attr( $field_key ) . '" value="" autocomplete="new-password" spellcheck="false"> ';
		$html .= '<span class="paylumo-mode-tab__status ' . esc_attr( $tone ) . '">' . esc_html( $status ) . '</span>';
		$note  = (string) ( $data['description'] ?? '' );
		if ( '' !== $value ) {
			$note = trim( $note . ' ' . __( 'Leave blank to keep the saved key.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		}
		if ( '' !== $note ) {
			$html .= '<p class="description">' . esc_html( $note ) . '</p>';
		}
		$html .= '</fieldset></td></tr>';

		return $html;
	}

	public function validate_paylumo_env_secret_field( $key, $value ) {
		$value    = is_string( $value ) ? trim( sanitize_text_field( wp_unslash( $value ) ) ) : '';
		$env_name = self::SECRET_ENV_NAMES[ $key ] ?? '';

		if ( '' === $value || '' === $env_name ) {
			return '';
		}

		if ( self::is_valid_key( $key, $value ) ) {
			if ( $this->secret_key_usable( $key, $value ) ) {
				self::$pending_secrets[ $env_name ] = $value;
			}
		} else {
			$this->report_settings_error(
				sprintf(
					__( '%1$s was not saved: it must start with %2$s. Keys from the other mode and other values are not allowed. The previous value was kept.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
					$this->form_fields[ $key ]['title'],
					self::KEY_PREFIXES[ $key ]
				)
			);
		}

		return '';
	}

	private function secret_key_usable( $key, $value ) {
		if ( ! in_array( $key, array( 'test_secret_key', 'live_secret_key', 'test_restricted_key', 'live_restricted_key' ), true ) ) {
			return true;
		}

		$label  = $this->form_fields[ $key ]['title'];
		$result = ( new Stripe_API( $value ) )->check_access();

		if ( true === $result ) {
			return true;
		}

		$data   = $result->get_error_data();
		$status = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 0;

		if ( 401 === $status ) {
			$this->report_settings_error( sprintf( __( '%s was not saved: Stripe did not accept this key (it may be mistyped, deleted or rolled). The previous value was kept.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $label ) );
			return false;
		}

		if ( 403 === $status ) {
			$missing = is_array( $data ) && ! empty( $data['paylumo_resource'] ) ? (string) $data['paylumo_resource'] : __( 'Checkout Sessions and Refunds', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			$this->report_settings_error( sprintf( __( '%1$s was not saved: this restricted key has no access to %2$s. In the Stripe Dashboard, give the key Write access to Checkout Sessions and Refunds, then paste it again. The previous value was kept.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $label, $missing ) );
			return false;
		}

		$this->report_settings_error( sprintf( __( '%s was saved, but it could not be checked with Stripe right now (no connection). Place a test order to make sure it works.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $label ) );
		return true;
	}

	public function process_admin_options() {
		self::$pending_secrets = array();
		$saved                 = parent::process_admin_options();

		foreach ( self::RESTRICTED_FIELDS as $mode => $restricted_field ) {
			if ( isset( self::$pending_secrets[ self::SECRET_ENV_NAMES[ $restricted_field ] ] ) ) {
				unset( self::$pending_secrets[ self::SECRET_ENV_NAMES[ self::MODE_FIELDS[ $mode ]['secret'] ] ] );
			}
		}

		if ( ! empty( self::$pending_secrets ) ) {
			$written = Secrets::write( self::$pending_secrets );
			if ( is_wp_error( $written ) ) {
				$this->report_settings_error( __( 'The secret keys could not be saved securely on this server (encryption is not available or the database did not save them). Nothing was saved. Contact your host.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
				self::log( 'settings: secrets could not be saved: ' . $written->get_error_code(), 'error', true );
			} else {
				foreach ( self::RESTRICTED_FIELDS as $mode => $restricted_field ) {
					$kind = '';
					if ( isset( self::$pending_secrets[ self::SECRET_ENV_NAMES[ $restricted_field ] ] ) ) {
						$kind = 'restricted';
					} elseif ( isset( self::$pending_secrets[ self::SECRET_ENV_NAMES[ self::MODE_FIELDS[ $mode ]['secret'] ] ] ) ) {
						$kind = 'secret';
					}
					if ( '' !== $kind && is_wp_error( self::drop_other_payment_key( $mode, $kind ) ) ) {
						$this->report_settings_error( __( 'The new key was saved and is in use, but the previous key of this mode could not be deleted from the database. Save again or contact your host.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
					}
				}
			}
			self::$pending_secrets = array();
		}

		return $saved;
	}

	public function validate_test_publishable_key_field( $key, $value ) {
		return $this->validate_key_value( $key, $value );
	}

	public function validate_live_publishable_key_field( $key, $value ) {
		return $this->validate_key_value( $key, $value );
	}

	public function validate_mode_field( $key, $value ) {
		$value = is_string( $value ) ? sanitize_key( wp_unslash( $value ) ) : '';
		return self::normalize_mode( $value );
	}

	private function validate_key_value( $key, $value ) {
		$value    = is_string( $value ) ? trim( sanitize_text_field( wp_unslash( $value ) ) ) : '';
		$previous = isset( $this->settings[ $key ] ) ? (string) $this->settings[ $key ] : '';
		$result   = self::resolve_key_value( $key, $value, $previous );

		if ( $result['invalid'] ) {
			$this->report_settings_error(
				sprintf(
					__( '%1$s was not saved: it must start with %2$s. Keys from the other mode and other values are not allowed. The previous value was kept.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
					$this->form_fields[ $key ]['title'],
					self::KEY_PREFIXES[ $key ]
				)
			);
		}

		return $result['value'];
	}

	private static function resolve_key_value( $key, $value, $previous ) {
		if ( '' === $value ) {
			return array(
				'value'   => '',
				'invalid' => false,
			);
		}

		if ( self::is_valid_key( $key, $value ) ) {
			return array(
				'value'   => $value,
				'invalid' => false,
			);
		}

		return array(
			'value'   => self::is_valid_key( $key, $previous ) ? $previous : '',
			'invalid' => true,
		);
	}

	public static function filter_rest_settings_values( $settings, $gateway = null ) {
		if ( ! is_array( $settings ) ) {
			return $settings;
		}

		$stored = get_option( 'woocommerce_paylumo_settings', array() );
		$stored = is_array( $stored ) ? $stored : array();

		foreach ( array_keys( self::KEY_PATTERNS ) as $key ) {
			if ( isset( self::SECRET_ENV_NAMES[ $key ] ) ) {
				$settings[ $key ] = '';
				continue;
			}

			$value    = ( isset( $settings[ $key ] ) && is_string( $settings[ $key ] ) ) ? trim( sanitize_text_field( $settings[ $key ] ) ) : '';
			$previous = ( isset( $stored[ $key ] ) && is_string( $stored[ $key ] ) ) ? $stored[ $key ] : '';
			$result   = self::resolve_key_value( $key, $value, $previous );

			$submitted = ( $settings[ $key ] ?? null ) !== ( $stored[ $key ] ?? null );

			if ( $result['invalid'] && $submitted ) {
				self::log( sprintf( 'settings (REST): %s was not saved: it must start with %s. The previous value was kept.', $key, self::KEY_PREFIXES[ $key ] ), 'error' );
			}

			$settings[ $key ] = $result['value'];
		}

		$mode_value = isset( $settings['mode'] ) && is_string( $settings['mode'] ) ? $settings['mode'] : '';
		if ( ! in_array( $mode_value, array( 'test', 'live' ), true ) ) {
			$settings['mode'] = self::normalize_mode( $stored['mode'] ?? 'test' );
		}

		if ( $gateway instanceof WC_Payment_Gateway ) {
			$gateway->settings = $settings;
		}

		return $settings;
	}

	public static function filter_rest_gateway_response( $response, $gateway, $request = null ) {
		if ( ! $response instanceof WP_REST_Response || ! is_object( $gateway ) || ! isset( $gateway->id ) || 'paylumo' !== $gateway->id ) {
			return $response;
		}

		$data = $response->get_data();

		if ( ! is_array( $data ) || ! isset( $data['settings'] ) || ! is_array( $data['settings'] ) ) {
			return $response;
		}

		foreach ( $data['settings'] as $id => $field ) {
			$is_secret = isset( self::SECRET_ENV_NAMES[ $id ] ) || ( is_array( $field ) && isset( $field['type'] ) && in_array( $field['type'], array( 'password', 'paylumo_env_secret' ), true ) );
			if ( $is_secret && is_array( $field ) ) {
				$data['settings'][ $id ]['value']   = '';
				$data['settings'][ $id ]['default'] = '';
			}
		}

		$response->set_data( $data );
		return $response;
	}

	public static function is_valid_key( $key, $value ) {
		if ( ! isset( self::KEY_PATTERNS[ $key ] ) || ! is_string( $value ) ) {
			return false;
		}

		return 1 === preg_match( self::KEY_PATTERNS[ $key ], $value );
	}

	private function report_settings_error( $message ) {
		if ( in_array( $message, self::$reported_errors, true ) ) {
			return;
		}

		self::$reported_errors[] = $message;

		if ( class_exists( 'WC_Admin_Settings' ) ) {
			WC_Admin_Settings::add_error( $message );
		}
	}

	public static function enqueue_settings_assets( $hook_suffix ) {
		$tab     = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		$section = isset( $_GET['section'] ) ? sanitize_key( wp_unslash( $_GET['section'] ) ) : '';

		if ( 'woocommerce_page_wc-settings' !== $hook_suffix || 'checkout' !== $tab || 'paylumo' !== $section ) {
			return;
		}

		$css_ver = PAYLUMO_VERSION . '.' . (int) filemtime( PAYLUMO_PLUGIN_DIR . 'assets/css/settings.css' );
		$js_ver  = PAYLUMO_VERSION . '.' . (int) filemtime( PAYLUMO_PLUGIN_DIR . 'assets/js/settings.js' );
		wp_enqueue_style( 'paylumo-settings', PAYLUMO_PLUGIN_URL . 'assets/css/settings.css', array(), $css_ver );
		wp_enqueue_script( 'paylumo-settings', PAYLUMO_PLUGIN_URL . 'assets/js/settings.js', array(), $js_ver, true );
		wp_localize_script(
			'paylumo-settings',
			'paylumoSettings',
			array(
				'copied'     => __( 'Copied', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'copyFailed' => __( 'Press Ctrl+C to copy', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'show'       => __( 'Show', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'hide'       => __( 'Hide', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
				'dismiss'    => __( 'Dismiss this notice.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ),
			)
		);
	}

	public static function normalize_mode( $mode ) {
		return 'live' === $mode ? 'live' : 'test';
	}

	public function get_mode() {
		return self::normalize_mode( $this->get_option( 'mode', 'test' ) );
	}

	public static function get_order_mode( WC_Order $order ) {
		return self::normalize_mode( (string) $order->get_meta( '_paylumo_mode' ) );
	}

	private static function key_kind_in_use( $mode ) {
		$mode        = self::normalize_mode( $mode );
		$secret_ok   = self::is_valid_key( self::MODE_FIELDS[ $mode ]['secret'], Secrets::get( self::SECRET_ENV_NAMES[ self::MODE_FIELDS[ $mode ]['secret'] ] ) );
		$restrict_ok = self::is_valid_key( self::RESTRICTED_FIELDS[ $mode ], Secrets::get( self::SECRET_ENV_NAMES[ self::RESTRICTED_FIELDS[ $mode ] ] ) );
		$saved       = get_option( self::ACTIVE_KEY_OPTION, array() );
		$last        = is_array( $saved ) && isset( $saved[ $mode ] ) ? (string) $saved[ $mode ] : '';

		if ( 'secret' === $last && $secret_ok ) {
			return 'secret';
		}
		if ( $restrict_ok && ( 'restricted' === $last || ! $secret_ok || '' === $last ) ) {
			return 'restricted';
		}
		return $secret_ok ? 'secret' : '';
	}

	private static function set_key_kind_in_use( $mode, $kind ) {
		$saved                                = get_option( self::ACTIVE_KEY_OPTION, array() );
		$saved                                = is_array( $saved ) ? $saved : array();
		$saved[ self::normalize_mode( $mode ) ] = 'restricted' === $kind ? 'restricted' : 'secret';
		update_option( self::ACTIVE_KEY_OPTION, $saved, false );
	}

	public static function get_saved_key( $mode, $kind ) {
		$fields = self::MODE_FIELDS[ self::normalize_mode( $mode ) ];
		if ( ! isset( $fields[ $kind ] ) ) {
			return '';
		}

		if ( 'secret' === $kind && 'restricted' === self::key_kind_in_use( $mode ) ) {
			return Secrets::get( self::SECRET_ENV_NAMES[ self::RESTRICTED_FIELDS[ self::normalize_mode( $mode ) ] ] );
		}

		if ( isset( self::SECRET_ENV_NAMES[ $fields[ $kind ] ] ) ) {
			$value = Secrets::get( self::SECRET_ENV_NAMES[ $fields[ $kind ] ] );
			return self::is_valid_key( $fields[ $kind ], $value ) ? $value : '';
		}

		$settings = get_option( 'woocommerce_paylumo_settings', array() );
		$value    = ( is_array( $settings ) && isset( $settings[ $fields[ $kind ] ] ) ) ? (string) $settings[ $fields[ $kind ] ] : '';
		return self::is_valid_key( $fields[ $kind ], $value ) ? $value : '';
	}

	private function keys_are_valid( $mode ) {
		foreach ( array_keys( self::MODE_FIELDS[ self::normalize_mode( $mode ) ] ) as $kind ) {
			if ( '' === self::get_saved_key( $mode, $kind ) ) {
				return false;
			}
		}

		return true;
	}

	private function mode_is_ready( $mode ) {
		return $this->keys_are_valid( $mode ) && ( 'test' === $mode || is_ssl() );
	}

	public function is_available() {
		return parent::is_available() && $this->mode_is_ready( $this->get_mode() );
	}

	public function admin_notice_invalid_keys() {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}

		$this->init_settings();
		$this->enabled = $this->get_option( 'enabled' );
		$mode          = $this->get_mode();

		if ( 'yes' !== $this->enabled || $this->mode_is_ready( $mode ) ) {
			return;
		}

		if ( ! $this->keys_are_valid( $mode ) ) {
			$message = 'live' === $mode ? __( 'Stripe is in Live mode but its live keys are missing or invalid, so it is hidden at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Stripe is in Test mode but its test keys are missing or invalid, so it is hidden at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
		} else {
			$message = __( 'Stripe is in Live mode but this site is not using HTTPS, so it is hidden at checkout.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
		}

		$settings_url = admin_url( 'admin.php?page=wc-settings&tab=checkout&section=paylumo' );

		echo '<div class="notice notice-error"><p>';
		echo esc_html( $message );
		echo ' <a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Open the gateway settings', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) . '</a>';
		echo '</p></div>';
	}

	public function process_payment( $order_id ) {
		$order = wc_get_order( $order_id );

		if ( ! $order instanceof WC_Order ) {
			wc_add_notice( __( 'We could not find your order. Please try again.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), 'error' );
			self::log( sprintf( 'process_payment: order %d not found.', absint( $order_id ) ), 'error' );
			return array( 'result' => 'failure' );
		}

		$mode = $this->get_mode();

		if ( ! $this->mode_is_ready( $mode ) ) {
			wc_add_notice( __( 'This payment method is not available right now. Please choose another payment method.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), 'error' );
			self::log( sprintf( 'process_payment: order %d stopped: %s mode is not ready (keys missing or invalid, or live mode without HTTPS).', $order->get_id(), $mode ), 'error' );
			return array( 'result' => 'failure' );
		}

		$api = new Stripe_API( self::get_saved_key( $mode, 'secret' ) );

		$amount = self::get_stripe_amount( $order->get_total(), $order->get_currency() );

		if ( $amount <= 0 ) {
			wc_add_notice( __( 'This order total cannot be paid with this payment method.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), 'error' );
			self::log( sprintf( 'process_payment: order %d stopped: amount in minor units is not above zero.', $order->get_id() ), 'error' );
			return array( 'result' => 'failure' );
		}

		$window = intdiv( time(), 60 ) * 60;

		$params = array(
			'mode'                 => 'payment',
			'line_items'           => array(
				array(
					'quantity'   => 1,
					'price_data' => array(
						'currency'     => strtolower( $order->get_currency() ),
						'unit_amount'  => $amount,
						'product_data' => array(
							'name' => sprintf( __( 'Order #%s', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $order->get_order_number() ),
						),
					),
				),
			),
			'success_url'          => $order->get_checkout_order_received_url(),
			'cancel_url'           => wc_get_checkout_url(),
			'expires_at'           => $window + 60 + PAYLUMO_SESSION_EXPIRY_MINUTES * MINUTE_IN_SECONDS,
			'client_reference_id'  => (string) $order->get_id(),
			'metadata'             => array( 'order_id' => (string) $order->get_id() ),
			'payment_intent_data'  => array( 'metadata' => array( 'order_id' => (string) $order->get_id() ) ),
		);

		$idempotency_key = 'paylumo-' . $order->get_id() . '-' . md5( http_build_query( $params, '', '&' ) );

		$previous_session_id = (string) $order->get_meta( '_paylumo_session_id' );
		$previous_mode       = self::get_order_mode( $order );
		$expired_sessions    = $order->get_meta( '_paylumo_expired_sessions' );
		$expired_sessions    = is_array( $expired_sessions ) ? $expired_sessions : array();

		$session = $api->create_checkout_session( $params, $idempotency_key );

		if ( ! is_wp_error( $session ) && self::is_valid_session( $session ) && $session['id'] !== $previous_session_id && in_array( $session['id'], $expired_sessions, true ) ) {
			self::log( sprintf( 'process_payment: order %d: Stripe replayed an already expired Checkout Session %s; requesting a new session.', $order->get_id(), $session['id'] ), 'info' );
			$session = $api->create_checkout_session( $params, $idempotency_key . '-' . md5( $previous_session_id ) );
		}

		if ( ! is_wp_error( $session ) && ! self::is_valid_session( $session ) ) {
			$session = new WP_Error( 'paylumo_session', 'Stripe response has no valid session id or url.' );
		}

		if ( is_wp_error( $session ) ) {
			wc_add_notice( __( 'We could not start the payment. Please try again or choose another payment method.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), 'error' );
			$error_data    = $session->get_error_data();
			$http_status   = ( is_array( $error_data ) && isset( $error_data['status'] ) ) ? (int) $error_data['status'] : 0;
			$is_auth_error = 'paylumo_api' === $session->get_error_code() && in_array( $http_status, array( 401, 403 ), true );
			self::log( sprintf( 'process_payment: order %d: could not create Checkout Session: %s: %s %s', $order->get_id(), $session->get_error_code(), $session->get_error_message(), wp_json_encode( $error_data ) ), 'error', $is_auth_error );
			return array( 'result' => 'failure' );
		}

		if ( '' !== $previous_session_id && $session['id'] !== $previous_session_id ) {
			$previous_api = $previous_mode === $mode ? $api : self::api_for_mode( $previous_mode );
			if ( null !== $previous_api ) {
				self::expire_previous_session( $previous_api, $order, $previous_session_id );
			} else {
				self::log( sprintf( 'process_payment: order %d: previous %s-mode Checkout Session was not expired because the %s secret key is missing.', $order->get_id(), $previous_mode, $previous_mode ), 'warning' );
			}
			$expired_sessions[] = $previous_session_id;
			$expired_sessions   = array_slice( array_values( array_unique( $expired_sessions ) ), -self::EXPIRED_SESSIONS_MAX );
			$order->update_meta_data( '_paylumo_expired_sessions', $expired_sessions );
		}

		$order->update_meta_data( '_paylumo_session_id', $session['id'] );
		$order->update_meta_data( '_paylumo_mode', $mode );
		$order->delete_meta_data( '_paylumo_session_idem_key' );
		$order->add_order_note( sprintf( __( 'Stripe Checkout Session created in %2$s mode: %1$s. Waiting for Stripe to confirm the payment.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $session['id'], $mode ) );
		$order->save();

		self::log( sprintf( 'process_payment: order %d: Checkout Session %s created, redirecting customer to Stripe.', $order->get_id(), $session['id'] ), 'info' );

		return array(
			'result'   => 'success',
			'redirect' => $session['url'],
		);
	}

	private static function expire_previous_session( Stripe_API $api, WC_Order $order, $session_id ) {
		$result = $api->expire_checkout_session( $session_id );

		if ( is_wp_error( $result ) ) {
			self::log( sprintf( 'process_payment: order %d: previous Checkout Session could not be expired (continuing with a new session): %s: %s', $order->get_id(), $result->get_error_code(), $result->get_error_message() ), 'warning' );
			return;
		}

		self::log( sprintf( 'process_payment: order %d: previous Checkout Session %s expired after the new one was created.', $order->get_id(), $session_id ), 'info' );
	}

	private static function api_for_mode( $mode ) {
		$secret = self::get_saved_key( $mode, 'secret' );
		return '' !== $secret ? new Stripe_API( $secret ) : null;
	}

	private static function dashboard_name( $mode ) {
		return 'live' === $mode ? __( 'the Stripe Dashboard (live mode)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'the Stripe Dashboard (test mode)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
	}

	private static function is_valid_session( $session ) {
		if ( ! is_array( $session ) ) {
			return false;
		}

		$id_ok  = isset( $session['id'] ) && is_string( $session['id'] ) && str_starts_with( $session['id'], 'cs_' );
		$url_ok = isset( $session['url'] ) && is_string( $session['url'] ) && str_starts_with( $session['url'], 'https://' );

		return $id_ok && $url_ok;
	}

	private const STRIPE_METADATA_VALUE_MAX = 500;

	public static function capture_current_refund( $refund, $args = array() ) {
		if ( ! is_array( $args ) || empty( $args['refund_payment'] ) ) {
			self::$current_wc_refund = null;
			return;
		}

		if ( $refund instanceof WC_Order_Refund ) {
			self::$current_wc_refund = $refund;
		}
	}

	private static function take_current_wc_refund() {
		$refund                  = self::$current_wc_refund;
		self::$current_wc_refund = null;
		return $refund;
	}

	public function process_refund( $order_id, $amount = null, $reason = '' ) {
		$wc_refund = self::take_current_wc_refund();
		$order     = wc_get_order( $order_id );

		if ( ! $order instanceof WC_Order ) {
			self::log( sprintf( 'process_refund: order %d not found.', absint( $order_id ) ), 'error' );
			return new WP_Error( 'paylumo_refund_order', __( 'Refund failed: the order could not be found.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		}

		if ( 'paylumo' !== $order->get_payment_method() ) {
			self::log( sprintf( 'process_refund: order %d refused: payment method is not paylumo.', $order->get_id() ), 'error' );
			return new WP_Error( 'paylumo_refund_method', __( 'Refund failed: this order was not paid with Stripe.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		}

		$mode = self::get_order_mode( $order );
		$api  = self::api_for_mode( $mode );

		if ( null === $api ) {
			self::log( sprintf( 'process_refund: order %d stopped: the %s secret key is missing or invalid.', $order->get_id(), $mode ), 'error' );
			$message = 'live' === $mode ? __( 'Refund failed: this order was paid in live mode, but the live secret key is missing or invalid. Add it in WooCommerce > Settings > Payments > Stripe > Live settings.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) : __( 'Refund failed: this order was paid in test mode, but the test secret key is missing or invalid. Add it in WooCommerce > Settings > Payments > Stripe > Test settings.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );
			return new WP_Error( 'paylumo_refund_keys', $message );
		}

		$payment_intent_id = self::get_order_payment_intent_id( $order );

		if ( '' === $payment_intent_id ) {
			self::log( sprintf( 'process_refund: order %d stopped: no Stripe payment intent saved on the order.', $order->get_id() ), 'error' );
			return new WP_Error( 'paylumo_refund_no_payment', sprintf( __( 'Refund failed: no Stripe payment was found for this order. It may be under MANUAL REVIEW (see the order notes). Refund it in %s and then use "Refund manually".', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), self::dashboard_name( $mode ) ) );
		}

		if ( null === $amount ) {
			self::log( sprintf( 'process_refund: order %d stopped: no refund amount given.', $order->get_id() ), 'error' );
			return new WP_Error( 'paylumo_refund_amount', __( 'Refund failed: a refund amount above zero is required.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		}

		$minor = self::get_stripe_amount( $amount, $order->get_currency() );

		if ( $minor <= 0 ) {
			self::log( sprintf( 'process_refund: order %d stopped: refund amount in minor units is not above zero.', $order->get_id() ), 'error' );
			return new WP_Error( 'paylumo_refund_amount', __( 'Refund failed: a refund amount above zero is required.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		}

		$wc_refund_id = self::get_wc_refund_id_for( $wc_refund, $order, $minor );

		if ( 0 === $wc_refund_id ) {
			self::log( sprintf( 'process_refund: order %d stopped: no WooCommerce refund record from this request matches the order and amount.', $order->get_id() ), 'error' );
			return new WP_Error( 'paylumo_refund_record', __( 'Refund failed: start the refund from the order screen (Refund button), which first creates the WooCommerce refund record.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );
		}

		$wc_reason = mb_substr( sanitize_text_field( (string) $reason ), 0, self::STRIPE_METADATA_VALUE_MAX );

		$metadata = array( 'order_id' => (string) $order->get_id() );

		if ( '' !== $wc_reason ) {
			$metadata['wc_reason'] = $wc_reason;
		}

		$params = array(
			'payment_intent' => $payment_intent_id,
			'amount'         => $minor,
			'metadata'       => $metadata,
		);

		$idempotency_key = 'paylumo-refund-' . $order->get_id() . '-' . md5( http_build_query( $params, '', '&' ) . '|' . $wc_refund_id );

		$refund = $api->create_refund( $params, $idempotency_key );

		if ( is_wp_error( $refund ) ) {
			return self::refund_error_from_api( $order, $refund );
		}

		$refund_id = ( isset( $refund['id'] ) && is_string( $refund['id'] ) && str_starts_with( $refund['id'], 're_' ) ) ? $refund['id'] : '';
		$status    = ( isset( $refund['status'] ) && is_string( $refund['status'] ) ) ? $refund['status'] : '';

		if ( in_array( $status, array( 'failed', 'canceled' ), true ) ) {
			self::log( sprintf( 'process_refund: order %d: Stripe refund %s has status %s.', $order->get_id(), $refund_id, $status ), 'error' );
			return new WP_Error( 'paylumo_refund_failed', sprintf( __( 'Refund failed: Stripe refund %1$s has status "%2$s", so no money was returned. See %3$s.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $refund_id, $status, self::dashboard_name( $mode ) ) );
		}

		if ( '' === $refund_id || ! in_array( $status, array( 'succeeded', 'pending', 'requires_action' ), true ) ) {
			self::log( sprintf( 'process_refund: order %d: Stripe response has no valid refund id or a known status.', $order->get_id() ), 'error' );
			return new WP_Error( 'paylumo_refund_unknown', self::refund_unknown_message( $mode ) );
		}

		$note = sprintf( __( 'Stripe refund %1$s created for %2$s (status: %3$s). Reason: %4$s', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $refund_id, wc_format_decimal( $amount ) . ' ' . $order->get_currency(), $status, '' !== $wc_reason ? $wc_reason : __( '(none)', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ) );

		if ( 'succeeded' !== $status ) {
			$note .= ' ' . sprintf( __( 'Stripe has not finished this refund yet; check its status in %s later.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), self::dashboard_name( $mode ) );
		}

		$stripe_amount   = ( isset( $refund['amount'] ) && is_int( $refund['amount'] ) ) ? $refund['amount'] : null;
		$stripe_currency = ( isset( $refund['currency'] ) && is_string( $refund['currency'] ) ) ? $refund['currency'] : '';

		if ( $minor !== $stripe_amount || strtolower( $order->get_currency() ) !== $stripe_currency ) {
			self::log( sprintf( 'process_refund: order %d: MANUAL REVIEW: Stripe refund %s reports %s %s, expected %d %s.', $order->get_id(), $refund_id, wp_json_encode( $stripe_amount ), $stripe_currency, $minor, strtolower( $order->get_currency() ) ), 'error', true );
			$note .= ' ' . sprintf( __( 'MANUAL REVIEW: Stripe reports a different refund amount or currency (%1$s %2$s, minor units). Compare with the Stripe Dashboard.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), wp_json_encode( $stripe_amount ), $stripe_currency );
		}

		$order->add_order_note( $note );

		self::log( sprintf( 'process_refund: order %d: Stripe refund %s created, %d minor units, status %s.', $order->get_id(), $refund_id, $minor, $status ), 'info' );

		return true;
	}

	private static function get_order_payment_intent_id( WC_Order $order ) {
		$payment_intent_id = (string) $order->get_meta( '_paylumo_payment_intent_id' );

		if ( '' === $payment_intent_id ) {
			$payment_intent_id = (string) $order->get_transaction_id();
		}

		return str_starts_with( $payment_intent_id, 'pi_' ) ? $payment_intent_id : '';
	}

	private static function get_wc_refund_id_for( $wc_refund, WC_Order $order, $minor ) {
		if ( ! $wc_refund instanceof WC_Order_Refund || (int) $wc_refund->get_id() <= 0 ) {
			return 0;
		}

		if ( (int) $wc_refund->get_parent_id() !== (int) $order->get_id() ) {
			return 0;
		}

		if ( self::get_stripe_amount( $wc_refund->get_amount(), $order->get_currency() ) !== $minor ) {
			return 0;
		}

		return (int) $wc_refund->get_id();
	}

	private static function refund_error_from_api( WC_Order $order, WP_Error $error ) {
		$error_data    = $error->get_error_data();
		$http_status   = ( is_array( $error_data ) && isset( $error_data['status'] ) ) ? (int) $error_data['status'] : 0;
		$is_api_error  = 'paylumo_api' === $error->get_error_code();
		$is_auth_error = $is_api_error && in_array( $http_status, array( 401, 403 ), true );

		self::log( sprintf( 'process_refund: order %d: could not create Stripe refund: %s: %s %s', $order->get_id(), $error->get_error_code(), $error->get_error_message(), wp_json_encode( $error_data ) ), 'error', $is_auth_error );

		if ( ! $is_api_error ) {
			return new WP_Error( 'paylumo_refund_unknown', self::refund_unknown_message( self::get_order_mode( $order ) ) );
		}

		$stripe_message = '' !== $error->get_error_message() ? $error->get_error_message() : __( 'no details were given.', 'paylumo-payment-gateway-for-stripe-and-woocommerce' );

		return new WP_Error( 'paylumo_refund_stripe', sprintf( __( 'Stripe refused the refund. Nothing was refunded. Stripe says: %s', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), $stripe_message ) );
	}

	private static function refund_unknown_message( $mode ) {
		return sprintf( __( 'Refund status unknown: Stripe could not be reached or sent an unclear answer, so the refund may or may not have been created. Check %s before trying again. If Stripe shows the refund, record it here with "Refund manually".', 'paylumo-payment-gateway-for-stripe-and-woocommerce' ), self::dashboard_name( $mode ) );
	}

	private const ZERO_DECIMAL_CURRENCIES = array( 'bif', 'clp', 'djf', 'gnf', 'jpy', 'kmf', 'krw', 'mga', 'pyg', 'rwf', 'vnd', 'vuv', 'xaf', 'xof', 'xpf' );

	private const SPECIAL_TWO_DECIMAL_CURRENCIES = array( 'isk', 'ugx' );

	private const THREE_DECIMAL_CURRENCIES = array( 'bhd', 'jod', 'kwd', 'omr', 'tnd' );

	private const MAX_STRIPE_AMOUNT_DIGITS = 12;

	public static function get_stripe_amount( $amount, $currency ) {
		$decimal  = self::to_decimal_string( $amount );
		$currency = strtolower( (string) $currency );

		if ( '' === $decimal ) {
			return 0;
		}

		if ( in_array( $currency, self::SPECIAL_TWO_DECIMAL_CURRENCIES, true ) ) {
			$minor = self::round_decimal_string( $decimal, 0 ) . '00';
		} elseif ( in_array( $currency, self::ZERO_DECIMAL_CURRENCIES, true ) ) {
			$minor = self::round_decimal_string( $decimal, 0 );
		} elseif ( in_array( $currency, self::THREE_DECIMAL_CURRENCIES, true ) ) {
			$minor = self::round_decimal_string( $decimal, 2 ) . '0';
		} else {
			$minor = self::round_decimal_string( $decimal, 2 );
		}

		$minor = ltrim( $minor, '0' );

		if ( strlen( $minor ) > self::MAX_STRIPE_AMOUNT_DIGITS ) {
			return 0;
		}

		return (int) $minor;
	}

	private static function to_decimal_string( $amount ) {
		if ( is_int( $amount ) ) {
			return $amount >= 0 ? (string) $amount : '';
		}

		if ( is_float( $amount ) ) {
			if ( ! is_finite( $amount ) || $amount < 0 ) {
				return '';
			}
			$amount = sprintf( '%.10F', $amount );
		}

		if ( ! is_string( $amount ) ) {
			return '';
		}

		$amount = trim( $amount );

		if ( 1 !== preg_match( '/^(?:\d+(?:\.\d*)?|\.\d+)\z/', $amount ) ) {
			return '';
		}

		return $amount;
	}

	private static function round_decimal_string( $decimal, $places ) {
		$parts    = explode( '.', $decimal, 2 );
		$integer  = '' === $parts[0] ? '0' : $parts[0];
		$fraction = isset( $parts[1] ) ? $parts[1] : '';
		$fraction = str_pad( $fraction, $places + 1, '0' );
		$digits   = $integer . substr( $fraction, 0, $places );
		$next     = (int) $fraction[ $places ];

		if ( $next >= 5 ) {
			$digits = self::increment_digit_string( $digits );
		}

		return $digits;
	}

	private static function increment_digit_string( $digits ) {
		for ( $i = strlen( $digits ) - 1; $i >= 0; $i-- ) {
			if ( '9' !== $digits[ $i ] ) {
				$digits[ $i ] = (string) ( (int) $digits[ $i ] + 1 );
				return $digits;
			}
			$digits[ $i ] = '0';
		}

		return '1' . $digits;
	}

	public static function is_debug_enabled() {
		$settings = get_option( 'woocommerce_paylumo_settings', array() );
		return is_array( $settings ) && isset( $settings['debug'] ) && 'yes' === $settings['debug'];
	}

	public static function log( $message, $level = 'info', $force = false ) {
		if ( ! $force && ! self::is_debug_enabled() ) {
			return;
		}

		if ( ! function_exists( 'wc_get_logger' ) ) {
			return;
		}

		wc_get_logger()->log( $level, (string) $message, array( 'source' => PAYLUMO_LOG_SOURCE ) );
	}
}
