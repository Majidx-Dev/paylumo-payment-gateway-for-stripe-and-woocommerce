<?php

namespace Paylumo\StripeGateway;

defined( 'ABSPATH' ) || exit;

use Throwable;
use WP_Error;

final class Secrets {
	private const VAULT_OPTION = 'paylumo_secrets_vault';

	private const VAULT_CHECK = 'paylumo-vault-ok';

	private const LEGACY_CONFIG_OPTION = 'paylumo_secrets_file';

	private const LEGACY_CHECK_TRANSIENT = 'paylumo_secrets_public_check';

	private static $values = null;

	private static $vault_broken = false;

	private static $migrating = false;

	public static function get( $name ) {
		$values = self::store_values();
		return isset( $values[ (string) $name ] ) ? $values[ (string) $name ] : '';
	}

	public static function write( array $values ) {
		$clean = array();
		foreach ( $values as $name => $value ) {
			if ( self::is_name( (string) $name ) && self::is_safe_value( (string) $value ) ) {
				$clean[ (string) $name ] = (string) $value;
			}
		}

		if ( empty( $clean ) ) {
			return true;
		}

		$merged  = self::sorted( array_merge( self::store_values(), $clean ) );
		$written = self::write_vault( $merged );

		if ( true !== $written ) {
			return $written;
		}

		self::$values = null;
		if ( self::store_values() !== $merged ) {
			return new WP_Error( 'paylumo_secrets_verify', 'The secrets could not be read back.' );
		}

		return true;
	}

	public static function remove( array $names ) {
		$left = array_diff_key( self::store_values(), array_flip( array_map( 'strval', $names ) ) );

		if ( $left === self::store_values() ) {
			return true;
		}

		$written = self::write_vault( $left );
		if ( true !== $written ) {
			return $written;
		}

		self::$values = null;
		if ( self::store_values() !== self::sorted( $left ) ) {
			return new WP_Error( 'paylumo_secrets_verify', 'The secrets could not be read back.' );
		}

		return true;
	}

	public static function vault_is_broken() {
		self::store_values();
		return self::$vault_broken;
	}

	public static function ignored_sources() {
		$found = array();
		foreach ( array( 'PAYLUMO_TEST_SECRET_KEY', 'PAYLUMO_TEST_WEBHOOK_SECRET', 'PAYLUMO_LIVE_SECRET_KEY', 'PAYLUMO_LIVE_WEBHOOK_SECRET', 'PAYLUMO_ENV_FILE' ) as $name ) {
			if ( defined( $name ) || false !== getenv( $name ) ) {
				$found[] = $name;
			}
		}

		return $found;
	}

	public static function migrate_legacy_store() {
		if ( self::$migrating ) {
			return;
		}

		self::$migrating = true;
		self::migrate_legacy_file();
		self::$migrating = false;
	}

	private static function migrate_legacy_file() {
		$config = get_option( self::LEGACY_CONFIG_OPTION );
		if ( false === $config ) {
			return;
		}

		$config = is_array( $config ) ? $config : array();
		$path   = isset( $config['path'] ) && is_string( $config['path'] ) ? $config['path'] : '';
		$store  = isset( $config['store'] ) && is_string( $config['store'] ) ? $config['store'] : ( '' !== $path ? 'file' : '' );

		if ( in_array( $store, array( 'file', 'php' ), true ) && self::is_legacy_file( $path ) && is_file( $path ) ) {
			if ( ! is_readable( $path ) ) {
				return;
			}

			$values = self::read_legacy_file( $path );
			if ( ! empty( $values ) && true !== self::write( $values ) ) {
				return;
			}

			if ( ! unlink( $path ) ) {
				return;
			}
		}

		delete_option( self::LEGACY_CONFIG_OPTION );
		delete_transient( self::LEGACY_CHECK_TRANSIENT );
	}

	private static function store_values() {
		if ( null === self::$values ) {
			self::$vault_broken = false;
			self::$values       = self::read_vault();

			if ( ! self::$migrating && empty( self::$values ) && ! self::$vault_broken && false !== get_option( self::LEGACY_CONFIG_OPTION ) ) {
				self::migrate_legacy_store();
				self::$values = self::read_vault();
			}
		}

		return self::$values;
	}

	private static function read_vault() {
		$vault = get_option( self::VAULT_OPTION );
		if ( ! is_array( $vault ) || empty( $vault['values'] ) || ! is_array( $vault['values'] ) ) {
			return array();
		}

		$key = self::vault_key();
		if ( '' === $key || self::VAULT_CHECK !== self::decrypt( (string) ( $vault['check'] ?? '' ), $key ) ) {
			self::$vault_broken = true;
			return array();
		}

		$values = array();
		foreach ( $vault['values'] as $name => $cipher ) {
			$plain = self::decrypt( (string) $cipher, $key );
			if ( self::is_name( (string) $name ) && is_string( $plain ) && self::is_safe_value( $plain ) ) {
				$values[ (string) $name ] = $plain;
			} else {
				self::$vault_broken = true;
			}
		}

		return self::sorted( $values );
	}

	private static function write_vault( array $values ) {
		$key = self::vault_key();
		if ( '' === $key ) {
			return new WP_Error( 'paylumo_secrets_sodium', 'Encryption is not available on this server.' );
		}

		$vault = array( 'v' => 1, 'check' => self::encrypt( self::VAULT_CHECK, $key ), 'values' => array() );
		foreach ( $values as $name => $value ) {
			$vault['values'][ $name ] = self::encrypt( $value, $key );
		}

		update_option( self::VAULT_OPTION, $vault, false );
		return true;
	}

	private static function vault_key() {
		if ( ! function_exists( 'sodium_crypto_secretbox' ) || ! function_exists( 'sodium_crypto_generichash' ) ) {
			return '';
		}

		$material = '';
		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY' ) as $constant ) {
			if ( defined( $constant ) && 'put your unique phrase here' !== constant( $constant ) ) {
				$material .= (string) constant( $constant );
			}
		}

		if ( '' === $material ) {
			$material = wp_salt( 'secure_auth' );
		}

		return sodium_crypto_generichash( 'paylumo-payment-gateway-for-stripe-and-woocommerce|vault|' . $material, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
	}

	private static function encrypt( $plain, $key ) {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return base64_encode( $nonce . sodium_crypto_secretbox( (string) $plain, $nonce, $key ) );
	}

	private static function decrypt( $encoded, $key ) {
		$raw = base64_decode( (string) $encoded, true );
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return false;
		}

		try {
			return sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $key );
		} catch ( Throwable $e ) {
			return false;
		}
	}

	private static function is_legacy_file( $path ) {
		$explicit = defined( 'PAYLUMO_ENV_FILE' ) && PAYLUMO_ENV_FILE === $path;
		return '' !== $path && ! $explicit && ! is_link( $path ) && 1 === preg_match( '/(?:-stripe\.env|\/paylumo-secrets-[a-z0-9]+\.php)\z/', $path );
	}

	private static function read_legacy_file( $path ) {
		$lines = is_file( $path ) && is_readable( $path ) ? file( $path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) : false;
		if ( ! is_array( $lines ) ) {
			return array();
		}

		$values = array();
		foreach ( $lines as $line ) {
			if ( 1 === preg_match( '/^\s*(?:export\s+)?(PAYLUMO_[A-Z0-9_]+)\s*=\s*["\']?([A-Za-z0-9_]+)["\']?\s*\z/', $line, $match ) ) {
				$values[ $match[1] ] = $match[2];
			}
		}

		return $values;
	}

	private static function is_name( $name ) {
		return 1 === preg_match( '/^PAYLUMO_[A-Z0-9_]+\z/', (string) $name );
	}

	public static function is_safe_value( $value ) {
		return 1 === preg_match( '/^[A-Za-z0-9_]+\z/', (string) $value );
	}

	private static function sorted( array $values ) {
		ksort( $values );
		return $values;
	}
}
