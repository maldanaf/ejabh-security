<?php
/**
 * Self-updates from GitHub Releases, with signature verification.
 *
 * WordPress only knows about updates for plugins hosted on wordpress.org. This
 * teaches it to look at this plugin's GitHub releases instead, so publishing a
 * release reaches every site running the plugin — and, with auto-update on,
 * installs itself without anyone logging in to each site.
 *
 * An updater is also a way in: whoever can publish a release can run code on
 * every site. So each release zip must carry an Ed25519 signature made with a
 * private key that never leaves the maintainer's machine (not GitHub, not CI).
 * A package whose signature does not verify against the public key below is
 * refused before WordPress unpacks it — a hijacked GitHub account alone cannot
 * push code to the sites.
 *
 * Optional wp-config.php constants:
 *   EJABH_SEC_UPDATE_REPO    "owner/repo" (default below).
 *   EJABH_SEC_GITHUB_TOKEN   Read-only token, required if the repo is private.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * GitHub release updater.
 */
class Ejabh_Updater {

	/** Default "owner/repo"; override with EJABH_SEC_UPDATE_REPO. */
	const DEFAULT_REPO = 'maldanaf/ejabh-security';

	/** Ed25519 public key (hex) that release zips are signed with. */
	const PUBLIC_KEY = 'af148abbe4567a5247d60f838a291b7a5672562d539f4268a9c06f7bffb930ad';

	/** Release asset names. */
	const ASSET     = 'ejabh-security.zip';
	const SIGNATURE = 'ejabh-security.zip.sig';

	const CACHE = 'dys_sec_update_release';

	/** Plugin slug as WordPress sees it. */
	const SLUG = 'ejabh-security';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'inject_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugin_info' ), 20, 3 );
		add_filter( 'upgrader_pre_download', array( $this, 'verified_download' ), 10, 4 );
		add_filter( 'upgrader_source_selection', array( $this, 'fix_folder_name' ), 10, 4 );
		add_filter( 'auto_update_plugin', array( $this, 'auto_update' ), 10, 2 );
	}

	/**
	 * "owner/repo".
	 *
	 * @return string
	 */
	public static function repo() {
		$repo = defined( 'EJABH_SEC_UPDATE_REPO' ) ? (string) EJABH_SEC_UPDATE_REPO : self::DEFAULT_REPO;
		return preg_match( '#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $repo ) ? $repo : '';
	}

	/**
	 * Headers for GitHub API calls.
	 *
	 * @param string $accept Accept header.
	 * @return array
	 */
	private static function headers( $accept = 'application/vnd.github+json' ) {
		$headers = array(
			'Accept'               => $accept,
			'User-Agent'           => 'Ejabh-Security/' . EJABH_SEC_VERSION,
			'X-GitHub-Api-Version' => '2022-11-28',
		);
		if ( defined( 'EJABH_SEC_GITHUB_TOKEN' ) && EJABH_SEC_GITHUB_TOKEN ) {
			$headers['Authorization'] = 'Bearer ' . EJABH_SEC_GITHUB_TOKEN;
		}
		return $headers;
	}

	/**
	 * The latest published release, cached for six hours.
	 *
	 * @return array|null {version, zip, sig, notes, url, published}
	 */
	public static function latest() {
		$repo = self::repo();
		if ( ! $repo ) {
			return null;
		}

		// "Check again" on Dashboard → Updates should really check again.
		$force = is_admin() && isset( $_GET['force-check'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$cached = get_site_transient( self::CACHE );
		if ( ! $force && is_array( $cached ) ) {
			return $cached['release'];
		}

		$response = wp_remote_get(
			'https://api.github.com/repos/' . $repo . '/releases/latest',
			array(
				'timeout' => 10,
				'headers' => self::headers(),
			)
		);

		$release = null;
		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$release = self::parse( json_decode( (string) wp_remote_retrieve_body( $response ), true ) );
		}

		// Cache failures too (for an hour) so an unreachable GitHub does not
		// slow down every admin page.
		set_site_transient( self::CACHE, array( 'release' => $release ), $release ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );

		return $release;
	}

	/**
	 * Pull what we need out of the API response.
	 *
	 * @param mixed $data Decoded JSON.
	 * @return array|null
	 */
	private static function parse( $data ) {
		if ( ! is_array( $data ) || empty( $data['tag_name'] ) || ! empty( $data['draft'] ) || ! empty( $data['prerelease'] ) ) {
			return null;
		}

		$version = ltrim( (string) $data['tag_name'], 'vV' );
		if ( ! preg_match( '/^\d+\.\d+(?:\.\d+)?$/', $version ) ) {
			return null;
		}

		$zip = '';
		$sig = '';
		foreach ( (array) ( $data['assets'] ?? array() ) as $asset ) {
			// The API URL works for public and private repos alike (with a
			// token); browser_download_url does not for private ones.
			if ( self::ASSET === ( $asset['name'] ?? '' ) ) {
				$zip = (string) $asset['url'];
			} elseif ( self::SIGNATURE === ( $asset['name'] ?? '' ) ) {
				$sig = (string) $asset['url'];
			}
		}

		// An unsigned release is not a release we will offer.
		if ( ! $zip || ! $sig ) {
			return null;
		}

		return array(
			'version'   => $version,
			'zip'       => $zip,
			'sig'       => $sig,
			'notes'     => (string) ( $data['body'] ?? '' ),
			'url'       => (string) ( $data['html_url'] ?? '' ),
			'published' => (string) ( $data['published_at'] ?? '' ),
		);
	}

	/**
	 * Tell WordPress an update exists.
	 *
	 * @param mixed $transient update_plugins transient.
	 * @return mixed
	 */
	public function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}

		$release = self::latest();
		if ( ! $release ) {
			return $transient;
		}

		$item = (object) array(
			'id'           => 'github.com/' . self::repo(),
			'slug'         => self::SLUG,
			'plugin'       => EJABH_SEC_BASENAME,
			'new_version'  => $release['version'],
			'url'          => $release['url'],
			'package'      => $release['zip'],
			'tested'       => '7.0',
			'requires_php' => '7.4',
			'icons'        => array(),
			'banners'      => array(),
		);

		if ( version_compare( $release['version'], EJABH_SEC_VERSION, '>' ) ) {
			$transient->response[ EJABH_SEC_BASENAME ] = $item;
			unset( $transient->no_update[ EJABH_SEC_BASENAME ] );
		} else {
			// Listing it under no_update is what makes the auto-update toggle
			// appear on the Plugins screen.
			$transient->no_update[ EJABH_SEC_BASENAME ] = $item;
			unset( $transient->response[ EJABH_SEC_BASENAME ] );
		}

		return $transient;
	}

	/**
	 * "View details" popup.
	 *
	 * @param mixed  $result Default result.
	 * @param string $action API action.
	 * @param object $args   Arguments.
	 * @return mixed
	 */
	public function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! isset( $args->slug ) || self::SLUG !== $args->slug ) {
			return $result;
		}

		$release = self::latest();

		return (object) array(
			'name'          => 'Ejabh Security',
			'slug'          => self::SLUG,
			'version'       => $release ? $release['version'] : EJABH_SEC_VERSION,
			'author'        => 'Ejabh',
			'homepage'      => $release ? $release['url'] : '',
			'requires'      => '6.4',
			'tested'        => '7.0',
			'requires_php'  => '7.4',
			'last_updated'  => $release ? $release['published'] : '',
			'download_link' => $release ? $release['zip'] : '',
			'sections'      => array(
				'changelog' => $release && $release['notes'] ? wpautop( esc_html( $release['notes'] ) ) : '',
			),
		);
	}

	/**
	 * Download our package ourselves and refuse it unless the signature checks.
	 *
	 * @param mixed       $reply    False to let WordPress download.
	 * @param string      $package  Package URL.
	 * @param WP_Upgrader $upgrader Upgrader.
	 * @param array       $hook_extra Extra.
	 * @return mixed Local file path, WP_Error, or $reply untouched.
	 */
	public function verified_download( $reply, $package, $upgrader = null, $hook_extra = array() ) {
		$release = self::latest();
		if ( false !== $reply || ! $release || $package !== $release['zip'] ) {
			return $reply;
		}

		$sig = self::fetch( $release['sig'] );
		if ( is_wp_error( $sig ) ) {
			return $sig;
		}

		$zip = self::fetch( $release['zip'] );
		if ( is_wp_error( $zip ) ) {
			return $zip;
		}

		if ( ! self::signature_valid( $zip, $sig ) ) {
			Ejabh_Logger::log(
				'update_signature_invalid',
				sprintf( 'رُفض تحديث Ejabh Security %s: توقيع الحزمة غير صحيح. قد يكون حساب GitHub أو الإصدار مخترقاً — لا تثبّته يدوياً وتحقق من المستودع.', $release['version'] ),
				'critical'
			);
			return new WP_Error( 'ejabh_bad_signature', __( 'توقيع حزمة التحديث غير صحيح — رُفض التثبيت حمايةً للموقع.', 'ejabh-security' ) );
		}

		$tmp = wp_tempnam( self::ASSET );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( ! $tmp || false === file_put_contents( $tmp, $zip ) ) {
			return new WP_Error( 'ejabh_tmp', __( 'تعذّر حفظ حزمة التحديث مؤقتاً.', 'ejabh-security' ) );
		}

		Ejabh_Logger::log( 'update_verified', sprintf( 'تحقق توقيع تحديث Ejabh Security %s وبدأ التثبيت.', $release['version'] ), 'info' );

		return $tmp;
	}

	/**
	 * Does the detached signature match the bytes?
	 *
	 * @param string $data Package bytes.
	 * @param string $sig  Signature file contents (hex or raw).
	 * @return bool
	 */
	public static function signature_valid( $data, $sig ) {
		$sig = trim( (string) $sig );
		if ( 128 === strlen( $sig ) && ctype_xdigit( $sig ) ) {
			$sig = sodium_hex2bin( $sig );
		}
		if ( SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return false;
		}

		try {
			return sodium_crypto_sign_verify_detached( $sig, $data, sodium_hex2bin( self::PUBLIC_KEY ) );
		} catch ( Throwable $e ) {
			return false;
		}
	}

	/**
	 * Download a release asset into memory.
	 *
	 * @param string $url API asset URL.
	 * @return string|WP_Error
	 */
	private static function fetch( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout' => 60,
				'headers' => self::headers( 'application/octet-stream' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'ejabh_download', sprintf( 'GitHub HTTP %d', (int) wp_remote_retrieve_response_code( $response ) ) );
		}

		return (string) wp_remote_retrieve_body( $response );
	}

	/**
	 * Make sure the unpacked folder is "ejabh-security", whatever the zip's
	 * top-level directory is called — otherwise WordPress installs a second
	 * copy beside the first.
	 *
	 * @param string      $source        Unpacked source dir.
	 * @param string      $remote_source Parent dir.
	 * @param WP_Upgrader $upgrader      Upgrader.
	 * @param array       $hook_extra    Extra.
	 * @return string|WP_Error
	 */
	public function fix_folder_name( $source, $remote_source, $upgrader = null, $hook_extra = array() ) {
		if ( empty( $hook_extra['plugin'] ) || EJABH_SEC_BASENAME !== $hook_extra['plugin'] ) {
			return $source;
		}

		$wanted = trailingslashit( $remote_source ) . self::SLUG . '/';
		if ( trailingslashit( $source ) === $wanted ) {
			return $source;
		}

		global $wp_filesystem;
		if ( $wp_filesystem && $wp_filesystem->move( $source, $wanted, true ) ) {
			return $wanted;
		}

		return new WP_Error( 'ejabh_folder', __( 'تعذّرت تهيئة مجلد التحديث.', 'ejabh-security' ) );
	}

	/**
	 * Auto-update this plugin when the setting is on.
	 *
	 * @param bool|null $update Current decision.
	 * @param object    $item   Update item.
	 * @return bool|null
	 */
	public function auto_update( $update, $item ) {
		if ( isset( $item->plugin ) && EJABH_SEC_BASENAME === $item->plugin && Ejabh_Settings::get( 'auto_update_self' ) ) {
			return true;
		}
		return $update;
	}
}
