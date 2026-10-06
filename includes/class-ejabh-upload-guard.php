<?php
/**
 * Upload interception.
 *
 * Inspects every file in $_FILES while the plugin is being included — before
 * `plugins_loaded`, so before any other plugin's upload handler runs. A shell
 * aimed at a vulnerable form, AJAX action or REST route is deleted from PHP's
 * temp directory and its $_FILES entry is turned into an ordinary upload
 * error, so the vulnerable code receives nothing to save.
 *
 * This runs before pluggable.php is loaded: no current user, no wp_mail().
 * Detections are queued and written to the log on `init`.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Blocks malicious uploads at request time.
 */
class Ejabh_Upload_Guard {

	/** Largest upload read in full. Bigger files are only checked by name. */
	const MAX_INSPECT_BYTES = 4194304;

	/**
	 * Detections waiting for `init`.
	 *
	 * @var array
	 */
	private static $queue = array();

	/**
	 * Inspect the current request's uploads.
	 *
	 * @return void
	 */
	public static function inspect_request() {
		if ( empty( $_FILES ) || ! Ejabh_Settings::get( 'upload_guard_enabled' ) ) {
			return;
		}

		foreach ( array_keys( $_FILES ) as $field ) {
			self::inspect_field( $field );
		}

		if ( self::$queue ) {
			add_action( 'init', array( __CLASS__, 'flush' ), 1 );
		}
	}

	/**
	 * One $_FILES field, single or multi-file (name="files[]").
	 *
	 * @param string $field Field name.
	 * @return void
	 */
	private static function inspect_field( $field ) {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification.Missing
		$entry = $_FILES[ $field ];

		if ( ! is_array( $entry ) || ! isset( $entry['tmp_name'] ) ) {
			return;
		}

		if ( ! is_array( $entry['tmp_name'] ) ) {
			if ( self::is_malicious( (string) $entry['tmp_name'], (string) ( $entry['name'] ?? '' ), $field ) ) {
				$_FILES[ $field ]['tmp_name'] = '';
				$_FILES[ $field ]['error']    = UPLOAD_ERR_EXTENSION;
				$_FILES[ $field ]['size']     = 0;
			}
			return;
		}

		// Multi-file fields; nested deeper than one level is unusual enough to
		// walk recursively rather than special-case.
		array_walk_recursive(
			$_FILES[ $field ]['tmp_name'],
			static function ( &$tmp, $key ) use ( $field ) {
				// Find the matching name by walking the same path; a flat
				// lookup is enough for the overwhelmingly common one-level case.
				$names = $_FILES[ $field ]['name'];
				$name  = is_array( $names ) && isset( $names[ $key ] ) && is_string( $names[ $key ] ) ? $names[ $key ] : '';

				if ( is_string( $tmp ) && self::is_malicious( $tmp, $name, $field ) ) {
					$tmp = '';
				}
			}
		);

		// A blanked tmp_name must also report an error, or handlers that only
		// check `error` would carry on with an empty path.
		self::mark_blanked( $_FILES[ $field ]['tmp_name'], $_FILES[ $field ]['error'] );
		// phpcs:enable
	}

	/**
	 * Set UPLOAD_ERR_EXTENSION wherever tmp_name was cleared.
	 *
	 * @param mixed $tmp   tmp_name (sub)tree.
	 * @param mixed $error error (sub)tree, same shape.
	 * @return void
	 */
	private static function mark_blanked( $tmp, &$error ) {
		if ( ! is_array( $tmp ) ) {
			return;
		}
		foreach ( $tmp as $key => $value ) {
			if ( is_array( $value ) ) {
				if ( isset( $error[ $key ] ) ) {
					self::mark_blanked( $value, $error[ $key ] );
				}
			} elseif ( '' === $value && isset( $error[ $key ] ) && UPLOAD_ERR_OK === (int) $error[ $key ] ) {
				$error[ $key ] = UPLOAD_ERR_EXTENSION;
			}
		}
	}

	/**
	 * Decide, and if malicious destroy the temp file.
	 *
	 * @param string $tmp   Temp path from PHP.
	 * @param string $name  Client-supplied file name.
	 * @param string $field Form field.
	 * @return bool True when the upload was blocked.
	 */
	private static function is_malicious( $tmp, $name, $field ) {
		if ( '' === $tmp || ! is_uploaded_file( $tmp ) ) {
			return false;
		}

		$size     = (int) @filesize( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$contents = '';
		if ( $size > 0 ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged
			$contents = (string) @file_get_contents( $tmp, false, null, 0, min( $size, self::MAX_INSPECT_BYTES ) );
		}

		$reason = self::verdict( $contents, $name );
		if ( null === $reason ) {
			return false;
		}

		self::keep_evidence( $contents, $name );
		@unlink( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink, WordPress.PHP.NoSilencedErrors.Discouraged

		self::$queue[] = array(
			'name'   => $name,
			'field'  => $field,
			'size'   => $size,
			'reason' => $reason,
			'uri'    => isset( $_SERVER['REQUEST_URI'] ) ? substr( (string) wp_unslash( $_SERVER['REQUEST_URI'] ), 0, 300 ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		);

		return true;
	}

	/**
	 * Why an upload must be refused, or null if it may proceed.
	 *
	 * @param string $contents Uploaded bytes (possibly truncated).
	 * @param string $name     Client-supplied file name.
	 * @return string|null
	 */
	public static function verdict( $contents, $name ) {
		// Archives are inert until someone extracts them, and backup formats
		// (All-in-One WP Migration's .wpress is uncompressed) contain the whole
		// site's PHP in plain text. Whatever comes out of one is caught by the
		// watcher and the file scan.
		if ( in_array( Ejabh_Threat_Detector::ext( $name ), array( 'zip', 'gz', 'tgz', 'tar', 'wpress', '7z', 'rar', 'bz2', 'xz' ), true )
			&& ! Ejabh_Threat_Detector::is_executable_name( $name ) ) {
			return null;
		}

		$has_php = Ejabh_Threat_Detector::has_php( $contents );

		// PHP code under a name the server will execute. Nothing on this site
		// accepts raw PHP over HTTP — plugins and themes arrive as .zip.
		if ( $has_php && Ejabh_Threat_Detector::is_executable_name( $name ) ) {
			return 'ملف PHP قابل للتنفيذ';
		}

		$hit = Ejabh_Threat_Detector::blocking_hit( Ejabh_Threat_Detector::examine( $contents, basename( $name ) ) );
		if ( $hit ) {
			return $hit['title'];
		}

		// PHP hidden inside an "image" or text file is a loader waiting for an
		// include(). Rare enough in genuine uploads to refuse outright.
		if ( $has_php && preg_match( '/<\?php\s/i', $contents ) ) {
			return 'كود PHP مخبّأ داخل ملف بامتداد غير تنفيذي';
		}

		return null;
	}

	/**
	 * Keep a copy of the payload for investigation, outside the web's reach.
	 *
	 * @param string $contents Bytes.
	 * @param string $name     Original name.
	 * @return void
	 */
	private static function keep_evidence( $contents, $name ) {
		if ( '' === $contents ) {
			return;
		}
		$dir  = Ejabh_Quarantine::dir();
		$safe = preg_replace( '/[^A-Za-z0-9._-]/', '_', basename( (string) $name ) );
		$file = $dir . '/' . gmdate( 'Ymd-His' ) . '-upload-' . substr( (string) $safe, 0, 60 ) . '.blocked';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		@file_put_contents( $file, $contents );
	}

	/**
	 * Write queued detections to the log (and so to the alert mail).
	 *
	 * @return void
	 */
	public static function flush() {
		foreach ( self::$queue as $item ) {
			Ejabh_Logger::log(
				'upload_blocked',
				sprintf(
					'اعتُرض ملف خبيث لحظة رفعه وحُذف قبل حفظه: "%1$s" (%2$s) — السبب: %3$s. الحقل: %4$s. الصفحة المستهدفة: %5$s',
					$item['name'],
					size_format( $item['size'] ),
					$item['reason'],
					$item['field'],
					$item['uri']
				),
				'critical'
			);
		}
		self::$queue = array();
	}
}
