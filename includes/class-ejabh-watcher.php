<?php
/**
 * New-file watcher.
 *
 * The upload guard only sees uploads that pass through WordPress. A shell that
 * arrives some other way — through another shell, FTP, a compromised hosting
 * account, a sibling site on the same server — never touches a WordPress
 * request. This job wakes every five minutes, finds PHP and HTML files created
 * or changed since the last pass, and quarantines or neutralises the ones that
 * match a high-confidence rule.
 *
 * Change is detected by max(mtime, ctime). Attackers routinely backdate mtime
 * with `touch -r` to blend in; ctime is set by the kernel and cannot be forged
 * from PHP.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Cron-driven detection of freshly planted files.
 */
class Ejabh_Watcher {

	const HOOK     = 'dys_sec_watch';
	const SCHEDULE = 'ejabh_sec_five_minutes';
	const STATE    = 'dys_sec_watch_state';

	/** Seconds of work per wake-up; an unfinished walk resumes next time. */
	const TIME_BUDGET = 8;

	/** Re-examine anything this close to the previous pass, for clock skew. */
	const SLACK = 120;

	/** Larger files are not read by the watcher (the full scan reports them). */
	const MAX_BYTES = 3145728;

	/**
	 * If one pass finds more than this, stop acting and ask a human — a burst
	 * that size is more likely a bad rule meeting a plugin update than an
	 * attacker, and silently quarantining a plugin would break the site.
	 */
	const MAX_ACTIONS_PER_PASS = 25;

	/**
	 * Lazily prepared checksum verifier.
	 *
	 * @var Ejabh_Verifier|null|false
	 */
	private $verifier = null;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_filter( 'cron_schedules', array( __CLASS__, 'add_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval
		add_action( self::HOOK, array( $this, 'run' ) );
	}

	/**
	 * Five-minute cron interval.
	 *
	 * @param array $schedules Existing schedules.
	 * @return array
	 */
	public static function add_schedule( $schedules ) {
		$schedules[ self::SCHEDULE ] = array(
			'interval' => 5 * MINUTE_IN_SECONDS,
			'display'  => 'Every five minutes (Ejabh Security watcher)',
		);
		return $schedules;
	}

	/**
	 * (Re)schedule according to settings.
	 *
	 * @return void
	 */
	public static function reschedule() {
		add_filter( 'cron_schedules', array( __CLASS__, 'add_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval

		$next = wp_next_scheduled( self::HOOK );

		if ( ! Ejabh_Settings::get( 'watch_enabled' ) ) {
			if ( $next ) {
				wp_unschedule_event( $next, self::HOOK );
			}
			return;
		}

		if ( ! $next ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, self::SCHEDULE, self::HOOK );
		}
	}

	/**
	 * Remove the schedule.
	 *
	 * @return void
	 */
	public static function unschedule() {
		$next = wp_next_scheduled( self::HOOK );
		while ( $next ) {
			wp_unschedule_event( $next, self::HOOK );
			$next = wp_next_scheduled( self::HOOK );
		}
	}

	/**
	 * Saved state merged over defaults.
	 *
	 * @return array
	 */
	public static function state() {
		$state = get_option( self::STATE, array() );
		return array_merge(
			array(
				'since'        => 0,  // Files changed at/after this are examined.
				'pass_started' => 0,
				'stack'        => array(),
				'last_pass'    => 0,
				'examined'     => 0,
				'actions'      => 0,
				'held'         => 0,  // 1 = too many hits, waiting for a human.
			),
			is_array( $state ) ? $state : array()
		);
	}

	/**
	 * One wake-up.
	 *
	 * @return void
	 */
	public function run() {
		if ( ! Ejabh_Settings::get( 'watch_enabled' ) ) {
			return;
		}

		$state = self::state();

		// First run: everything already on disk is the full scan's job. Start
		// watching from now.
		if ( ! $state['since'] ) {
			$state['since']     = time();
			$state['last_pass'] = time();
			update_option( self::STATE, $state, false );
			return;
		}

		if ( ! $state['stack'] ) {
			$state['stack']        = array( untrailingslashit( ABSPATH ) );
			$state['pass_started'] = time();
			$state['examined']     = 0;
			$state['actions']      = 0;
		}

		$threshold = (int) $state['since'] - self::SLACK;
		$deadline  = microtime( true ) + self::TIME_BUDGET;
		$skip      = $this->skip_list();

		while ( $state['stack'] && microtime( true ) < $deadline ) {
			$dir     = array_pop( $state['stack'] );
			$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $entries ) {
				continue;
			}

			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}

				$path = $dir . '/' . $entry;
				if ( is_link( $path ) ) {
					continue;
				}

				$rel = Ejabh_Core_Integrity::relative( $path );

				if ( is_dir( $path ) ) {
					if ( ! $this->skipped( $rel, $skip ) ) {
						$state['stack'][] = $path;
					}
					continue;
				}

				if ( ! $this->watched_extension( $entry ) ) {
					continue;
				}

				$changed = max( (int) @filemtime( $path ), (int) @filectime( $path ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( $changed < $threshold ) {
					continue;
				}

				++$state['examined'];
				if ( $this->examine( $path, $rel, $state ) ) {
					++$state['actions'];
				}
			}
		}

		if ( ! $state['stack'] ) {
			// Pass complete: next pass looks at what changed after this one began.
			$state['since']     = (int) $state['pass_started'];
			$state['last_pass'] = time();
		}

		update_option( self::STATE, $state, false );
	}

	/**
	 * Check one changed file and act on it.
	 *
	 * @param string $path  Absolute path.
	 * @param string $rel   Site-relative path.
	 * @param array  $state Pass state (by reference).
	 * @return bool True when a malicious file was found.
	 */
	private function examine( $path, $rel, array &$state ) {
		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( $size <= 0 || $size > self::MAX_BYTES ) {
			return false;
		}

		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents || self::is_stub( $contents ) ) {
			return false;
		}

		$hit = Ejabh_Threat_Detector::blocking_hit( Ejabh_Threat_Detector::examine( $contents, $rel ) );
		if ( ! $hit ) {
			return false;
		}

		// Byte-identical to an official core or plugin release: never touch it.
		$verifier = $this->verifier();
		if ( $verifier && $verifier->is_authentic( $rel, $contents ) ) {
			return false;
		}

		$action = (string) Ejabh_Settings::get( 'watch_action' );

		// Without checksums (api.wordpress.org unreachable) a core file cannot
		// be proven genuine, and quarantining a real one breaks the site. Core
		// tampering is the integrity scan's job; here we only report.
		if ( ! $verifier && ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) ) {
			$action = 'report';
		}

		if ( $state['held'] || $state['actions'] >= self::MAX_ACTIONS_PER_PASS ) {
			if ( ! $state['held'] ) {
				$state['held'] = 1;
				Ejabh_Logger::log(
					'watch_held',
					sprintf( 'المراقب وجد أكثر من %d ملفاً خبيثاً في دورة واحدة، فأوقف الإجراءات التلقائية ويكتفي بالتبليغ حتى يراجعها شخص. شغّل فحص الملفات الكامل.', self::MAX_ACTIONS_PER_PASS ),
					'critical'
				);
			}
			$action = 'report';
		}

		$result = $this->act( $path, $rel, $hit, $action );

		Ejabh_Findings::add(
			array(
				'scan_id'   => 'watch',
				'scan_type' => 'file',
				'severity'  => 'critical',
				'rule'      => 'report' === $result ? $hit['id'] : 'watcher_neutralised',
				'title'     => 'report' === $result
					? $hit['title']
					: sprintf( 'حُجر تلقائياً: %s', $hit['title'] ),
				'target'    => $rel,
				'snippet'   => trim( (string) preg_replace( '/\s+/', ' ', substr( $contents, max( 0, $hit['offset'] - 120 ), 400 ) ) ),
			)
		);

		$labels = array(
			'quarantine' => 'نُقل إلى الحجر الصحي',
			'neutralize' => 'أُفرغ محتواه (نسخة منه في الحجر الصحي)',
			'report'     => 'لم يُمَسّ — تبليغ فقط',
			'failed'     => 'تعذّر عزله — يجب حذفه يدوياً فوراً',
		);

		Ejabh_Logger::log(
			'report' === $result || 'failed' === $result ? 'watch_detected' : 'watch_neutralised',
			sprintf(
				'ظهر ملف خبيث على السيرفر: %1$s — %2$s. الإجراء: %3$s. آخر تعديل: %4$s UTC.',
				$rel,
				$hit['title'],
				$labels[ $result ],
				gmdate( 'Y-m-d H:i', max( (int) @filemtime( $path ), (int) @filectime( $path ) ) ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			),
			'critical'
		);

		return true;
	}

	/**
	 * Carry out the configured response.
	 *
	 * @param string $path   Absolute path.
	 * @param string $rel    Site-relative path.
	 * @param array  $hit    Matching rule.
	 * @param string $action quarantine|neutralize|report.
	 * @return string What actually happened: quarantine|neutralize|report|failed.
	 */
	private function act( $path, $rel, array $hit, $action ) {
		if ( 'report' === $action ) {
			return 'report';
		}

		$reason  = 'المراقب التلقائي: ' . $hit['title'];
		$capture = Ejabh_Quarantine::capture( $path, $reason );

		if ( empty( $capture['ok'] ) ) {
			// Files the site cannot boot without are never touched: emptying an
			// infected wp-config.php takes the whole site down. A human fixes those.
			if ( self::untouchable( $path, $rel ) ) {
				return 'failed';
			}
			// Otherwise the refusal was permissions on the directory; emptying
			// in place needs only write access to the file itself.
			return $this->write_stub( $path, $rel, $hit ) ? 'neutralize' : 'failed';
		}

		if ( 'neutralize' === $action ) {
			// Leave an inert file behind. Some droppers re-create a missing
			// file on the next request; a present, harmless one stops that.
			$this->write_stub( $path, $rel, $hit );
			return 'neutralize';
		}

		return 'quarantine';
	}

	/**
	 * Replace a file with an inert placeholder.
	 *
	 * @param string $path Absolute path.
	 * @param string $rel  Site-relative path.
	 * @param array  $hit  Matching rule.
	 * @return bool
	 */
	private function write_stub( $path, $rel, array $hit ) {
		$note = sprintf( 'Neutralised by Ejabh Security %s UTC — rule %s. Original kept in quarantine.', gmdate( 'Y-m-d H:i' ), $hit['id'] );

		$stub = in_array( Ejabh_Threat_Detector::ext( $rel ), Ejabh_Threat_Detector::PHP_EXT, true )
			? "<?php\n// {$note}\nhttp_response_code( 404 );\nexit;\n"
			: "<!-- {$note} -->\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		return false !== @file_put_contents( $path, $stub );
	}

	/**
	 * Files the watcher may report but never modify.
	 *
	 * @param string $path Absolute path.
	 * @param string $rel  Site-relative path.
	 * @return bool
	 */
	private static function untouchable( $path, $rel ) {
		$boot = array( 'wp-config.php', 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', '.htaccess' );
		if ( in_array( $rel, $boot, true ) ) {
			return true;
		}

		$real = wp_normalize_path( (string) realpath( $path ) );

		// This plugin, and the pre-rename copy if its folder is still present:
		// both hold the attack patterns as data.
		foreach ( array( EJABH_SEC_DIR, WP_PLUGIN_DIR . '/dys-security' ) as $dir ) {
			$own = wp_normalize_path( (string) realpath( $dir ) );
			if ( '' !== $own && '/' !== $own && 0 === strpos( $real, trailingslashit( $own ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Is this one of our own placeholders?
	 *
	 * @param string $contents File contents.
	 * @return bool
	 */
	public static function is_stub( $contents ) {
		return strlen( $contents ) < 400 && false !== strpos( $contents, 'Neutralised by Ejabh Security' );
	}

	/**
	 * Checksum verifier, prepared on first use.
	 *
	 * @return Ejabh_Verifier|null
	 */
	private function verifier() {
		if ( null === $this->verifier ) {
			$verifier = new Ejabh_Verifier();
			$verifier->prepare();
			$this->verifier = $verifier->has_reference() ? $verifier : false;
		}
		return $this->verifier ? $this->verifier : null;
	}

	/**
	 * Only executable code and rendered pages are watched.
	 *
	 * @param string $name File name.
	 * @return bool
	 */
	private function watched_extension( $name ) {
		$ext = Ejabh_Threat_Detector::ext( $name );
		return in_array( $ext, Ejabh_Threat_Detector::PHP_EXT, true )
			|| in_array( $ext, Ejabh_Threat_Detector::MARKUP_EXT, true )
			|| Ejabh_Threat_Detector::is_executable_name( $name );
	}

	/**
	 * Directories never walked.
	 *
	 * @return array Site-relative prefixes.
	 */
	private function skip_list() {
		$skip = (array) Ejabh_Settings::get( 'scan_skip_dirs' );

		// Our own evidence stores hold malware on purpose.
		$skip[] = 'wp-content/dys-quarantine';
		$skip[] = 'wp-content/dys-security-backups';

		return array_values( array_filter( array_map( 'trim', $skip ) ) );
	}

	/**
	 * Should this directory be skipped?
	 *
	 * @param string $rel  Site-relative path.
	 * @param array  $skip Prefixes / fragments.
	 * @return bool
	 */
	private function skipped( $rel, array $skip ) {
		foreach ( $skip as $fragment ) {
			if ( $rel === $fragment || 0 === strpos( $rel, $fragment . '/' ) || preg_match( '#(?:^|/)' . preg_quote( $fragment, '#' ) . '$#', $rel ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Clear the "held" flag after a human has reviewed a burst.
	 *
	 * @return void
	 */
	public static function release_hold() {
		$state         = self::state();
		$state['held'] = 0;
		update_option( self::STATE, $state, false );
	}
}
