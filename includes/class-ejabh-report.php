<?php
/**
 * Standalone security report.
 *
 * Produces a single self-contained HTML file that can be handed to the client
 * or opened in a browser and printed to PDF. No external assets, so it renders
 * identically offline.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Builds and serves the exportable report.
 */
class Ejabh_Report {

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'admin_post_dys_sec_report', array( $this, 'download' ) );
	}

	/**
	 * Stream the report as a download.
	 *
	 * @return void
	 */
	public function download() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_report' );

		$html     = self::build();
		$filename = 'security-report-' . gmdate( 'Y-m-d-Hi' ) . '.html';

		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . strlen( $html ) );

		Ejabh_Logger::log( 'report_exported', 'صُدِّر تقرير الحماية.', 'info' );

		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- fully built and escaped in build().
		exit;
	}

	/**
	 * Assemble the report document.
	 *
	 * @return string
	 */
	public static function build() {
		$counts     = Ejabh_Findings::counts();
		$file_state = Ejabh_File_Scanner::state();
		$db_state   = Ejabh_DB_Scanner::state();
		$int_state  = Ejabh_Integrity::state();
		$sessions   = Ejabh_Sessions::summary();
		$checks     = Ejabh_Hardening::checks();
		$findings   = Ejabh_Findings::get( '', 400 );

		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$total = array_sum( $counts );

		$verdict_class = 'ok';
		$verdict       = __( 'لم تُرصد مؤشرات اختراق.', 'ejabh-security' );
		if ( $counts['critical'] ) {
			$verdict_class = 'bad';
			$verdict       = __( 'توجد نتائج حرجة تستدعي تدخلاً فورياً.', 'ejabh-security' );
		} elseif ( $counts['high'] ) {
			$verdict_class = 'warn';
			$verdict       = __( 'توجد نتائج عالية الخطورة تحتاج مراجعة.', 'ejabh-security' );
		}

		ob_start();
		?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( sprintf( 'تقرير الحماية — %s', $site ) ); ?></title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI",Tahoma,Arial,sans-serif;line-height:1.7;color:#1d2327;background:#f6f7f7;margin:0;padding:24px}
.wrap{max-width:1000px;margin:0 auto;background:#fff;padding:32px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
h1{margin:0 0 4px;font-size:26px}
h2{margin:32px 0 12px;font-size:19px;border-bottom:2px solid #f0f0f1;padding-bottom:6px}
.meta{color:#646970;font-size:13px;margin-bottom:24px}
.verdict{padding:14px 18px;border-radius:6px;font-weight:600;margin:20px 0}
.verdict.ok{background:#edfaef;border-inline-start:4px solid #00a32a}
.verdict.warn{background:#fcf9e8;border-inline-start:4px solid #dba617}
.verdict.bad{background:#fcf0f1;border-inline-start:4px solid #d63638}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.card{flex:1 1 150px;border:1px solid #dcdcde;border-radius:6px;padding:12px 14px}
.card .n{font-size:24px;font-weight:700;display:block}
.card .l{font-size:12px;color:#646970}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}
th,td{text-align:start;padding:8px 10px;border-bottom:1px solid #f0f0f1;vertical-align:top}
th{background:#f6f7f7;font-size:12px;text-transform:none}
code{background:#f0f0f1;padding:1px 5px;border-radius:3px;font-size:12px;direction:ltr;display:inline-block;word-break:break-all}
.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap}
.b-critical{background:#d63638}.b-high{background:#e06d1f}.b-medium{background:#b8860b}.b-low{background:#607d8b}
.s-ok{color:#00a32a;font-weight:700}.s-warn{color:#dba617;font-weight:700}.s-fail{color:#d63638;font-weight:700}
.snip{background:#1d2327;color:#c3c4c7;padding:8px 10px;border-radius:3px;font-size:11px;direction:ltr;white-space:pre-wrap;word-break:break-all;margin:6px 0 0;max-height:120px;overflow:auto}
footer{margin-top:34px;padding-top:14px;border-top:1px solid #f0f0f1;color:#646970;font-size:12px}
@media print{body{background:#fff;padding:0}.wrap{box-shadow:none;padding:0}.snip{max-height:none}}
</style>
</head>
<body>
<div class="wrap">
	<h1><?php esc_html_e( 'تقرير حالة الحماية', 'ejabh-security' ); ?></h1>
	<div class="meta">
		<?php echo esc_html( $site ); ?> — <?php echo esc_html( home_url() ); ?><br>
		<?php
		printf(
			/* translators: 1: date, 2: WP version, 3: PHP version. */
			esc_html__( 'صدر في %1$s UTC · ووردبريس %2$s · PHP %3$s', 'ejabh-security' ),
			esc_html( gmdate( 'Y-m-d H:i' ) ),
			esc_html( get_bloginfo( 'version' ) ),
			esc_html( PHP_VERSION )
		);
		?>
	</div>

	<div class="verdict <?php echo esc_attr( $verdict_class ); ?>"><?php echo esc_html( $verdict ); ?></div>

	<div class="cards">
		<div class="card"><span class="n"><?php echo esc_html( number_format_i18n( $counts['critical'] ) ); ?></span><span class="l"><?php esc_html_e( 'حرج', 'ejabh-security' ); ?></span></div>
		<div class="card"><span class="n"><?php echo esc_html( number_format_i18n( $counts['high'] ) ); ?></span><span class="l"><?php esc_html_e( 'عالي', 'ejabh-security' ); ?></span></div>
		<div class="card"><span class="n"><?php echo esc_html( number_format_i18n( $counts['medium'] ) ); ?></span><span class="l"><?php esc_html_e( 'متوسط', 'ejabh-security' ); ?></span></div>
		<div class="card"><span class="n"><?php echo esc_html( number_format_i18n( $counts['low'] ) ); ?></span><span class="l"><?php esc_html_e( 'منخفض', 'ejabh-security' ); ?></span></div>
		<div class="card"><span class="n"><?php echo esc_html( number_format_i18n( $sessions['total'] ) ); ?></span><span class="l"><?php esc_html_e( 'جلسات نشطة', 'ejabh-security' ); ?></span></div>
	</div>

	<h2><?php esc_html_e( 'نطاق الفحص', 'ejabh-security' ); ?></h2>
	<table>
		<tr>
			<th style="width:32%"><?php esc_html_e( 'فحص الملفات', 'ejabh-security' ); ?></th>
			<td>
				<?php
				printf(
					/* translators: 1: files, 2: date. */
					esc_html__( '%1$s ملف — آخر تنفيذ: %2$s', 'ejabh-security' ),
					esc_html( number_format_i18n( $file_state['scanned'] ) ),
					esc_html( $file_state['finished'] ? gmdate( 'Y-m-d H:i', (int) $file_state['finished'] ) . ' UTC' : __( 'لم يُنفَّذ', 'ejabh-security' ) )
				);
				if ( ! empty( $file_state['core_stats']['checked'] ) ) {
					echo '<br>';
					printf(
						/* translators: 1: checked, 2: modified, 3: unknown. */
						esc_html__( 'نواة ووردبريس: %1$s ملف مُقارَن، %2$s مُعدَّل، %3$s ملف غريب', 'ejabh-security' ),
						esc_html( number_format_i18n( (int) $file_state['core_stats']['checked'] ) ),
						esc_html( number_format_i18n( (int) $file_state['core_stats']['modified'] ) ),
						esc_html( number_format_i18n( (int) $file_state['core_stats']['unknown'] ) )
					);
				}
				?>
			</td>
		</tr>
		<tr>
			<th><?php esc_html_e( 'فحص قاعدة البيانات', 'ejabh-security' ); ?></th>
			<td>
				<?php
				printf(
					/* translators: 1: rows, 2: date. */
					esc_html__( '%1$s صف — آخر تنفيذ: %2$s', 'ejabh-security' ),
					esc_html( number_format_i18n( $db_state['rows'] ) ),
					esc_html( $db_state['finished'] ? gmdate( 'Y-m-d H:i', (int) $db_state['finished'] ) . ' UTC' : __( 'لم يُنفَّذ', 'ejabh-security' ) )
				);
				?>
			</td>
		</tr>
		<tr>
			<th><?php esc_html_e( 'تدقيق نزاهة الإضافات', 'ejabh-security' ); ?></th>
			<td>
				<?php
				printf(
					/* translators: 1: verified, 2: modified, 3: unverifiable. */
					esc_html__( '%1$s مُتحقَّق · %2$s مُعدَّل · %3$s غير قابل للتحقق', 'ejabh-security' ),
					esc_html( number_format_i18n( (int) $int_state['verified'] ) ),
					esc_html( number_format_i18n( (int) $int_state['modified'] ) ),
					esc_html( number_format_i18n( (int) $int_state['unverifiable'] ) )
				);
				?>
			</td>
		</tr>
		<tr>
			<th><?php esc_html_e( 'مراقبة تغيّر الملفات', 'ejabh-security' ); ?></th>
			<td>
				<?php
				printf(
					/* translators: 1: baseline size, 2: new, 3: changed, 4: deleted. */
					esc_html__( 'خط أساس %1$s ملف — جديد: %2$s · مُعدَّل: %3$s · محذوف: %4$s', 'ejabh-security' ),
					esc_html( number_format_i18n( Ejabh_FIM::count() ) ),
					esc_html( number_format_i18n( (int) $file_state['fim_new'] ) ),
					esc_html( number_format_i18n( (int) $file_state['fim_changed'] ) ),
					esc_html( number_format_i18n( (int) $file_state['fim_gone'] ) )
				);
				?>
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'حالة التحصين', 'ejabh-security' ); ?></h2>
	<table>
		<thead><tr><th style="width:60px"><?php esc_html_e( 'الحالة', 'ejabh-security' ); ?></th><th style="width:30%"><?php esc_html_e( 'البند', 'ejabh-security' ); ?></th><th><?php esc_html_e( 'التفاصيل', 'ejabh-security' ); ?></th></tr></thead>
		<tbody>
		<?php foreach ( $checks as $check ) : ?>
			<?php
			$icon = 'ok' === $check['status'] ? '✔' : ( 'warn' === $check['status'] ? '!' : '✖' );
			?>
			<tr>
				<td class="s-<?php echo esc_attr( $check['status'] ); ?>"><?php echo esc_html( $icon ); ?></td>
				<td><?php echo esc_html( $check['label'] ); ?></td>
				<td><?php echo esc_html( $check['detail'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>

	<h2>
		<?php
		printf(
			/* translators: %s: findings count. */
			esc_html__( 'النتائج التفصيلية (%s)', 'ejabh-security' ),
			esc_html( number_format_i18n( $total ) )
		);
		?>
	</h2>
	<?php if ( ! $findings ) : ?>
		<p><?php esc_html_e( 'لا توجد نتائج مسجّلة. شغّل الفحوصات أولاً.', 'ejabh-security' ); ?></p>
	<?php else : ?>
		<table>
			<thead><tr><th style="width:60px"><?php esc_html_e( 'الخطورة', 'ejabh-security' ); ?></th><th><?php esc_html_e( 'النتيجة', 'ejabh-security' ); ?></th></tr></thead>
			<tbody>
			<?php foreach ( $findings as $row ) : ?>
				<tr>
					<td><span class="b b-<?php echo esc_attr( $row->severity ); ?>"><?php echo esc_html( $row->severity ); ?></span></td>
					<td>
						<strong><?php echo esc_html( $row->title ); ?></strong><br>
						<code><?php echo esc_html( $row->target ); ?><?php echo $row->line_no ? ':' . (int) $row->line_no : ''; ?></code>
						<?php if ( $row->snippet ) : ?>
							<div class="snip"><?php echo esc_html( $row->snippet ); ?></div>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<footer>
		<?php esc_html_e( 'أُنشئ هذا التقرير بواسطة Ejabh Security. النتائج بدرجة "منخفض" و"متوسط" غالباً كود مشروع في مكتبات خارجية — ابدأ المعالجة من الحرج ثم العالي.', 'ejabh-security' ); ?>
	</footer>
</div>
</body>
</html>
		<?php
		return (string) ob_get_clean();
	}
}
