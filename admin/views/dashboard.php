<?php
/**
 * Security dashboard.
 *
 * @package Ejabh_Security
 *
 * @var Ejabh_Admin $admin
 * @var array     $counts
 * @var array     $file_counts
 * @var array     $db_counts
 * @var array     $sessions
 * @var array     $file_state
 * @var array     $db_state
 * @var array     $top
 * @var array     $log
 */

defined( 'ABSPATH' ) || exit;

$owner      = get_userdata( Ejabh_Settings::owner_id() );
$twofa_on   = (bool) Ejabh_Settings::get( '2fa_enabled' );
$guard_on   = (bool) Ejabh_Settings::get( 'guard_enabled' );
$caps_on    = (bool) Ejabh_Settings::get( 'caps_enabled' );
$bypassed   = Ejabh_2FA::bypassed();
$total_open = array_sum( $counts );
?>
<div class="wrap ejabh-wrap">
	<h1><span class="dashicons dashicons-shield-alt"></span> <?php esc_html_e( 'لوحة الحماية', 'ejabh-security' ); ?></h1>

	<?php if ( $bypassed ) : ?>
		<div class="notice notice-error">
			<p><strong><?php esc_html_e( 'تحذير: المصادقة الثنائية معطّلة حالياً بواسطة الثابت EJABH_SEC_2FA_BYPASS في wp-config.php.', 'ejabh-security' ); ?></strong>
			<?php esc_html_e( 'هذا مخصص للطوارئ فقط — احذف السطر بعد حل المشكلة.', 'ejabh-security' ); ?></p>
		</div>
	<?php endif; ?>

	<?php $watch = Ejabh_Watcher::state(); ?>
	<?php if ( ! empty( $watch['held'] ) ) : ?>
		<div class="notice notice-error">
			<p><strong><?php esc_html_e( 'مراقب الملفات أوقف الإجراءات التلقائية:', 'ejabh-security' ); ?></strong>
			<?php esc_html_e( 'وجد ملفات خبيثة كثيرة في دورة واحدة، فصار يبلّغ عنها دون حجرها. راجع النتائج في «فحص الملفات» وتصرّف فيها، ثم أعد تفعيل الحجر التلقائي.', 'ejabh-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0 0 10px;">
				<?php wp_nonce_field( 'dys_sec_watch_release' ); ?>
				<input type="hidden" name="action" value="dys_sec_watch_release" />
				<button type="submit" class="button"><?php esc_html_e( 'راجعتُها — أعِد تفعيل الحجر التلقائي', 'ejabh-security' ); ?></button>
			</form>
		</div>
	<?php endif; ?>

	<?php if ( $counts['critical'] ) : ?>
		<div class="notice notice-error">
			<p><strong>
			<?php
			printf(
				/* translators: %s: number of critical findings. */
				esc_html__( 'يوجد %s نتيجة حرجة تحتاج تدخلاً فورياً.', 'ejabh-security' ),
				esc_html( number_format_i18n( $counts['critical'] ) )
			);
			?>
			</strong></p>
		</div>
	<?php endif; ?>

	<div class="ejabh-grid">
		<div class="ejabh-card ejabh-card--<?php echo $counts['critical'] ? 'danger' : ( $counts['high'] ? 'warn' : 'ok' ); ?>">
			<span class="ejabh-card__label"><?php esc_html_e( 'نتائج الفحص المفتوحة', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $total_open ) ); ?></span>
			<span class="ejabh-card__meta">
				<?php
				printf(
					/* translators: 1: critical, 2: high, 3: medium, 4: low. */
					esc_html__( 'حرج %1$s · عالي %2$s · متوسط %3$s · منخفض %4$s', 'ejabh-security' ),
					esc_html( number_format_i18n( $counts['critical'] ) ),
					esc_html( number_format_i18n( $counts['high'] ) ),
					esc_html( number_format_i18n( $counts['medium'] ) ),
					esc_html( number_format_i18n( $counts['low'] ) )
				);
				?>
			</span>
		</div>

		<div class="ejabh-card">
			<span class="ejabh-card__label"><?php esc_html_e( 'جلسات دخول نشطة', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $sessions['total'] ) ); ?></span>
			<span class="ejabh-card__meta">
				<?php
				printf(
					/* translators: 1: admin sessions, 2: users, 3: unique IPs. */
					esc_html__( 'منها %1$s لمديرين · %2$s مستخدم · %3$s عنوان IP', 'ejabh-security' ),
					esc_html( number_format_i18n( $sessions['admins'] ) ),
					esc_html( number_format_i18n( $sessions['users'] ) ),
					esc_html( number_format_i18n( $sessions['unique_ips'] ) )
				);
				?>
			</span>
			<a class="ejabh-card__link" href="<?php echo esc_url( admin_url( 'admin.php?page=ejabh-security-sessions' ) ); ?>"><?php esc_html_e( 'عرض الجلسات ←', 'ejabh-security' ); ?></a>
		</div>

		<div class="ejabh-card">
			<span class="ejabh-card__label"><?php esc_html_e( 'آخر فحص للملفات', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value">
				<?php
				echo $file_state['finished']
					? esc_html( $admin->ago( (int) $file_state['finished'] ) )
					: esc_html__( 'لم يُنفَّذ', 'ejabh-security' );
				?>
			</span>
			<span class="ejabh-card__meta">
				<?php
				printf(
					/* translators: 1: files scanned, 2: findings. */
					esc_html__( '%1$s ملف · %2$s نتيجة', 'ejabh-security' ),
					esc_html( number_format_i18n( $file_state['scanned'] ) ),
					esc_html( number_format_i18n( array_sum( $file_counts ) ) )
				);
				?>
			</span>
			<a class="ejabh-card__link" href="<?php echo esc_url( admin_url( 'admin.php?page=ejabh-security-files' ) ); ?>"><?php esc_html_e( 'فحص الملفات ←', 'ejabh-security' ); ?></a>
		</div>

		<div class="ejabh-card">
			<span class="ejabh-card__label"><?php esc_html_e( 'آخر فحص لقاعدة البيانات', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value">
				<?php
				echo $db_state['finished']
					? esc_html( $admin->ago( (int) $db_state['finished'] ) )
					: esc_html__( 'لم يُنفَّذ', 'ejabh-security' );
				?>
			</span>
			<span class="ejabh-card__meta">
				<?php
				printf(
					/* translators: 1: rows scanned, 2: findings. */
					esc_html__( '%1$s صف · %2$s نتيجة', 'ejabh-security' ),
					esc_html( number_format_i18n( $db_state['rows'] ) ),
					esc_html( number_format_i18n( array_sum( $db_counts ) ) )
				);
				?>
			</span>
			<a class="ejabh-card__link" href="<?php echo esc_url( admin_url( 'admin.php?page=ejabh-security-database' ) ); ?>"><?php esc_html_e( 'فحص قاعدة البيانات ←', 'ejabh-security' ); ?></a>
		</div>

		<?php $blocked = Ejabh_Login_Limiter::active_block_count(); ?>
		<div class="ejabh-card<?php echo $blocked ? ' ejabh-card--warn' : ''; ?>">
			<span class="ejabh-card__label"><?php esc_html_e( 'عناوين محظورة الآن', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $blocked ) ); ?></span>
			<span class="ejabh-card__meta">
				<?php
				printf(
					/* translators: %s: number of quarantined files. */
					esc_html__( '%s ملف في الحجر الصحي', 'ejabh-security' ),
					esc_html( number_format_i18n( Ejabh_Quarantine::held_count() ) )
				);
				?>
			</span>
			<a class="ejabh-card__link" href="<?php echo esc_url( admin_url( 'admin.php?page=ejabh-security-quarantine' ) ); ?>"><?php esc_html_e( 'الحجر والحظر ←', 'ejabh-security' ); ?></a>
		</div>

		<?php $harden_fails = count( array_filter( Ejabh_Hardening::checks(), static function ( $c ) { return 'fail' === $c['status']; } ) ); ?>
		<div class="ejabh-card<?php echo $harden_fails ? ' ejabh-card--danger' : ' ejabh-card--ok'; ?>">
			<span class="ejabh-card__label"><?php esc_html_e( 'بنود تحصين ناقصة', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $harden_fails ) ); ?></span>
			<span class="ejabh-card__meta"><?php esc_html_e( 'قابلة للإصلاح بضغطة واحدة', 'ejabh-security' ); ?></span>
			<a class="ejabh-card__link" href="<?php echo esc_url( admin_url( 'admin.php?page=ejabh-security-hardening' ) ); ?>"><?php esc_html_e( 'لوحة التحصين ←', 'ejabh-security' ); ?></a>
		</div>
	</div>

	<div class="ejabh-actions">
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'dys_sec_report' ); ?>
			<input type="hidden" name="action" value="dys_sec_report" />
			<button type="submit" class="button button-secondary">
				<span class="dashicons dashicons-download" style="vertical-align:text-bottom;"></span>
				<?php esc_html_e( 'تنزيل تقرير الحماية الكامل', 'ejabh-security' ); ?>
			</button>
		</form>
	</div>

	<h2><?php esc_html_e( 'حالة طبقات الحماية', 'ejabh-security' ); ?></h2>
	<table class="widefat striped ejabh-table">
		<tbody>
			<tr>
				<td class="ejabh-status"><?php echo $twofa_on && ! $bypassed ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'المصادقة الثنائية بالبريد', 'ejabh-security' ); ?></strong></td>
				<td>
					<?php if ( $twofa_on && ! $bypassed ) : ?>
						<?php esc_html_e( 'إجبارية على كل المستخدمين. يُرسل رمز لمرة واحدة إلى بريد المستخدم بعد كلمة المرور.', 'ejabh-security' ); ?>
						<?php
						$exempt = (array) Ejabh_Settings::get( '2fa_exempt_user_ids' );
						if ( $exempt ) :
							printf(
								' <em>%s</em>',
								esc_html(
									sprintf(
										/* translators: %d: number of exempt users. */
										__( 'يوجد %d حساب مستثنى.', 'ejabh-security' ),
										count( $exempt )
									)
								)
							);
						endif;
						?>
					<?php else : ?>
						<?php esc_html_e( 'معطّلة — الدخول بكلمة المرور فقط.', 'ejabh-security' ); ?>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo $guard_on ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'حظر إضافات مدير الملفات', 'ejabh-security' ); ?></strong></td>
				<td>
					<?php
					printf(
						/* translators: %d: number of blocked slugs. */
						esc_html__( '%d إضافة على قائمة الحظر. تُمنع من التثبيت والتفعيل والتحميل، ويُحذف مجلدها تلقائياً إن ظهر على السيرفر.', 'ejabh-security' ),
						count( Ejabh_Plugin_Guard::blocked_slugs() )
					);
					?>
					<?php if ( ! Ejabh_Settings::get( 'guard_autodelete' ) ) : ?>
						<strong><?php esc_html_e( '(الحذف التلقائي معطّل — يُبلَّغ فقط)', 'ejabh-security' ); ?></strong>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo $caps_on ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'تقييد إدارة الإضافات', 'ejabh-security' ); ?></strong></td>
				<td>
					<?php if ( $caps_on && $owner ) : ?>
						<?php
						printf(
							/* translators: 1: owner name, 2: owner login. */
							esc_html__( 'مقصورة على %1$s (%2$s). بقية المديرين لا يستطيعون تثبيت أو تفعيل أو تعديل الإضافات والقوالب.', 'ejabh-security' ),
							esc_html( $owner->display_name ),
							esc_html( $owner->user_login )
						);
						?>
					<?php else : ?>
						<?php esc_html_e( 'معطّلة — كل المديرين يستطيعون تثبيت الإضافات.', 'ejabh-security' ); ?>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( '2fa_block_xmlrpc' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'حظر XML-RPC', 'ejabh-security' ); ?></strong></td>
				<td><?php esc_html_e( 'يغلق مسار مصادقة يتجاوز شاشة الرمز ويسمح بتجربة كلمات مرور بالجملة.', 'ejabh-security' ); ?></td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( '2fa_block_app_pw' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'حظر كلمات مرور التطبيقات', 'ejabh-security' ); ?></strong></td>
				<td><?php esc_html_e( 'كلمات مرور التطبيقات تصادق عبر REST بدون رمز تحقق، فتُعطَّل.', 'ejabh-security' ); ?></td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( 'admin_guard_enabled' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'قفل إنشاء حسابات المدير', 'ejabh-security' ); ?></strong></td>
				<td><?php esc_html_e( 'لا يستطيع أحد غير المالك إنشاء أو ترقية حساب مدير، وأي حساب مدير يظهر خارج القائمة المعتمدة يُرصَد ويُرسَل عنه تنبيه فوري.', 'ejabh-security' ); ?></td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( 'login_limit_enabled' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'تحديد محاولات الدخول', 'ejabh-security' ); ?></strong></td>
				<td>
					<?php
					printf(
						/* translators: 1: attempts, 2: window, 3: lockout. */
						esc_html__( 'حظر العنوان بعد %1$d محاولات فاشلة خلال %2$d دقيقة، لمدة %3$d دقيقة.', 'ejabh-security' ),
						(int) Ejabh_Settings::get( 'login_max_attempts' ),
						(int) Ejabh_Settings::get( 'login_window_mins' ),
						(int) Ejabh_Settings::get( 'login_lockout_mins' )
					);
					?>
				</td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( 'fim_enabled' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'مراقبة تغيّر الملفات', 'ejabh-security' ); ?></strong></td>
				<td>
					<?php
					if ( Ejabh_FIM::has_baseline() ) {
						printf(
							/* translators: %s: baseline file count. */
							esc_html__( 'خط أساس مسجَّل لـ %s ملف. أي ملف PHP جديد أو مُعدَّل يُبلَّغ عنه في الفحص التالي.', 'ejabh-security' ),
							esc_html( number_format_i18n( Ejabh_FIM::count() ) )
						);
					} else {
						esc_html_e( 'لم يُبنَ خط الأساس بعد — شغّل فحص الملفات مرة واحدة لتأسيسه.', 'ejabh-security' );
					}
					?>
				</td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( 'new_ip_alert_enabled' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'تنبيه الدخول من مكان جديد', 'ejabh-security' ); ?></strong></td>
				<td><?php esc_html_e( 'بريد فوري لصاحب الحساب ولمسؤول الأمن عند دخول من عنوان IP جديد.', 'ejabh-security' ); ?></td>
			</tr>
			<tr>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( 'enum_block_enabled' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'منع تعداد المستخدمين', 'ejabh-security' ); ?></strong></td>
				<td><?php esc_html_e( 'إغلاق ?author=N و REST users وخريطة المؤلفين.', 'ejabh-security' ); ?></td>
			</tr>
			<tr>
				<?php $next = wp_next_scheduled( Ejabh_Scheduler::HOOK ); ?>
				<td class="ejabh-status"><?php echo Ejabh_Settings::get( 'sched_scan_enabled' ) ? '<span class="ejabh-on">✔</span>' : '<span class="ejabh-off">✖</span>'; ?></td>
				<td><strong><?php esc_html_e( 'الفحص التلقائي المجدول', 'ejabh-security' ); ?></strong></td>
				<td>
					<?php
					if ( $next ) {
						printf(
							/* translators: %s: relative time. */
							esc_html__( 'الفحص القادم %s. لا يُرسَل بريد إلا عند ظهور نتائج جديدة.', 'ejabh-security' ),
							esc_html( $admin->ago( $next ) )
						);
					} else {
						esc_html_e( 'غير مجدول.', 'ejabh-security' );
					}
					?>
				</td>
			</tr>
		</tbody>
	</table>

	<?php if ( $top ) : ?>
		<h2><?php esc_html_e( 'أهم النتائج', 'ejabh-security' ); ?></h2>
		<table class="widefat striped ejabh-table">
			<thead>
				<tr>
					<th style="width:80px;"><?php esc_html_e( 'الخطورة', 'ejabh-security' ); ?></th>
					<th><?php esc_html_e( 'النتيجة', 'ejabh-security' ); ?></th>
					<th><?php esc_html_e( 'الموقع', 'ejabh-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $top as $row ) : ?>
					<tr>
						<td><?php echo wp_kses_post( $admin->severity_badge( $row->severity ) ); ?></td>
						<td><?php echo esc_html( $row->title ); ?></td>
						<td><code class="ejabh-target"><?php echo esc_html( $row->target ); ?><?php echo $row->line_no ? ':' . (int) $row->line_no : ''; ?></code></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<?php if ( $log ) : ?>
		<h2><?php esc_html_e( 'آخر الأحداث', 'ejabh-security' ); ?></h2>
		<table class="widefat striped ejabh-table">
			<tbody>
				<?php foreach ( $log as $row ) : ?>
					<tr>
						<td style="width:90px;"><?php echo wp_kses_post( $admin->severity_badge( $row->severity ) ); ?></td>
						<td style="width:130px;"><?php echo esc_html( $admin->ago( $row->created_at ) ); ?></td>
						<td><?php echo esc_html( $row->message ); ?></td>
						<td style="width:120px;"><code><?php echo esc_html( $row->ip ); ?></code></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=ejabh-security-log' ) ); ?>"><?php esc_html_e( 'عرض السجل الكامل ←', 'ejabh-security' ); ?></a></p>
	<?php endif; ?>
</div>
