<?php
/**
 * Shared scan screen for the file and database scanners.
 *
 * @package Ejabh_Security
 *
 * @var Ejabh_Admin $admin
 * @var string    $kind
 * @var string    $title
 * @var string    $intro
 * @var array     $state
 * @var array     $findings
 * @var array     $counts
 * @var string    $back
 */

defined( 'ABSPATH' ) || exit;

$running = 'scanning' === $state['status'];
$total   = array_sum( $counts );

$filter = isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
if ( $filter && isset( $counts[ $filter ] ) ) {
	$findings = array_values(
		array_filter(
			$findings,
			static function ( $row ) use ( $filter ) {
				return $row->severity === $filter;
			}
		)
	);
}
?>
<div class="wrap ejabh-wrap">
	<h1><span class="dashicons dashicons-search"></span> <?php echo esc_html( $title ); ?></h1>
	<p class="description"><?php echo esc_html( $intro ); ?></p>

	<div class="ejabh-scanbox" data-kind="<?php echo esc_attr( $kind ); ?>">
		<p class="ejabh-scan-actions">
			<button type="button" class="button button-primary ejabh-scan-start" <?php disabled( $running ); ?>>
				<?php esc_html_e( 'ابدأ فحصاً جديداً', 'ejabh-security' ); ?>
			</button>
			<button type="button" class="button ejabh-scan-cancel" <?php disabled( ! $running ); ?>>
				<?php esc_html_e( 'إلغاء', 'ejabh-security' ); ?>
			</button>
			<span class="spinner ejabh-spinner"></span>
		</p>

		<div class="ejabh-progress">
			<?php if ( $running ) : ?>
				<strong><?php esc_html_e( 'فحص قيد التنفيذ — اضغط "ابدأ فحصاً جديداً" لمتابعته أو "إلغاء" لإيقافه.', 'ejabh-security' ); ?></strong>
			<?php elseif ( $state['finished'] ) : ?>
				<?php
				printf(
					/* translators: %s: relative time. */
					esc_html__( 'آخر فحص: %s', 'ejabh-security' ),
					esc_html( $admin->ago( (int) $state['finished'] ) )
				);
				?>
			<?php else : ?>
				<?php esc_html_e( 'لم يُنفَّذ فحص بعد.', 'ejabh-security' ); ?>
			<?php endif; ?>
		</div>

		<?php if ( 'file' === $kind && Ejabh_Settings::get( 'fim_enabled' ) ) : ?>
			<div class="ejabh-core-box">
				<strong><?php esc_html_e( 'مراقبة تغيّر الملفات:', 'ejabh-security' ); ?></strong>
				<?php if ( ! Ejabh_FIM::has_baseline() ) : ?>
					<?php esc_html_e( 'لم يُبنَ خط الأساس بعد — الفحص الأول سيسجّل بصمة كل ملف بصمت، والفحوصات التالية ستُبلّغ عن أي جديد أو مُعدَّل.', 'ejabh-security' ); ?>
				<?php else : ?>
					<?php
					printf(
						/* translators: 1: baseline size, 2: new, 3: modified, 4: deleted. */
						esc_html__( 'خط أساس %1$s ملف — في آخر فحص: %2$s جديد · %3$s مُعدَّل · %4$s محذوف', 'ejabh-security' ),
						esc_html( number_format_i18n( Ejabh_FIM::count() ) ),
						esc_html( number_format_i18n( (int) $state['fim_new'] ) ),
						esc_html( number_format_i18n( (int) $state['fim_changed'] ) ),
						esc_html( number_format_i18n( (int) $state['fim_gone'] ) )
					);
					?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ejabh-inline-form" style="margin-inline-start:10px;"
						onsubmit="return confirm('<?php echo esc_js( __( 'سيُمسح خط الأساس، وسيُعامَل الفحص التالي كأنه الأول (بلا تنبيهات تغيير). استخدمه بعد تنظيف الموقع أو تحديث كبير. متابعة؟', 'ejabh-security' ) ); ?>');">
						<?php wp_nonce_field( 'dys_sec_reset_fim' ); ?>
						<input type="hidden" name="action" value="dys_sec_reset_fim" />
						<button type="submit" class="button button-small"><?php esc_html_e( 'إعادة ضبط خط الأساس', 'ejabh-security' ); ?></button>
					</form>
				<?php endif; ?>
			</div>
		<?php endif; ?>

		<?php if ( 'file' === $kind && ! empty( $state['core_stats'] ) ) : ?>
			<?php $core = $state['core_stats']; ?>
			<div class="ejabh-core-box">
				<strong><?php esc_html_e( 'التحقق من سلامة نواة ووردبريس:', 'ejabh-security' ); ?></strong>
				<?php if ( ! empty( $core['error'] ) ) : ?>
					<span class="ejabh-off"><?php echo esc_html( $core['error'] ); ?></span>
				<?php else : ?>
					<?php
					printf(
						/* translators: 1: files checked, 2: modified, 3: missing, 4: unknown extras. */
						esc_html__( 'تم مقارنة %1$s ملف — مُعدَّل: %2$s · مفقود: %3$s · ملفات غريبة داخل النواة: %4$s', 'ejabh-security' ),
						esc_html( number_format_i18n( (int) $core['checked'] ) ),
						esc_html( number_format_i18n( (int) $core['modified'] ) ),
						esc_html( number_format_i18n( (int) $core['missing'] ) ),
						esc_html( number_format_i18n( (int) $core['unknown'] ) )
					);
					?>
				<?php endif; ?>
			</div>
		<?php endif; ?>
	</div>

	<h2>
		<?php
		printf(
			/* translators: %s: number of findings. */
			esc_html__( 'النتائج (%s)', 'ejabh-security' ),
			esc_html( number_format_i18n( $total ) )
		);
		?>
	</h2>

	<?php
	$actions      = Ejabh_Signatures::actions();
	$action_count = Ejabh_Findings::action_counts( $kind );
	if ( array_sum( $action_count ) ) :
		?>
		<div class="ejabh-actionbar">
			<strong><?php esc_html_e( 'ما المطلوب منك:', 'ejabh-security' ); ?></strong>
			<?php foreach ( $actions as $slug => $meta ) : ?>
				<?php if ( empty( $action_count[ $slug ] ) ) { continue; } ?>
				<span class="ejabh-badge ejabh-badge--<?php echo esc_attr( $meta['class'] ); ?>">
					<?php echo esc_html( $meta['label'] ); ?>: <?php echo esc_html( number_format_i18n( $action_count[ $slug ] ) ); ?>
				</span>
			<?php endforeach; ?>
		</div>
	<?php endif; ?>

	<?php if ( $total ) : ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:10px 0;"
			onsubmit="return confirm('<?php echo esc_js( __( 'سيُمسح سجل النتائج بالكامل. استخدمه بعد أن تنتهي من المعالجة، ثم شغّل فحصاً جديداً. متابعة؟', 'ejabh-security' ) ); ?>');">
			<?php wp_nonce_field( 'dys_sec_clear_findings' ); ?>
			<input type="hidden" name="action" value="dys_sec_clear_findings" />
			<input type="hidden" name="kind" value="<?php echo esc_attr( $kind ); ?>" />
			<input type="hidden" name="back" value="<?php echo esc_attr( $back ); ?>" />
			<button type="submit" class="button">
				<span class="dashicons dashicons-trash" style="vertical-align:text-bottom;"></span>
				<?php esc_html_e( 'مسح سجل النتائج', 'ejabh-security' ); ?>
			</button>
			<span class="description"><?php esc_html_e( 'بعد ما تنتهي من التنظيف — امسح النتائج ثم شغّل فحصاً جديداً لترى ما تبقّى فعلاً.', 'ejabh-security' ); ?></span>
		</form>
	<?php endif; ?>

	<ul class="subsubsub">
		<?php
		$base   = admin_url( 'admin.php?page=' . $back );
		$levels = array(
			''         => __( 'الكل', 'ejabh-security' ),
			'critical' => __( 'حرج', 'ejabh-security' ),
			'high'     => __( 'عالي', 'ejabh-security' ),
			'medium'   => __( 'متوسط', 'ejabh-security' ),
			'low'      => __( 'منخفض', 'ejabh-security' ),
		);
		$parts  = array();
		foreach ( $levels as $slug => $label ) {
			$count = '' === $slug ? $total : (int) $counts[ $slug ];
			$url   = '' === $slug ? $base : add_query_arg( 'severity', $slug, $base );
			$parts[] = sprintf(
				'<li><a href="%s"%s>%s <span class="count">(%s)</span></a></li>',
				esc_url( $url ),
				$filter === $slug ? ' class="current"' : '',
				esc_html( $label ),
				esc_html( number_format_i18n( $count ) )
			);
		}
		echo implode( ' | ', $parts ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
	</ul>
	<div style="clear:both;"></div>

	<?php if ( ! $findings ) : ?>
		<p><?php esc_html_e( 'لا توجد نتائج لهذا التصنيف.', 'ejabh-security' ); ?></p>
	<?php else : ?>
		<table class="widefat striped ejabh-table ejabh-findings">
			<thead>
				<tr>
					<th style="width:74px;"><?php esc_html_e( 'الخطورة', 'ejabh-security' ); ?></th>
					<th><?php esc_html_e( 'النتيجة والموقع', 'ejabh-security' ); ?></th>
					<th style="width:120px;"><?php esc_html_e( 'الحالة', 'ejabh-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $findings as $row ) : ?>
					<tr class="ejabh-finding ejabh-finding--<?php echo esc_attr( $row->status ); ?>">
						<td><?php echo wp_kses_post( $admin->severity_badge( $row->severity ) ); ?></td>
						<td>
							<strong><?php echo esc_html( $row->title ); ?></strong>
							<div class="ejabh-finding__target">
								<code class="ejabh-target"><?php echo esc_html( $row->target ); ?><?php echo $row->line_no ? ':' . (int) $row->line_no : ''; ?></code>
								<span class="ejabh-muted">· <?php echo esc_html( $row->rule ); ?></span>
							</div>

							<?php
							$act  = isset( $row->action ) ? (string) $row->action : 'review';
							$meta = isset( $actions[ $act ] ) ? $actions[ $act ] : $actions['review'];
							?>
							<div class="ejabh-fix ejabh-fix--<?php echo esc_attr( $meta['class'] ); ?>">
								<span class="ejabh-fix__label"><?php echo esc_html( $meta['label'] ); ?></span>
								<span class="ejabh-fix__text"><?php echo esc_html( isset( $row->remediation ) ? $row->remediation : '' ); ?></span>
							</div>

							<?php if ( $row->snippet ) : ?>
								<pre class="ejabh-snippet" dir="ltr"><?php echo esc_html( $row->snippet ); ?></pre>
							<?php endif; ?>

							<?php
							// Offer one-click quarantine for file findings that
							// point at a real path we are told to remove.
							$is_file_target = ( 'file' === $row->scan_type || 'integrity' === $row->scan_type )
								&& in_array( $act, array( 'delete', 'review' ), true )
								&& $row->target
								&& false === strpos( $row->target, ' ' )
								&& file_exists( ABSPATH . $row->target );
							?>
							<?php if ( $is_file_target && Ejabh_Settings::get( 'quarantine_enabled' ) ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ejabh-inline-form" style="margin-top:6px;"
									onsubmit="return confirm('<?php echo esc_js( __( 'سيُنقل الملف إلى الحجر الصحي (لا يُحذف). يمكنك استعادته إن تبيّن أنه سليم. متابعة؟', 'ejabh-security' ) ); ?>');">
									<?php wp_nonce_field( 'dys_sec_quarantine' ); ?>
									<input type="hidden" name="action" value="dys_sec_quarantine" />
									<input type="hidden" name="what" value="capture" />
									<input type="hidden" name="target" value="<?php echo esc_attr( $row->target ); ?>" />
									<input type="hidden" name="back" value="<?php echo esc_attr( $back ); ?>" />
									<button type="submit" class="button button-small"><?php esc_html_e( 'انقله للحجر الصحي', 'ejabh-security' ); ?></button>
								</form>
							<?php endif; ?>
						</td>
						<td>
							<?php if ( 'open' === $row->status ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<?php wp_nonce_field( 'dys_sec_finding' ); ?>
									<input type="hidden" name="action" value="dys_sec_finding_status" />
									<input type="hidden" name="finding_id" value="<?php echo esc_attr( $row->id ); ?>" />
									<input type="hidden" name="back" value="<?php echo esc_attr( $back ); ?>" />
									<input type="hidden" name="status" value="ignored" />
									<button type="submit" class="button button-small"><?php esc_html_e( 'تجاهُل', 'ejabh-security' ); ?></button>
								</form>
							<?php else : ?>
								<span class="ejabh-muted"><?php echo esc_html( 'ignored' === $row->status ? __( 'متجاهَلة', 'ejabh-security' ) : __( 'مُعالَجة', 'ejabh-security' ) ); ?></span>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<?php wp_nonce_field( 'dys_sec_finding' ); ?>
									<input type="hidden" name="action" value="dys_sec_finding_status" />
									<input type="hidden" name="finding_id" value="<?php echo esc_attr( $row->id ); ?>" />
									<input type="hidden" name="back" value="<?php echo esc_attr( $back ); ?>" />
									<input type="hidden" name="status" value="open" />
									<button type="submit" class="button-link"><?php esc_html_e( 'إعادة فتح', 'ejabh-security' ); ?></button>
								</form>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>

		<p class="description" style="margin-top:12px;">
			<?php esc_html_e( 'ملاحظة: النتائج بدرجة "منخفض" و"متوسط" غالباً كود مشروع في مكتبات خارجية (vendor). ابدأ دائماً من الحرج ثم العالي.', 'ejabh-security' ); ?>
		</p>
	<?php endif; ?>
</div>
