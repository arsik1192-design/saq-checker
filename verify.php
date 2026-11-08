<?php
// ===========================================================================
//  Проверка кода до начала сканирования.
//  Клиент дёргает этот адрес перед запуском, чтобы игрок не ждал три
//  минуты и только потом узнавал, что код не тот.
//  Код НЕ гасится - он сгорает только при приёме отчёта в receive.php.
// ===========================================================================

require __DIR__ . '/config.php';
require __DIR__ . '/lib.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function out($ok, $error = '', $extra = []) {
    echo json_encode(array_merge(['ok' => $ok, 'error' => $error], $extra),
                     JSON_UNESCAPED_UNICODE);
    exit;
}

// Небольшая задержка: перебирать коды через этот адрес невыгодно.
usleep(300000);

$token = '';
if (isset($_REQUEST['token'])) { $token = trim((string)$_REQUEST['token']); }
if ($token === '' || strlen($token) > 64) {
    out(false, 'Код не указан');
}

ensure_dirs();
$tokens = tokens_load();

if (!isset($tokens[$token])) {
    out(false, 'Такой код не выдавался. Проверьте, правильно ли вы его ввели.');
}

$t = $tokens[$token];

if (!empty($t['used_at'])) {
    out(false, 'Этот код уже использован. Попросите у администратора новый.');
}
if (time() > (int)$t['expires_at']) {
    out(false, 'Срок действия кода истёк. Попросите у администратора новый.');
}

out(true, '', [
    'minutes_left' => max(0, intdiv((int)$t['expires_at'] - time(), 60)),
]);
