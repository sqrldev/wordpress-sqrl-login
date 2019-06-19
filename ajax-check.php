<?php
include '../../../wp-load.php';

$siteURL = "https://uhash.com";
header("Access-Control-Allow-Origin: {$siteURL}");
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Max-Age: 1');    // cache for 1 day
header("Access-Control-Allow-Methods: GET, OPTIONS");

$wp_users = get_users(array(
	'meta_key'     => 'sqrl_session',
	'meta_value'   => $_GET['session'],
	'number'       => 1,
	'count_total'  => false,
	'fields'       => 'id',
));

if($wp_users[0]) {
	echo "true";
} else {
	echo "false";
}