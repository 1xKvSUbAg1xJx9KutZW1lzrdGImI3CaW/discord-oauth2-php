<?php
include_once 'discord.php';
include_once 'config.php';

$discord = new DiscordOauth2($client_id, $client_secret, $redirect_uri);
$discord->oauth_session_start();
$discord->oauth_session_destroy();

header('Location: ' . $_SERVER['HTTP_REFERER']);
