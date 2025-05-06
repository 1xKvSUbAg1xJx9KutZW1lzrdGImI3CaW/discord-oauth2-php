<?php
include_once 'discord.php';
include_once 'config.php';

$discord = new DiscordOauth2($client_id, $client_secret, $redirect_uri);

$discord->oauth_session_start();

$profile;

if ($discord->oauth_session_valid())
    $profile = $discord->get_profile();
?>

<html>

<head>
    <title>discord-aouth2-php demo</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
</head>

<body style="height: 100vh;width: 100vw;margin: 0">
    <main style="display: flex;flex-direction: column;width: 100%;height: 100%;justify-content: center;align-items: center">
        <?php
        if (!$discord->oauth_session_valid()) {
        ?>
            <a href="<?php echo $discord->get_oauth_url() ?>" role="button">Authenticate with Discord</a>
        <?php
        } else {
        ?>
            <div style="display: flex;gap:1rem">
                <img draggable="false" style="border-radius: 50%;user-select: none;" src="<?php echo $profile->get_avatar_url() ?>" height="128px">
                <div>
                    <p>Hello, <?= htmlspecialchars($profile->global_name ?? $profile->username, ENT_QUOTES) ?></p>
                    <a href="logout.php" type="button">logout</a>
                </div>
            </div>
        <?php
        }
        ?>
    </main>
</body>

</html>