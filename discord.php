<?php
class DiscordOauth2 {
    public string $client_id;
    public string $client_secret;
    public string $redirect_uri;
    private ?string $discord_token;

    function __construct(string $client_id, string $client_secret, string $redirect_uri, ?string $discord_token = null)
    {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->redirect_uri = $redirect_uri;
        $this->discord_token = $discord_token;
    }

    public function get_oauth_url($scope = ['identify']) : string {
        if(!in_array('identify', $scope))
            array_push($scope, 'identify');

        $state = bin2hex(random_bytes(32));
        $_SESSION['discord_state'] = $state;

        return 'https://discord.com/oauth2/authorize?client_id=' 
        . $this->client_id . '&response_type=code&redirect_uri=' . $this->redirect_uri
        . '&scope=' . implode('+', $scope) . '&state=' . $state;
    }

    public function get_profile() : DiscordProfile {
        if(!$this->oauth_session_valid())
            throw new Exception('Invalid oauth2 session');
        if(!$this->has_scope('identify'))
            throw new Exception('Missing identify scope');

        $curl = curl_init('https://discord.com/api/users/@me');
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Authorization: ' . $_SESSION['discord_access_token']
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($curl);

        return new DiscordProfile(json_decode($response, true));
    }

    /**
    * @return DiscordGuild[]
    */
    public function get_guilds() : array {
        if(!$this->oauth_session_valid())
            throw new Exception('Invalid oauth2 session');
        if(!$this->has_scope('guilds'))
            throw new Exception('Missing guilds scope');

        $curl = curl_init('https://discord.com/api/users/@me/guilds');
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Authorization: ' . $_SESSION['discord_access_token']
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($curl);

        $guilds = [];
        
        foreach(json_decode($response, true) as $guild)
            array_push($guilds, new DiscordGuild($guild));
        
        return $guilds;
    }

    /**
    * @return DiscordConnection[]
    */
    public function get_connections() : array {
        if(!$this->oauth_session_valid())
            throw new Exception('Invalid oauth2 session');
        if(!$this->has_scope('connections'))
            throw new Exception('Missing connections scope');
        
        $curl = curl_init('https://discord.com/api/users/@me/connections');
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Authorization: ' . $_SESSION['discord_access_token']
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($curl);

        $connections = [];
        
        foreach(json_decode($response, true) as $connection)
            array_push($connections, new DiscordConnection($connection));
        
        return $connections;
    }

    public function add_guild_member(string $guild_id) : AddGuildMemberResult {
        if(!$this->oauth_session_valid())
            throw new Exception('Invalid oauth2 session');
        if(is_null($this->discord_token))
            throw new Exception('This method requires a token to be set');
        if(!$this->has_scope('guilds.join'))
            throw new Exception('Missing guilds.join scope');
        
        $profile = $this->get_profile();

        $curl = curl_init('https://discord.com/api/guilds/' . $guild_id . '/members/' . $profile->id);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Authorization: Bot ' . $this->discord_token,
            'Content-Type: application/json'
        ));
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode(array(
            'access_token' => substr($_SESSION['discord_access_token'], strlen('Bearer '))
        )));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($curl);
        $status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        
        switch($status_code) {
            case 201:
                return AddGuildMemberResult::MemberAdded;
            case 204:
                return AddGuildMemberResult::AlreadyMember;
            default:
                return AddGuildMemberResult::Failed;
        }
    }

    private function has_scope(string $scope) : bool {
        if(!$this->oauth_session_valid())
            return false;
        return in_array($scope, $_SESSION['discord_scope']);
    }

    public function oauth_session_valid() : bool {
        if(!isset($_SESSION['discord_refresh_token']) || !isset($_SESSION['discord_access_token']) || !isset($_SESSION['discord_expire_at']) || !isset($_SESSION['discord_scope']))
            return false;

        if(time() > $_SESSION['discord_expire_at'])
            return false;

        return true;
    }

    public function oauth_session_start() {
        session_start();

        if(!isset($_GET['code']) || !isset($_GET['state']))
            return;

        $code = $_GET['code'];
        $state = $_GET['state'];

        try {
            
            if($_SESSION['discord_state'] != $_GET['state'])
                return;

            $curl = curl_init('https://discord.com/api/oauth2/token');
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query(array(
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
                'code' => $code,
                'redirect_uri' => $this->redirect_uri,
                'grant_type' => 'authorization_code'
            )));

            $response = curl_exec($curl);
            curl_close($curl);

            $json_body = json_decode($response, true);

            $_SESSION['discord_refresh_token'] = $json_body['refresh_token'];
            $_SESSION['discord_access_token'] = $json_body['token_type'] . ' ' . $json_body['access_token'];
            $_SESSION['discord_expire_at'] = time() + $json_body['expires_in'];
            $_SESSION['discord_scope'] = explode(' ', $json_body['scope']);
            
        } finally {
            $parsed_url = parse_url($_SERVER['REQUEST_URI'], PHP_URL_QUERY);
            parse_str($parsed_url, $query_params);
            unset($query_params['code']);
            unset($query_params['state']);
            header('Location: ' . str_replace($parsed_url, http_build_query($query_params), $_SERVER['REQUEST_URI']));
            die();
        }
    }

    public function oauth_session_destroy() {
        session_destroy();
    }
}

class DiscordProfile {
    public string $id;
    public string $username;
    public ?string $avatar;
    public string $discriminator;
    public int $public_flags;
    public int $flags;
    public ?string $banner;
    public ?int $accent_color;
    public ?string $global_name;
    public ?string $avatar_decoration_data;
    public ?string $collectibles;
    public ?string $banner_color;
    public ?string $clan;
    public bool $mfa_enabled;
    public string $locale;
    public ?int $premium_type;
    public ?string $email;
    public bool $verified;

    function __construct($json_response) {
        foreach($json_response as $key => $value)
            $this->$key = $value;
    }

    function get_avatar_url(bool $allow_animated = false) : string {
        if(is_null($this->avatar))
            return 'https://cdn.discordapp.com/embed/avatars/' . strval((intval($this->id) >> 22) % 6) . '.png';
        return 'https://cdn.discordapp.com/avatars/' . $this->id . '/' . $this->avatar . (($allow_animated && str_starts_with($this->avatar, 'a_')) ? '.gif' : '.png');
    }
}

class DiscordGuild {
    public string $id;
    public string $name;
    public ?string $icon;
    public ?string $banner;
    public bool $owner;
    public int $permissions;
    public string $permissions_new;

    public array $features;

    function __construct($json_response) {
        foreach($json_response as $key => $value)
            $this->$key = $value;
    }
}

class DiscordConnection {
    public string $id;
    public string $name;
    public string $type;
    public ?bool $revoked;
    public ?array $integrations;
    public bool $verified;
    public bool $friend_sync;
    public bool $show_activity;
    public bool $two_way_link;
    public int $visibility;

    function __construct($json_response) {
        foreach($json_response as $key => $value)
            $this->$key = $value;
    }
}

enum AddGuildMemberResult {
    case Failed;
    case MemberAdded;
    case AlreadyMember;

    public static function toString(AddGuildMemberResult $result) : string {
        switch($result) {
            case AddGuildMemberResult::Failed:
                return 'Failed';
            case AddGuildMemberResult::MemberAdded:
                return 'MemberAdded';
            case AddGuildMemberResult::AlreadyMember:
                return 'AlreadyMember';
            default:
                return 'Unknown';
        }
    }
}
?>