<?php
/**
 * DynDns (http://github.com/JPG-Consulting/DynDns/)
 *
 * @link      https://github.com/JPG-Consulting/DynDns/
 * @copyright Copyright (c) 2015 Juan Pedro Gonzalez (http://www.jpg-consulting.com.com)
 * @license   http://www.gnu.org/licenses/gpl.html GNU General Public License v2.0
 */

/**
 * Configuration values
 */
$config = require dirname(dirname(__DIR__)) . '/config/dyndns.config.php';

/**
 * Program start
 */
if (!isset($config)) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "System not configured!";
    exit;
} elseif (!is_array($config)) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "Invalid configuration.";
    exit;
} elseif (!isset($config['pdo']['dsn'])) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "Database not configured.";
    exit;
}

/**
 * Configuration
 */
if (!array_key_exists('username', $config['pdo'])) $config['pdo']['username'] = null;
if (!array_key_exists('password', $config['pdo'])) $config['pdo']['password'] = null;
if (!array_key_exists('options', $config['pdo'])) $config['pdo']['options'] = array();
if (!is_array($config['pdo']['options'])) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "Invalid database options configuration.";
    exit;
}

if (!isset($config['authentication']['realm'])) $config['authentication']['realm'] = $_SERVER['SERVER_NAME'];

// TTL default to 300 (5 minutes)
if (!isset($config['ttl'])) $config['ttl'] = 300;

/**
 * Connect to database.
 */
try {
    $dbh = new PDO($config['pdo']['dsn'], $config['pdo']['username'], $config['pdo']['password'], $config['pdo']['options']);
} catch (PDOException $e) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    //echo 'Exception : '.$e->getMessage();
    exit;
} catch (Exception $e) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    //echo 'Exception : '.$e->getMessage();
    exit;
}

/**
 * Authentication
 */
if (!isset($_SERVER['PHP_AUTH_USER'])) {
    header('WWW-Authenticate: Basic realm="' . $config['authentication']['realm'] . '"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'This service requires basic http authentication';
    exit();
}

/**
 * Validate user.
 */
$sth = $dbh->prepare("SELECT * FROM users WHERE username = :username");
if (!$sth instanceof PDOStatement) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    exit;
}

$result = $sth->execute(array(
    ':username' => $_SERVER['PHP_AUTH_USER']
));

if (!$result) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    exit;
}

$user = $sth->fetch(PDO::FETCH_ASSOC);
if (!is_array($user) || empty($user)) {
    header('WWW-Authenticate: Basic realm="' . $config['authentication']['realm'] . '"');
    header('HTTP/1.0 401 Unauthorized');
    echo "badauth\n";
    exit();
}

$status = 0;
$hash=$user['password'];
$ret = crypt($_SERVER['PHP_AUTH_PW'], $hash);
if (function_exists('mb_strlen')) {
    if (!is_string($ret) || mb_strlen($ret, '8bit') != mb_strlen($hash, '8bit') || mb_strlen($ret, '8bit') <= 13) {
        header('WWW-Authenticate: Basic realm="' . $config['authentication']['realm'] . '"');
        header('HTTP/1.0 401 Unauthorized');
        echo "badauth\n";
        exit();
    }

    for ($i = 0; $i < mb_strlen($ret, '8bit'); $i++) {
        $status |= (ord($ret[$i]) ^ ord($hash[$i]));
    }    
} else {
    if (!is_string($ret) || strlen($ret) != strlen($hash) || strlen($ret) <= 13) {
        header('WWW-Authenticate: Basic realm="' . $config['authentication']['realm'] . '"');
        header('HTTP/1.0 401 Unauthorized');
        echo "badauth\n";
        exit();
    }

    for ($i = 0; $i < strlen($ret); $i++) {
        $status |= (ord($ret[$i]) ^ ord($hash[$i]));
    }
}

if ($status !== 0) {
    header('WWW-Authenticate: Basic realm="' . $config['authentication']['realm'] . '"');
    header('HTTP/1.0 401 Unauthorized');
    echo "badauth\n";
    exit();
}

/**
 * Hostname
 * Required parameter.
 */
if (isset($_GET['hostname'])) {
    $hostname = $_GET['hostname'];
    // Hostname must be composed of HOST.ZONE
    if (strpos($hostname, '.') === false) {
        header("HTTP/1.1 400 Bad Request");
        echo "nohost\n";
        exit;
    }
    
    // Validate hostname
    if (!(preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $hostname) //valid chars check
    && preg_match("/^.{1,253}$/", $hostname) //overall length check
    && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $hostname) )) {
        header("HTTP/1.1 400 Bad Request");
        echo "nohost\n";
        exit;
    }
} else {
    header("HTTP/1.1 400 Bad Request");
    echo "nohost\n";
    exit;
}

list($host, $zone) = explode('.', $hostname, 2);
$sth = $dbh->prepare("SELECT * FROM zones WHERE name = :zone");
if (!$sth instanceof PDOStatement) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    exit;
}

$result = $sth->execute(array(
    ':zone' => $zone
));

if (!$result) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    exit;
}

$zone = $sth->fetch(PDO::FETCH_ASSOC);
if (!is_array($zone) || empty($zone)) {
    header("HTTP/1.1 400 Bad Request");
    echo "nohost\n";
    exit;
}

// Get host
$sth = $dbh->prepare("SELECT * FROM hosts WHERE zone = :zone AND name = :host AND user = :user");
if (!$sth instanceof PDOStatement) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    exit;
}

$result = $sth->execute(array(
    ':zone' => $zone['id'],
    ':host' => $host,
    ':user' => $user['id']
));

if (!$result) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    exit;
}

$host = $sth->fetch(PDO::FETCH_ASSOC);
if (!is_array($host) || empty($host)) {
    header("HTTP/1.1 400 Bad Request");
    echo "nohost\n";
    exit;
}

// Old Address type
if (filter_var($host['address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $old_type='AAAA';
} elseif (filter_var($host['address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    $old_type='A';
} else {
    header("HTTP/1.1 500 Internal Server Error");
    echo "911\n";
    exit;
}

/**
 * IP Address
 * Optional parameter.
 */
if (isset($_GET['myip'])) {
    $myip = $_GET['myip'];
} else {
    $myip = $_SERVER['REMOTE_ADDR'];

    if (isset($_SERVER['HTTP_FORWARDED'])) {
    	if (filter_var($_SERVER['HTTP_FORWARDED'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            $myip = $_SERVER['HTTP_FORWARDED'];
    	}
    }

    if (isset($_SERVER['HTTP_FORWARDED_FOR'])) {
        if (filter_var($_SERVER['HTTP_FORWARDED_FOR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            $myip = $_SERVER['HTTP_FORWARDED_FOR'];
        }
    }

    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        if (filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            $myip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
    }

    if (isset($_SERVER['HTTP_CLIENT_IP'])) {
        if (filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            $myip = $_SERVER['HTTP_CLIENT_IP'];
        }
    }
}

// Validate IP
if (filter_var($myip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    echo "nochg " . $host['address'] . "\n";
    exit();
}

if (filter_var($myip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $type='AAAA';
} elseif (filter_var($myip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    $type='A';
} else {
    echo "nochg " . $host['address'] . "\n";
    exit();
}

/**
 * Send nsupdate.
 */
$nsupdate_cmds = array();
$nsupdate_cmds[] = "server " . $zone['ns'];
$nsupdate_cmds[] = "zone " . $zone['name'];
$nsupdate_cmds[] = "update delete " . $hostname . " " . $old_type;
$nsupdate_cmds[] = "update add " . $hostname . " " . $config['ttl'] . " " . $type . " " . $myip;
$nsupdate_cmds[] = "send";

exec("echo \"" . implode("\n", $nsupdate_cmds) . "\" | nsupdate", $output, $returnCode);

// Check whether nsupdate responded with an error
if ($returnCode) {
    echo "nochg " . $host['address'] . "\n";
} else {
    echo "good " . $myip . "\n";

    // Update database
    $sth = $dbh->prepare("UPDATE hosts SET address = :address WHERE zone = :zone AND name = :host");
    if ($sth instanceof PDOStatement) {
        $sth->execute(array(
            ':address' => $myip,
            ':zone'    => $zone['id'],
            ':host'    => $host['name']
        ));
    }
}