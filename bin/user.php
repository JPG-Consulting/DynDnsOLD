<?php
/**
 * DynDns (http://github.com/JPG-Consulting/DynDns/)
 * Open protocol for Dynamic DNS updates.
 *
 * @link      https://github.com/JPG-Consulting/DynDns/
 * @copyright Copyright (c) 2015 Juan Pedro Gonzalez (http://www.jpg-consulting.com.com)
 * @license   http://www.gnu.org/licenses/gpl.html GNU General Public License v2.0
 */

/**
 * This makes our life easier when dealing with paths. Everything is relative
 * to the application root now.
 */
chdir(dirname(__DIR__));

/**
 * Ensure this script is running from CLI.
 */
if (php_sapi_name() !== "cli") {
    echo "Error: This script must be runned from CLI.";
    exit(1);
}

/**
 * Password hash library
 */
require_once 'includes/password_hash.php';

/**
 * Configuration
 */
$config = require('config/dyndns.config.php');

if (!isset($config)) {
	echo "Error: System is not configured!";
    exit(1);
} elseif (!is_array($config)) {
    echo "Error: Invalid configuration.";
    exit(1);
} elseif (!isset($config['pdo']['dsn'])) {
    echo "Error: Database not configured.";
    exit(1);
}

if (!array_key_exists('username', $config['pdo'])) $config['pdo']['username'] = null;
if (!array_key_exists('password', $config['pdo'])) $config['pdo']['password'] = null;
if (!array_key_exists('options', $config['pdo'])) $config['pdo']['options'] = array();
if (!is_array($config['pdo']['options'])) {
    echo "Error: Invalid database options configured.";
    exit(1);
}

/**
 * Arguments:
 *    --username=[USERNAME]
 *    --password=[PASSWORD]
 */
foreach ($argv as $arg) {
    if (preg_match('/--([^=]+)=(.*)/',$arg,$reg)) {
        $_GET[$reg[1]] = $reg[2];
    } elseif(preg_match('/-([a-zA-Z0-9])/',$arg,$reg)) {
        $_GET[$reg[1]] = 'true';
    }
}

if (isset($_GET['algorithm'])) {
    if (is_numeric($_GET['algorithm'])) {
        $_GET['algorithm'] = (int)$_GET['algorithm'];
    } elseif (is_string($_GET['algorithm'])) {
        $_GET['algorithm'] = strtoupper($_GET['algorithm']);
        switch($_GET['algorithm']) {
            case 'BCRYPT':
       	        $_GET['algorithm'] = PASSWORD_BCRYPT;
       	        break;
       	    default:
       	        if (!empty($_GET['algorithm'])) {
       	            fwrite(STDOUT, PHP_EOL . 'Unknown password hashing algorithm. Defaulting to BCRYPT.' . PHP_EOL . PHP_EOL);
       	        }
       	        $_GET['algorithm'] = PASSWORD_BCRYPT;
        }
    } else {
        $_GET['algorithm'] = PASSWORD_BCRYPT;
    }
} else {
	$_GET['algorithm'] = PASSWORD_BCRYPT;
}

if (!isset($_GET['username'])) {
    while (true) {
        fwrite(STDOUT, 'Username: ');
        $_GET['username'] = trim(fgets(STDIN));

        if (empty($_GET['username'])) {
            fwrite(STDOUT, PHP_EOL . 'Username can not be empty.' . PHP_EOL . PHP_EOL);
        } else {
            break;
        }
    }
}

if (!isset($_GET['password'])) {
    while (true) {
        fwrite(STDOUT, 'Password: ');
        $_GET['password'] = trim(fgets(STDIN));

        if (!empty($_GET['password'])) {
            fwrite(STDOUT, 'Re-type password: ');
            $password_verify = trim(fgets(STDIN));

            if (strcmp($_GET['password'], $password_verify) !== 0) {
                fwrite(STDOUT, PHP_EOL . 'Passwords do not match. Please try again.' . PHP_EOL . PHP_EOL);
            } else {
                break;
            }
        } else {
            fwrite(STDOUT, PHP_EOL . 'Password can not be empty.' . PHP_EOL . PHP_EOL);
        }
    }
}

/**
 * Crypto
 */
$password_hash = password_hash($_GET['password'], $_GET['algorithm']);
if (!is_string($password_hash) || empty($password_hash)) {
    fwrite(STDOUT, PHP_EOL . 'Error: Failed to create a valid password hash.' . PHP_EOL);
    exit(1);
}

/**
 * Connect to database.
 */
try {
    $dbh = new PDO($config['pdo']['dsn'], $config['pdo']['username'], $config['pdo']['password'], $config['pdo']['options']);
} catch (PDOException $e) {
    fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
} catch (Exception $e) {
    fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

/**
 * Get user
 */
try {
    $sth = $dbh->prepare("SELECT * FROM users WHERE username = :username");
    if (!$sth instanceof PDOStatement) {
        fwrite(STDOUT, PHP_EOL . 'Error: SQL query for user failed.' . PHP_EOL);
        exit(1);
    }

    $result = $sth->execute(array(
        ':username' => $_GET['username']
    ));

    if (!$result) {
        fwrite(STDOUT, PHP_EOL . 'Error: SQL query for user failed.' . PHP_EOL);
        exit(1);
    }

    $user = $sth->fetch(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
} catch (Exception $e) {
    fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

if (!is_array($user) || empty($user)) {
    try {
        $sth = $dbh->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
        if ($sth instanceof PDOStatement) {
            $sth->execute(array(
                ':username' => $_GET['username'],
                ':password' => $password_hash
            ));
        }
    } catch (PDOException $e) {
        fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
        exit(1);
    } catch (Exception $e) {
        fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
        exit(1);
    }

    fwrite(STDOUT, PHP_EOL . 'The user ' . $_GET['username'] . ' has been created!' . PHP_EOL);
} else {
    try {
        $sth = $dbh->prepare("UPDATE users SET password = :password WHERE id = :userid");
        if ($sth instanceof PDOStatement) {
            $sth->execute(array(
                ':password' => $password_hash,
                ':userid'   => $user['id']
            ));
        }
    } catch (PDOException $e) {
        fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
        exit(1);
    } catch (Exception $e) {
        fwrite(STDOUT, PHP_EOL . 'Error: ' . $e->getMessage() . PHP_EOL);
        exit(1);
    }

    fwrite(STDOUT, PHP_EOL . 'Password changed for user ' . $_GET['username'] . '!'. PHP_EOL);
}