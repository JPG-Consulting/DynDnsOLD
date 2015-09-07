<?php
if (!defined('PASSWORD_BCRYPT')) {
	/**
	 * PHPUnit Process isolation caches constants, but not function declarations.
	 * So we need to check if the constants are defined separately from
	 * the functions to enable supporting process isolation in userland
	 * code.
	 */
	define('PASSWORD_BCRYPT', 1);
	define('PASSWORD_DEFAULT', PASSWORD_BCRYPT);
	define('PASSWORD_BCRYPT_DEFAULT_COST', 10);
}

if (php_sapi_name() !== "cli") {
    echo "Error: This script must be runned from CLI.";
    exit(1);
}

/**
 * Configuration
 */
$config = require(dirname(__DIR__) . '/config/dyndns.config.php');

/**
 * Arguments:
 *    --username=[USERNAME]
 *    --password=[PASSWORD]
 *    --salt=[SALT]
 *    --algorithm=[BCRYPT]
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
switch ($_GET['algorithm']) {
    case PASSWORD_BCRYPT:
        $cost = PASSWORD_BCRYPT_DEFAULT_COST;
        if (isset($_GET['cost'])) {
        	$cost = (int) $_GET['cost'];
        	if ($cost < 4 || $cost > 31) {
        		fwrite(STDOUT, PHP_EOL . 'Error: Invalid bcrypt cost argument specified: ' . $_GET['cost'] . PHP_EOL);
        		exit(1);
        	}
        	 
        } elseif (isset($config['authentication']['cost'])) {
            $cost = (int) $config['authentication']['cost'];
            if ($cost < 4 || $cost > 31) {
                fwrite(STDOUT, PHP_EOL . 'Error: Invalid bcrypt cost: ' . $config['authentication']['cost'] . PHP_EOL);
                exit(1);
            }
        }
        // The length of salt to generate
        $raw_salt_len = 16;
        // The length required in the final serialization
        $required_salt_len = 22;
        $hash_format = sprintf("$2y$%02d$", $cost);
        // The expected length of the final crypt() output
        $resultLength = 60;
        break;
    default:
        fwrite(STDOUT, PHP_EOL . 'Error: Unknown password hashing algorithm.' . PHP_EOL);
        exit(1);
}

$salt_req_encoding = false;

if (isset($_GET['salt'])) {
    switch (gettype($_GET['salt'])) {
        case 'NULL':
        case 'boolean':
        case 'integer':
        case 'double':
        case 'string':
            $salt = (string) $_GET['salt'];
            break;
        case 'object':
            if (method_exists($_GET['salt'], '__tostring')) {
                $salt = (string) $_GET['salt'];
                break;
            }
        case 'array':
        case 'resource':
        default:
            fwrite(STDOUT, PHP_EOL . 'Error: Non-string salt parameter supplied.' . PHP_EOL);
            exit(1);
    }

    if (function_exists('mb_strlen')) {
        $given_salt_length = mb_strlen($salt, '8bit');
    } else {
        $given_salt_length = strlen($salt);
    }

    if ($given_salt_length < $required_salt_len) {
        fwrite(STDOUT, PHP_EOL . 'Error: Provided salt is too short: ' . $given_salt_length . ' expecting ' . $required_salt_len . '.' . PHP_EOL);
        exit(1);
    } elseif (0 == preg_match('#^[a-zA-Z0-9./]+$#D', $salt)) {
        $salt_req_encoding = true;
    }
} else {
    $buffer = '';
    $buffer_valid = false;

    if (function_exists('mcrypt_create_iv') && !defined('PHALANGER')) {
        $buffer = mcrypt_create_iv($raw_salt_len, MCRYPT_DEV_URANDOM);
        if ($buffer) {
            $buffer_valid = true;
        }
    }

    if (!$buffer_valid && function_exists('openssl_random_pseudo_bytes')) {
        $strong = false;
        $buffer = openssl_random_pseudo_bytes($raw_salt_len, $strong);
        if ($buffer && $strong) {
            $buffer_valid = true;
        }
    }

    if (!$buffer_valid && @is_readable('/dev/urandom')) {
        $file = fopen('/dev/urandom', 'r');
        $read = 0;
        $local_buffer = '';
        while ($read < $raw_salt_len) {
            $local_buffer .= fread($file, $raw_salt_len - $read);
            
            if (function_exists('mb_strlen')) {
                $read = mb_strlen($local_buffer, '8bit');
            } else {
                $read = strlen($local_buffer);
            }
        }
        fclose($file);
        if ($read >= $raw_salt_len) {
            $buffer_valid = true;
        }
        $buffer = str_pad($buffer, $raw_salt_len, "\0") ^ str_pad($local_buffer, $raw_salt_len, "\0");
    }

    if (function_exists('mb_strlen')) {
        $buffer_length = mb_strlen($buffer, '8bit');
    } else {
        $buffer_length = strlen($buffer);
    }
    
    if (!$buffer_valid || $buffer_length < $raw_salt_len) {
        for ($i = 0; $i < $raw_salt_len; $i++) {
            if ($i < $buffer_length) {
                $buffer[$i] = $buffer[$i] ^ chr(mt_rand(0, 255));
            } else {
                $buffer .= chr(mt_rand(0, 255));
            }
        }
    }

    $salt = $buffer;
    $salt_req_encoding = true;
}

if ($salt_req_encoding) {
    // encode string with the Base64 variant used by crypt
    $base64_digits = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    $bcrypt64_digits = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    $base64_string = base64_encode($salt);
    $salt = strtr(rtrim($base64_string, '='), $base64_digits, $bcrypt64_digits);
}

if (function_exists('mb_substr')) {
    $salt = mb_substr($salt, 0, $required_salt_len, '8bit');
} else {
    $salt = substr($salt, 0, $required_salt_len);
}

$hash = $hash_format . $salt;

$password_hash = crypt($_GET['password'], $hash);

if (function_exists('mb_strlen')) {
    if (!is_string($password_hash) || mb_strlen($password_hash, '8bit') != $resultLength) {
        fwrite(STDOUT, PHP_EOL . 'Error: Failed to create password hash.' . PHP_EOL);
        exit(1);
    }
} else {
    if (!is_string($password_hash) || strlen($password_hash) != $resultLength) {
        fwrite(STDOUT, PHP_EOL . 'Error: Failed to create password hash.' . PHP_EOL);
        exit(1);
    }
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