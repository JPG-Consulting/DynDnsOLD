<?php
/**
 * DynDns (http://github.com/JPG-Consulting/DynDns/)
 *
 * @link      https://github.com/JPG-Consulting/DynDns/
 * @copyright Copyright (c) 2015 Juan Pedro Gonzalez (http://www.jpg-consulting.com.com)
 * @license   http://www.gnu.org/licenses/gpl.html GNU General Public License v2.0
 */
return array(
    'pdo' => array(
        'dsn' => 'sqlite:' . dirname(__DIR__) . '/data/dyndns.sqlite',
        'username' => null,
        'password' => null,
        'options'  => array()
    ),
    'authentication' => array(
        /**
         * Authentication realm (Optional)
         *
         * Default: $_SERVER['SERVER_NAME']
         */
        //'realm' => 'Restricted area',
    ),
    'ttl' => 300
);