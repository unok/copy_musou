<?php
/*
The MIT License (MIT)

Copyright (c) 2015 Kazuhiko UNO

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/*
 * CREATE TABLE datas (id integer primary key autoincrement, user_name text not null, access_key text not null, hash_value text not null, content text not null, created datetime, updated datetime);
 * CREATE UNIQUE INDEX datas_user_name_access_key on datas (user_name, access_key);
 *
 * library
 *     mcrypt
 *     PDO:sqlite
 *
 */
const KEY_MIN_LEN          = 4;
const USER_KEY             = 'user_name';
const ACCESS_KEY           = 'access_key';
const DATA_KEY             = 'data';
const DATA_TABLE_NAME      = 'datas';
const MAX_UPLOAD_FILE_SIZE = 1048576; // 1Mbyte
const DATA_LIFE_TIME       = 300; // 5min

$SALT = '12345678901234567890';

$salt_tmp = getenv('COPY_MUSOU_SALT');

if (!empty($salt_tmp)) {
    $SALT = $salt_tmp;
}

/**
 * EasyCrypt
 *
 * A class that provides you simple interface for decryptable encryption.
 * Requires PHP 5.0.0 or later.
 *
 * @Version 2.0.1
 * @Author  CertaiN
 * @License CC0 (No rights reserved)
 * @GitHub  http://github.com/certainist/EasyCrypt
 */
class EasyCrypt
{

    /**
     * @access   private
     * @property
     */
    private $key;
    private $mc;
    private $iv_size;
    private $init;

    /**
     * For encrypting.
     *
     * @access public
     * @static
     * @param  string $data Raw data.
     * @param  string $salt Secret key.
     * @return mixed  Encrypted data or FALSE on empty string.
     */
    public static function encrypt($data, $salt)
    {
        if ((string)$data === '') {
            return false;
        }
        $obj = new self($salt);
        return $obj->_encrypt($data);
    }

    /**
     * For decrypting.
     *
     * @access public
     * @static
     * @param  string $data Encrypted data.
     * @param  string $salt Secret key.
     * @return mixed  Decrypted data or FALSE.
     */
    public static function decrypt($data, $salt)
    {
        $obj = new self($salt);
        return $obj->_decrypt($data);
    }

    private function __construct($salt)
    {
        $this->mc      = mcrypt_module_open('rijndael-256', '', 'cbc', '');
        $this->key     = substr(sha1($salt), 0, mcrypt_enc_get_key_size($this->mc));
        $this->iv_size = mcrypt_enc_get_iv_size($this->mc);
    }

    private function __destruct()
    {
        if ($this->init) {
            mcrypt_generic_deinit($this->mc);
        }
        mcrypt_module_close($this->mc);
    }

    private function _encrypt($data)
    {
        if (PHP_OS === 'WIN32' || PHP_OS === 'WINNT') {
            srand();
            $iv = mcrypt_create_iv($this->iv_size, MCRYPT_RAND);
        } else {
            $iv = mcrypt_create_iv($this->iv_size, MCRYPT_DEV_URANDOM);
        }
        mcrypt_generic_init($this->mc, $this->key, $iv);
        $this->init = true;
        $data       = mcrypt_generic($this->mc, base64_encode($data));
        return rtrim(base64_encode(base64_encode($iv) . '-' . base64_encode($data)), '=');
    }

    private function _decrypt($data)
    {
        list($iv, $data) = array_map('base64_decode',
            explode(
                '-',
                base64_decode($data, true),
                2
            )
            + [1 => '']
        );
        if ($data === '' || !isset($iv[$this->iv_size - 1])) {
            return false;
        }
        mcrypt_generic_init($this->mc, $this->key, $iv);
        $this->init = true;
        return base64_decode(rtrim(mdecrypt_generic($this->mc, $data), "\0"), true);
    }

}

class DataManager
{
    private $db;
    private $salt;

    public function __construct($salt)
    {
        $this->db   = $this->get_db_connection();
        $this->salt = $salt;
    }


    public function get_content($user_key, $access_key)
    {
        $st_sel = $this->db->prepare("SELECT content, hash_value FROM " . DATA_TABLE_NAME . " WHERE user_name = ? AND access_key = ?");
        $st_sel->execute([$user_key, $this->convert_key($access_key)]);

        $record     = $st_sel->fetch();
        if ($record == false) {
            header("HTTP/1.1 403 Forbidden");
            return false;
        }

        $content    = $record['content'];
        $hash_value = $record['hash_value'];

        $decoded_content = $this->dencrypt_content($content, $access_key);
        assert($hash_value === sha1($decoded_content));

        return $this->dencrypt_content($content, $access_key);
    }

    public function put_content($user_key, $access_key, $file)
    {
        $this->data_insert($user_key, $access_key, $file);
        return true;
    }

    private function data_insert($user_key, $access_key, $file)
    {
        $fp       = fopen($file['tmp_name'], "r");
        $contents = fread($fp, min(filesize($file['tmp_name']), MAX_UPLOAD_FILE_SIZE));
        fclose($fp);

        $this->db->beginTransaction();
        $st_del = $this->db->prepare("DELETE FROM " . DATA_TABLE_NAME . " WHERE (user_name = ? AND access_key = ?) OR updated < ?");
        $st_ins = $this->db->prepare("INSERT INTO " . DATA_TABLE_NAME . " (user_name, access_key, content, hash_value, created, updated) VALUES (?, ?, ?, ?, ?, ?)");

        $st_del->execute([$user_key, $this->convert_key($access_key), date('Y/m/d H:i:s', strtotime(sprintf("-%d sec", DATA_LIFE_TIME)))]);
        $st_ins->execute([$user_key, $this->convert_key($access_key), $this->encrypt_content($contents, $access_key), sha1($contents), date('Y/m/d H:i:s'), date('Y/m/d H:i:s')]);

        $this->db->commit();
    }

    private function get_db_connection()
    {
        $db = new PDO('sqlite:' . DIRECTORY_SEPARATOR . __DIR__ . DIRECTORY_SEPARATOR . 'copy_musou.db');
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $db;
    }

    private function convert_key($key)
    {
        return sha1($key);
    }

    private function encrypt_content($content, $access_key)
    {
        return base64_encode(EasyCrypt::encrypt($content, $this->make_user_salt($access_key)));
    }

    private function dencrypt_content($content, $access_key)
    {
        return EasyCrypt::decrypt(base64_decode($content), $this->make_user_salt($access_key));
    }

    private function make_user_salt($access_key)
    {
        return $this->salt . $access_key;
    }
}


if (!array_key_exists(USER_KEY, $_POST) || !array_key_exists(ACCESS_KEY, $_POST)) {
    header("HTTP/1.1 401 Unauthorized");
    return false;
}

$user_key   = $_POST[USER_KEY];
$access_key = $_POST[ACCESS_KEY];

if (strlen($user_key) < KEY_MIN_LEN || strlen($access_key) < KEY_MIN_LEN) {
    header("HTTP/1.1 401 Unauthorized");
    return false;
}

$dm = new DataManager($SALT);
if (empty($_FILES)) {
    $content = $dm->get_content($user_key, $access_key);
    header('Content-Type: application/octet-stream');
    print $content;
    return true;
} elseif (array_key_exists(DATA_KEY, $_FILES)) {
    return $dm->put_content($user_key, $access_key, $_FILES[DATA_KEY]);
} else {
    header("HTTP/1.1 406 Not Acceptable");
    return false;
}

