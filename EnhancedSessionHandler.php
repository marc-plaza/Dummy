<?php
namespace Dummy;
class EnhancedSessionHandler implements \SessionHandlerInterface {
    private $db;
    private $key;
    private $iv;
    private $readStmt;
    private $writeStmt;
    private $insertStmt;
    private $destroyStmt;
    private $gcStmt;

    public function __construct($db,$user,$password,$key,$iv) {
        try {
            $this->key = $key;
            $this->iv = $iv;
            $this->db = new \PDO('mysql:host=localhost;dbname='.$db.';charset=utf8', $user, $password);
            $this->db->query('CREATE TABLE IF NOT EXISTS `sessions` (id VARCHAR(32) NOT NULL PRIMARY KEY,content TEXT,date INTEGER)');
            $this->readStmt = $this->db->prepare('SELECT content FROM `sessions` WHERE id = :id');
            $this->writeStmt = $this->db->prepare('UPDATE `sessions` SET content = :content, date = :date WHERE id = :id');
            $this->insertStmt = $this->db->prepare('INSERT IGNORE INTO `sessions` (id) VALUES (:id)');
            $this->deleteStmt = $this->db->prepare('DELETE FROM `sessions` WHERE id = :id');
            $this->gcStmt = $this->db->prepare('DELETE FROM `sessions` WHERE date < :date');
            $this->db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        } catch(\PDOException $e) {
            trigger_error("Can't create session. ".$e->getMessage(),E_USER_ERROR);
        }
    }

    public function open($save_path,$session_id) {
        return true;
    }

    public function create_sid() {
        return bin2hex(openssl_random_pseudo_bytes(16));
    }

    public function read($id) {
        try {
            $this->readStmt->bindValue(':id',$id);
            $this->readStmt->execute();
            $field = $this->readStmt->fetch();
            if(!$field) {
                return '';
            }
            return openssl_decrypt($field[0], "AES-256-CBC", $this->key, 0, $this->iv);
        } catch(\PDOException $e) {
            trigger_error("Can't read session. ".$e->getMessage(),E_USER_ERROR);
        }
    }

    public function write($id,$data) {
        try {
            $this->insertStmt->bindValue(':id',$id);
            $this->insertStmt->execute();
            $this->writeStmt->bindValue(':id',$id);
            $this->writeStmt->bindValue(':content',openssl_encrypt($data, "AES-256-CBC", $this->key, 0, $this->iv));
            $this->writeStmt->bindValue(':date',time());
            return $this->writeStmt->execute();
        } catch(\PDOException $e) {
            trigger_error("Can't write session. ".$e->getMessage(),E_USER_ERROR);
        }
    }

    public function destroy($id) {
        try {
            $this->deleteStmt->bindValue(':id',$id);
            return $this->deleteStmt->execute();
        } catch(\PDOException $e) {
            trigger_error("Can't delete session. ".$e->getMessage(),E_USER_ERROR);
        }
    }

    public function gc($maxlifetime) {
        try {
            $time = time() - $maxlifetime;
            $this->gcStmt->bindValue(':date',$time);
            return $this->gcStmt->execute();
        } catch(\PDOException $e) {
            trigger_error("Can't clean sessions. ".$e->getMessage(),E_USER_ERROR);
        }
    }

    public function close() {
        $this->gc(ini_get('session.gc_maxlifetime') || 24*60);
        $this->db = null;
        return true;
    }
}