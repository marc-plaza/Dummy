<?php
namespace Dummy;
class SecureCookie {
    private $key;
    private $iv;
    private $name;
    private $content;

    public function __construct($name,$key,$iv,$time = 86400) {
        $this->name = $name;
        $this->key = $key;
        $this->iv = $iv;
        $this->time = $time;
        if(isset($_COOKIE[$name])) {
            $this->content = unserialize(openssl_decrypt($_COOKIE[$name], "AES-256-CBC", $key, 0, $iv));
            if(!is_array($this->content)) {
                throw new \Exception("Can't retrieve content, are you using the right key and iv ?");
            }
        } else {
            $this->content = [];
        }
    }

    public function set($name,$value = '') {
        if(is_array($name)) {
            $this->content = $name;
        } else {
            $this->content[$name] = $value;
        }
        setcookie($this->name,openssl_encrypt(serialize($this->content), "AES-256-CBC", $this->key, 0, $this->iv),time()+$this->time,null,null,false,true);
    }

    public function get($name) {
        if(isset($this->content[$name])) {
            return $this->content[$name];
        }
        return null;
    } 
}