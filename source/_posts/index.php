<?php
error_reporting(0);
highlight_file(__FILE__);
$code=$_GET['code'];
if(preg_match('/[a-z0-9]/i',$code)){
    die('hacker');
}
eval($code);
