<?php
$br = (php_sapi_name() == "cli")? "":"<br>";

if(!extension_loaded('ole')) {
	dl('ole.' . PHP_SHLIB_SUFFIX);
}
$module = 'ole';
$functions = get_extension_funcs($module);
echo "Functions available in the test extension:$br\n";
foreach($functions as $func) {
    echo $func."$br\n";
}
echo "$br\n";
$function = 'confirm_' . $module . '_compiled';
if (extension_loaded($module)) {
	$str = $function($module);
} else {
	$str = "Module $module is not compiled into PHP";
}
echo "$str\n";


$ole = new OleInfile();
$methods = get_class_methods($ole);
var_dump($methods);

$ret = $ole->open("/mnt/hgfs/VMShare/wordml/Book.xlsx");
if($ret){
	var_dump($ole);
	$info = $ole->getEncryptionInfo();
	if($info){
		var_dump(get_class_methods($info));

		$pass = password("sample",$info);
		
		if($pass){
			print "====== OK ==== \n";
			$fp = $ole->getStreamByName('EncryptedPackage');
			if($fp){
				$ret = fread($fp,8);
				$ret = unpack("ilen",$ret);
				$data = "";
				while(!feof($fp)){
					$data .= fread($fp,4096);
				}
				fclose($fp);

				$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
				$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
				$skey = $info->getSecretKey();
				$content = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $skey, $data, MCRYPT_MODE_ECB, $iv);
				$out = fopen("/mnt/hgfs/VMShare/wordml/Book_un.xlsx","w");
				fwrite($out,$content);
				fclose($out);
			}
		}
	}
}

function password($pswd,$info){

	$info->verifyPassword(mb_convert_encoding($pswd,"UTF-16LE"));

	$skey = $info->getSecretKey();
  $vf = $info->getVerifier();
  $vf_hash = $info->getVerifierHash();

  $size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
  $iv = mcrypt_create_iv($size, MCRYPT_RAND);
  $_check1 = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $skey, $vf, MCRYPT_MODE_ECB, $iv);
  $check1 = sha1($_check1,1);
  $check2 = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $skey, $vf_hash, MCRYPT_MODE_ECB, $iv);

	if($check1 == substr($check2,0,strlen($check1))){
		return true;
	}
	else{
		return false;
	}
}

function hexstr2(&$data){
  $len = strlen($data);
  $ret = "";
  for($i = 0; $i < $len; $i++){
    $hex = dechex(ord($data[$i]));
    $ret .= str_pad($hex, 2, "0", STR_PAD_LEFT);
  }
  return $ret;
}

?>
