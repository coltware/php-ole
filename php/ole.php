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

$ole = new OleInfile();
$methods = get_class_methods($ole);
print "------ Class ".get_class($ole)." method list --------\n";
var_dump($methods);

$file = $argv[1];
if(!is_file($file)){
	die("can't find input-file [".$file."]\n");
}

$ret = $ole->open($file);
if($ret){
	$num = $ole->numChildren();
	if($num > 0){
		print "=== document entries === \n";
		for($i = 0; $i < $num; $i++){
			$stat = $ole->statIndex($i);
			var_dump($stat);
			//
			//  array(2) {
			//		["name"] => "xxxxxxx",
			//		["size"] => 9999
			//  }
		}
	}
	
	$info = $ole->getEncryptionInfo();
	if($info){
		print "------ Class ".get_class($info)." method list --------\n";
		var_dump(get_class_methods($info));
		
		$pass = password("abc",$info);
		
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
				$out = fopen(basename($file),"w");
				fwrite($out,$content);
				fclose($out);
			}
		}
	}
}

function password($pswd,$info){
	
	if(function_exists('mb_convert_encoding')){
		$info->verifyPassword(mb_convert_encoding($pswd,"UTF-16LE","UTF-8"));	
	}
	else{
		$info->verifyPassword(iconv("UTF-8","UTF-16LE",$pswd));
	}
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
