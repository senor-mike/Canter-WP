<?php

// ------------------------------------------------------
//		Verification
// ------------------------------------------------------
function wp_check_password($password, $hash, $user_id = '')
{
	global $wp_hasher;

	// If the hash is still md5...
	if (strlen($hash) <= 32)
	{
		$check = hash_equals($hash, md5( $password));

		if ($check && $user_id)
		{
			// Rehash using new hash.
			wp_set_password($password, $user_id);

			$hash = wp_hash_password($password);
		}

		/**
		 * Filters whether the plaintext password matches the encrypted password.
		 *
		 * @since 2.5.0
		 *
		 * @param bool       $check    Whether the passwords match.
		 * @param string     $password The plaintext password.
		 * @param string     $hash     The hashed password.
		 * @param string|int $user_id  User ID. Can be empty.
		 */
		return apply_filters('check_password', $check, $password, $hash, $user_id);
	}

	// If the stored hash is longer than an MD5,
	// presume the new style phpass portable hash.
	if (empty($wp_hasher ))
	{
		// require_once ABSPATH . WPINC . '/class-phpass.php';

		// // By default, use the portable hash from phpass.
		// $wp_hasher = new PasswordHash( 8, true );
	}

	$check = CheckPassword( $password, $hash );

	echo "CheckPassword() => $check: " .$check;
	/** This filter is documented in wp-includes/pluggable.php */
	// return apply_filters('check_password', $check, $password, $hash, $user_id);
}


function wp_set_password( $password, $user_id )
{
	global $wpdb;

	// CALL function HashPassword()

	//$hash = wp_hash_password($password);
		$hash = HashPassword($password);

	//$wpdb->update(
	//    $wpdb->users,
	//    array(
	//        'user_pass'           => $hash,
	//        'user_activation_key' => '',
	//    ),
	//    array( 'ID' => $user_id )
	//);

	//clean_user_cache( $user_id );
}


function CheckPassword($password, $stored_hash)
{
	if ( strlen( $password ) > 4096 ) {
		return false;
	}

	$hash = crypt_private($password, $stored_hash);
	if ($hash[0] == '*')
		$hash = crypt($password, $stored_hash);

	$result = $hash === $stored_hash;
	echo '$hash === $stored_hash: ' . $result;

	return $hash === $stored_hash;
}


// ------------------------------------------------------
//		Hashing
// ------------------------------------------------------
function encode64($input, $count)
{
	$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

	$output = '';
	$i = 0;
	do {
		$value = ord($input[$i++]);

		$output .= $itoa64[$value & 0x3f];

		if ($i < $count)
			$value |= ord($input[$i]) << 8;
			$output .= $itoa64[($value >> 6) & 0x3f];

		if ($i++ >= $count)
			break;

		if ($i < $count)
			$value |= ord($input[$i]) << 16;
			$output .= $itoa64[($value >> 12) & 0x3f];

		if ($i++ >= $count)
			break;

		$output .= $itoa64[($value >> 18) & 0x3f];

	} while ($i < $count);

	return $output;
}

// pluggable.php
// default value for iteration_count_log2 is 8

function gensalt_private($input)
{
	$iteration_count_log2 = 8;

	$output = '$P$';
	$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

	$output .= $itoa64[min(13, 30)];

	$output .= encode64($input, 6);

	return $output;
}

function crypt_private($password, $setting)
{
	$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

	$output = '*0';
	if (substr($setting, 0, 2) == $output)
		$output = '*1';

	$id = substr($setting, 0, 3);
	# We use "$P$", phpBB3 uses "$H$" for the same thing
	if ($id != '$P$' && $id != '$H$')
		return $output;

	$count_log2 = strpos($itoa64, $setting[3]);
	if ($count_log2 < 7 || $count_log2 > 30)
		return $output;

	$count = 1 << $count_log2;

	$salt = substr($setting, 4, 8);
	if (strlen($salt) != 8)
		return $output;

	# We're kind of forced to use MD5 here since it's the only
	# cryptographic primitive available in all versions of PHP
	# currently in use.  To implement our own low-level crypto
	# in PHP would result in much worse performance and
	# consequently in lower iteration counts and hashes that are
	# quicker to crack (by non-PHP code).
	if (PHP_VERSION >= '5') {
		$hash = md5($salt . $password, TRUE);
		do {
			$hash = md5($hash . $password, TRUE);
		} while (--$count);
	} else {
		$hash = pack('H*', md5($salt . $password));
		do {
			$hash = pack('H*', md5($hash . $password));
		} while (--$count);
	}

	$output = substr($setting, 0, 12);
	$output .= encode64($hash, 16);

	return $output;
}

function get_random_bytes($count)
{
	$output = '';

	if ( @is_readable('/dev/urandom') && ($fh = @fopen('/dev/urandom', 'rb')))
	{
		$output = fread($fh, $count);
		fclose($fh);
	}

	if (strlen($output) < $count)
	{
		$output = '';

		$random_state = microtime() . uniqid(rand(), TRUE);

		for ($i = 0; $i < $count; $i += 16)
		{
			$random_state = md5(microtime() . $random_state);
			$output .= pack('H*', md5($random_state));
		}

		// echo '$output => ' . $output . "<br>";

		// $mb_output = mb_substr($output, 0, $count, 'utf-8');
		// echo '$mb_output mb_substr => ' . $mb_output . "<br>";

		$output = substr($output, 0, $count);

		//echo '$output substr => ' . $output;


	}

	return $output;
}

function HashPassword($password)
{

	// if ( strlen( $password ) > 4096 )
	// {
	// 	return '*';
	// }

	$random = '';

	// if (CRYPT_BLOWFISH == 1 && !$this->portable_hashes)
	// {
		$random = get_random_bytes(16);
		$hash = crypt($password, gensalt_blowfish($random));
		if (strlen($hash) == 60) return $hash;
	// }

		if (strlen($random) < 3)
			$random = get_random_bytes(3);
		    $hash = crypt($password, gensalt_extended($random));

		   if (strlen($hash) == 20) return $hash;
	

	// if (strlen($random) < 6)
	// {
	// 	$random = get_random_bytes(6);
	//     $hash = crypt_private($password, gensalt_private($random));
	// }

	// if (strlen($hash) == 34) return $hash;
}

	function gensalt_blowfish($input)
	{
		# This one needs to use a different order of characters and a
		# different encoding scheme from the one in encode64() above.
		# We care because the last character in our encoded string will
		# only represent 2 bits.  While two known implementations of
		# bcrypt will happily accept and correct a salt string which
		# has the 4 unused bits set to non-zero, we do not want to take
		# chances and we also do not want to waste an additional byte
		# of entropy.
		$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

		$output = '$2a$';
		$output .= chr(ord('0') + 8 / 10);
		$output .= chr(ord('0') + 8 % 10);
		$output .= '$';

		$i = 0;
		do {
			$c1 = ord($input[$i++]);
			$output .= $itoa64[$c1 >> 2];
			$c1 = ($c1 & 0x03) << 4;
			if ($i >= 16) {
				$output .= $itoa64[$c1];
				break;
			}

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 4;
			$output .= $itoa64[$c1];
			$c1 = ($c2 & 0x0f) << 2;

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 6;
			$output .= $itoa64[$c1];
			$output .= $itoa64[$c2 & 0x3f];
		} while (1);

		return $output;
	}

	function gensalt_extended($input)
	{

		$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';


		$count_log2 = min(8 + 8, 24);
		# This should be odd to not reveal weak DES keys, and the
		# maximum valid value is (2**24 - 1) which is odd anyway.
		$count = (1 << $count_log2) - 1;

		$output = '_';
		$output .= $itoa64[$count & 0x3f];
		$output .= $itoa64[($count >> 6) & 0x3f];
		$output .= $itoa64[($count >> 12) & 0x3f];
		$output .= $itoa64[($count >> 18) & 0x3f];

		$output .= encode64($input, 3);

		return $output;
	}


// START - HASH PWD
	// $hashed_password = HashPassword("_jcuttie01");
	// echo "Hash for '_jcuttie01': " . $hashed_password;


// START - VERIFY HASH
$result = wp_check_password('_jcuttie01', '$1$Hcmgompv$suYZo82he8P3BhyOuy93P/');
echo 'VERIFICATION RESULT: ' . $result;

// test123
// $P$LV.bovyQgeqI5cLsuA2Kljcf/NzoIIA
