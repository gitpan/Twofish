# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use Crypt::Twofish;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

#!/usr/bin/perl

use Crypt::Twofish;

$key='biff';
$plaintext = '00_form     =[test] Credit Card Information
01_name     = Nishant Kakani
02_type     =Visa/master
03_number   =1234 1234 1234 1234
04_expmonth =11
05_expyear  =12';

$ciphertext= Encipher($key,length($key),$plaintext);
if(!$ciphertext) {print "not ok13\n";}
$decrypted= Decipher($key,length($key),$ciphertext,length($ciphertext));
if(!decrypted) {print "not ok13\n";}
print "ok13\n";
exit;               
