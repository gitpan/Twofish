package Crypt::Twofish;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw( Encipher Decipher LastError CheckTwofish );
$VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined Crypt::Twofish macro $constname";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap Crypt::Twofish $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=pod

=head1 NAME

Crypt::Twofish - Perl extension for Twofish. Twofish is a 128-bit block cipher. 

=head1 SYNOPSIS

  use Crypt::Twofish; 

  $ciphertext = Encipher($key,$keylength,$plaintext); 

  $decryptedtext = Decipher($key,$keylength,$ciphertext,$cipherlength);

  $lasterror = LastError();  

  CheckTwofish();  
    
=head1 DESCRIPTION

   This module is a perl extension for the Twofish encryption algorithm. The 
following are the four functions that this module supports:

   1. Encipher
   2. Decipher
   3. LastError
   4. CheckTwofish
 
  Encipher takes the key, the key length and the message to be encrypted as
parameters and returns the ciphertext. This is a variation from the actual
Twofish algorithm which only accepts keys of length 128(16 bytes),194(24 bytes)
or 256(32 bytes). What this algorithm does is, if the key length is not equal
to 128, 194 or 256 bits, and less than 256, it appends the key to itself until
the key length becomes equal to 256(32 bytes). If the key length is more than
32 bytes then only the first 32 bytes are considered as the key. Basically, you
can use any key you want and the module would do the rest for you.
You would typically call encipher as:

  $ciphertext = Encipher($key,$keylength,$plaintext);

Note: Remember to pass the key length parameter in bytes.

   Decipher takes the key, keylength, ciphertext and the length of ciphertext
as parameters and returns the plain text. Even Decipher does the same kind
of key repitition as Encipher. Here it is important to remember that
you have to use the same key with which you have encrypted, otherwise you get
garbled output. Decipher can typically be called as:

  $decryptedtext = Decipher($key,$keylength,$ciphertext,$cipherlength);

  $cipherlength is the length of the ciphertext, which is a multiple of 16
  (the block size). It can be useful for decrypting substrings. Once again
  pass the key length in bytes.
  
  LastError is a very useful function when something goes wrong with Encipher 
or Decipher. It returns the last error that was encountered. It does not take 
any arguements and can be simply called as:

  $lasterror = LastError();

  CheckTwofish is

=head1 INSTALLATION

 You can install this module by using the following commands:

 perl Makefile.PL
 make
 make test
 make install
  
=head1 AUTHOR

 Nishant Kakani, nishantkakani@hotmail.com

 I would like to thank Xenoscience Inc. and Counterpane Systems, without whose 
help I wouldn't have written this module. 

=head1 SEE ALSO
More about the Twofish algorithm can be found at the following site:
 
 http://www.counterpane.com/twofish.html

=cut
