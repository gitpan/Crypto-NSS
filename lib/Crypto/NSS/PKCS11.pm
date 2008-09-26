package Crypto::NSS::PKCS11;

use strict;
use warnings;

1;
__END__

=head1 NAME

Crypto::NSS::PKCS11 - Functions needed for communicating with PKCS#11 cryptographic modules

=head1 DESCRIPTION

PKCS#11 is a API for interfacing with cryptographic modules such as software tokens, smart cards. 
This module provides functions for obtaining certificates, keys, passwords etc.

=head1 INTERFACE

=head2 CLASS METHODS

=over

=item set_password_func ( CALLBACK )

Sets the function to call when a PKCS#11 module needs a password. The argument I<CALLBACK> must be either 
a code reference or a fully qualified function name.

=back

=cut