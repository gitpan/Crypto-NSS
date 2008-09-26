package Crypto::NSS;

use 5.006002;
use strict;
use warnings;

our $VERSION = '0.01_02';

require XSLoader;
XSLoader::load('Crypto::NSS', $VERSION);

require Net::NSS::SSL;

Crypto::NSS::PKCS11->set_password_func(sub {});

sub import {
    while(@_) {
        my $arg = shift;
        if ($arg eq "config_dir") {
            my $path = shift;
            Crypto::NSS->set_config_dir($path);
            Crypto::NSS->initialize;
        }
        elsif ($arg eq "init") {
            my $path = $ENV{NSS_CONFIG_DIR};
            Crypto::NSS->set_config_dir($path) if $path;
            Crypto::NSS->initialize;
        }
    }
    1;
}

1;
__END__

=head1 NAME

Crypto::NSS - Perl bindings to NSS (Netscape Security Services)

=head1 SYNOPSIS

  # Using NSS for SSL connections from LWP
  use LWP;
  use Crypto::NSS config_dir => "$ENV{HOME}/.netscape";
  use Net::HTTPS;
  
  local @Net::HTTPS::ISA = qw(Net::NSS::SSL Net::HTTP::Methods);
  
  my $content = get("https://secure.mycompany.com");
  
=head1 DESCRIPTION

This module provides an interface to Netscape Security Services (NSS) which is a set of libraries 
that Firefox, Thunderbird and several other applications uses for crypto, secure sockets, 
signing mail etc. NSS provides support for SSL v2 and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, 
X.509 v3 certificates, and other security standards.

Currently this module only implements the SSL bits but in the future (patches welcome!!) most of NSS will 
be available via this module.

=head1 INTERFACE

=head2 MODULE IMPORT

During import no initalization is normally done. It's however possible to do this by passing either 
C<config_dir =E<gt> PATH> or C<init>. If the later, import checks for the environment C<NSS_CONFIG_DIR> 
and sets the config dir to that if set.

=head2 CLASS METHODS

=over 4

=item config_dir ( ) : STRING

Returns the path where to look for C<cert8.db>, C<key3.db> and C<secmod.db> databases upon initialization.

=item set_config_dir ( DIRECTORY ) : BOOL

Specify the path to the directory where the C<cert8.db>, C<key3.db> and C<secmod.db> databases can be found. 
It's only allowed to set the directory prior to initialization or this method with return a false value.

=item is_initialized ( ) : BOOL

Returns whether the underlying NSS library has been initialized or not.

=item initialize ( ) : ERROR_CODE

Initializes NSS. Returns 0 on success or an error code on failure. Initialization is usually done 
when importing this module by passing either C<config_dir =E<gt> $path> or C<init> to use 
the default config directory (C<.>).

=back

=head1 BUGS AND LIMITATIONS

Please report any bugs or feature requests to C<bug-nss@rt.cpan.org>, 
or through the web interface at L<http://rt.cpan.org>.

=head1 SUPPORT

Commercial support is available from Versed Solutions. Contact author for details.

=head1 AUTHOR

Claes Jakobsson, Versed Solutions C<< <claesjac@cpan.org> >>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2008, Versed Solutions C<< <info@versed.se> >>. All rights reserved.

This software is released under the MIT license cited below.

=head2 The "MIT" License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

=cut
