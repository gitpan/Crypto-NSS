#!/usr/bin/perl

use strict;

use Test::More tests => 2;
use Test::Exception;

use Crypto::NSS config_dir => "db";

Crypto::NSS::SSL->set_cipher_suite("US");

my $socket = Net::NSS::SSL->new("127.0.0.1:4433", Connect => 0);
ok($socket);
isa_ok($socket, "Net::NSS::SSL");