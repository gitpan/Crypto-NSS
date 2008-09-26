#!/usr/bin/perl

use strict;

use Test::More tests => 8;
use File::Spec;

BEGIN { use_ok("Crypto::NSS"); }
is(Crypto::NSS->config_dir, ".");

my $config_dir = File::Spec->catdir(".", "db");

ok(Crypto::NSS->set_config_dir($config_dir));
is(Crypto::NSS->config_dir, $config_dir);

ok(!Crypto::NSS->is_initialized());
is(Crypto::NSS->initialize(), 0);
ok(Crypto::NSS->is_initialized());

ok(!Crypto::NSS->set_config_dir($config_dir));
