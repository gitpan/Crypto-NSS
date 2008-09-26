package Net::NSS::SSL;

use strict;
use warnings;

use Carp qw(croak);
use Socket;

my %socket_type = ( 
    tcp  => SOCK_STREAM,
	udp  => SOCK_DGRAM,
	icmp => SOCK_RAW,
);

sub new {
    my $pkg = shift;
    my %args = @_ & 1 ? do { my $addr = shift; (@_, PeerAddr => $addr); } : @_;

    my $proto = "tcp";
    my $type = defined $args{Type} ? $args{Type} : SOCK_STREAM;

    # Convert (Peer|Local)Addr to ${1}Host + ${1}Port unless specified and convert named port
    for my $pre (qw(Peer Local)) {
        if (exists $args{"${pre}Addr"} && $args{"${pre}Addr"}) {
            ($args{"${pre}Port"}) = $args{"${pre}Addr"} =~ /:(\w+)$/ if !defined $args{"${pre}Port"};
            ($args{"${pre}Host"}) = $args{"${pre}Addr"} =~ /^(.*?):/;
        }
        
        # Non-numerical port, look up from /etc/services or equivalent
        if (exists $args{"${pre}Port"} && $args{"${pre}Port"} !~ /^\d+$/) {
            my @serv = getservbyname($args{"${pre}Port"}, "tcp");
            croak "Can't get port for protocol '", $args{"${pre}Port"}, "'" unless @serv;
            $args{"${pre}Port"} = $serv[2];
        }
    }
    
    # Blocking is a bit special. We should consult a callback for this unless it's specified
    if (!exists $args{Blocking} && $pkg->can("blocking")) {
        $args{Blocking} = $pkg->blocking;
    }
    $args{Blocking} = 1 unless exists $args{Blocking};
    
    my $sock = Net::NSS::SSL->create_socket("tcp");
    
    $sock->set_socket_option(Blocking => $args{Blocking});
    
    # Optional options
    for my $option (qw(KeepAlive ReuseAddr)) {
        next unless exists $args{$option};
        $sock->set_socket_option(KeepAlive => $args{KeepAlive});
    }
    
    # Upgrade to SSL socket
    $sock->import_into_ssl_layer();

    # Maybe connect
    $args{Timeout} ||= 180;
    if ($args{PeerHost} && $args{PeerPort} && !(exists $args{Connect} && !$args{Connect})) {
        $sock->set_domain($args{PeerHost});
        $sock->connect($args{PeerHost}, $args{PeerPort}, $args{Timeout});
    }

    return $sock;
}

sub DESTROY {
    my $self = shift;
    $self->close();
}

1;
__END__

=head1 NAME

Net::NSS::SSL - SSL sockets using NSS

=head1 SYNOPSIS

=head1 INTERFACE

=head2 CLASS METHODS

=over 4

=item new ( ADDR, %ARGS ) : Net::NSS::SSL
=item new ( %ARGS ) : Net::NSS::SSL

Creates a new socket, sets it up correctly, imports it into NSS SSL layer and optionally if it's a 
client-side socket connect to the remote host.

=item create_socket ( TYPE ) : Net::NSS::SSL

Creates a new socket of the I<TYPE> C<tcp> or C<udp>. Does not set any socket options nor imports it into 
the SSL layer. You probablly want to use C<new> instead of this method.

=back

=head2 INSTANCE METHODS

=over 4

=item connect ( HOST, PORT, [ TIMEOUT ] )

Conencts to the host I<HOST> on the given I<PORT>. The optional argument I<TIMEOUT> sets how many seconds 
connect has to complete the connection setup. If ommited C<PR_INTERVAL_NO_TIMEOUT> is used.

=item set_domain ( DOMAIN )

Sets the domain name of the host we connect to (or actually what the CN in the servers certificate says). This 
is used in handshaking and if not matching handshake will fail.

=item set_socket_option ( OPTION, VALUE )

=item get_socket_option ( OPTION )

Gets and sets socket options. The following options are valid:

=over 4

=item KeepAlive ( 1 | 0 )

Periodically test whether connection is still alive.

=item NoDelay ( 1 | 0 )

Disable Nagle algorithm. Don't delay send to coalesce packets.

=item Blocking ( 1 | 0 )

Do blocking or non-blocking (network) I/O.

=back

=item close ( )

Closes the socket.

=item import_into_ssl_layer ( )

Imports the socket into NSS SSL layer if not already done. The constructor C<new> does this automatically for 
you.

=item set_pkcs11_pin_arg ( ARG )

Sets the argument that is passed along to pkcs11 callbacks for the given socket. I<ARG> can be any Perl scalar.

=back

=cut
