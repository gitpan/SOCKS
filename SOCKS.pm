package Net::SOCKS;

# Copyright (c) 1997 Clinton Wong. All rights reserved.
# This program is free software; you can redistribute it
# and/or modify it under the same terms as Perl itself. 

use strict;
use vars qw($VERSION @ISA @EXPORT);
use IO::Socket;
use Carp;

require Exporter;
require AutoLoader;

@ISA = qw(Exporter AutoLoader);
@EXPORT = qw(
	
);

$VERSION = '0.02';

# Status code exporter code adapted from HTTP::Status by Gisle Aas
my %status_code = (
  2  => "missing socks server net data",
  3  => "missing peer net data",
  4  => "socks server unavailable",
  5  => "timeout",
  6  => "unsupported protocol version",
  90 => "okay",
  91 => "failed",
  92 => "no_ident",
  93 => "user_mismatch"
);

my $mnemonic_code = '';
my ($code, $message);
while (($code, $message) = each %status_code) {
  # create mnemonic subroutines
  $message =~ tr/a-z \-/A-Z__/;
  $mnemonic_code .= "sub STATUS_$message () { $code }\t";
  # no need to make them exportable - yet
  # $mnemonic_code .= "push(\@EXPORT, 'STATUS_$message');\n";
}
eval $mnemonic_code; # only one eval for speed
die if $@;

sub status_message {
  return undef unless exists $status_code{ $_[0] };
  $status_code{ $_[0] };
}

1;
__END__

=head1 NAME

Net::SOCKS - a SOCKS client class

=head1 SYNOPSIS

Establishing a connection:

my $sock = new Net::SOCKS(socks_addr => '128.10.10.11',
                socks_port => 1080, user_id => 'clintdw',
                protocol_version => 4);

my $f= $sock->connect(peer_addr => '128.10.10.11', peer_port => 79);
print $f "clintdw\n";    # example writing to socket
while (<$f>) { print }   # example reading from socket
$sock->close();

Accepting an incoming connection:

$sock = new Net::SOCKS(socks_addr => '128.10.10.11',
                socks_port => 1080, user_id => 'clintdw',
                protocol_version => 4);

my ($ip, $ip_dot_dec, $port) = $sock->bind(peer_addr => "128.10.10.11",
                        peer_port => 9999);

$f= $sock->accept();
print $f "clintdw\n";    # example writing to socket
while (<$f>) { print }   # example reading from socket
$sock->close();


=head1 DESCRIPTION

$sock = new Net::SOCKS(socks_addr => '128.10.10.11',
                socks_port => 1080, user_id => 'clintdw',
                protocol_version => 4);

  To connect to a SOCKS server, specify the SOCKS server's
  hostname, port number, SOCKS protocol version, and optional
  username (for auth purposes).

my $f= $sock->connect(peer_addr => '128.10.10.11', peer_port => 79);

  To connect to another machine using SOCKS, use the connect method.
  Specify the host and port number as parameters.

my ($ip, $ip_dot_dec, $port) = $sock->bind(peer_addr => "128.10.10.11",
                        peer_port => 9999);

  If you wanted to accept a connection with SOCKS, specify the host
  and port of the machine you expect a connection from.  Upon
  success, bind() returns the ip address and port number that
  the SOCKS server is listening at on your behalf.

$f= $sock->accept();

  If a call to bind() returns a success status code STATUS_OKAY,
  a call to the accept() method will return when the peer host
  connects to the host/port that was returned by the bind() method.
  Upon success, accept() returns STATUS_OKAY.

$sock->close();

  Closes the connection.

=head1 AUTHOR

Clinton Wong, clintdw@netcom.com

Copyright (c) 1997 Clinton Wong. All rights reserved.
This program is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

perl(1).

=cut

# constructor new()

# We don't do any parameter error checking here because the programmer
# should be able to get an object back from new().  A croak
# isn't graceful and returning undef isn't descriptive enough.
# Error checking happens when connect() or bind() calls _validate().
# Error messages are retrieved through status_message() and status_num().

sub new {
  my $class = shift;

  my $self  = {};
  bless $self, $class;

  ${*self}{status_num} = STATUS_OKAY;
  $self->_import_args(@_);
  $self;
}

# connect() opens a socket through _request() and sends a command
# code of 1 to the SOCKS server.  It returns a reference to a socket
# upon success or undef upon failure.

sub connect {
  my $self = shift;
  if ( $self->_request(1, @_) == STATUS_OKAY ) { return ${*self}{fh} }
  return undef;
}

# bind() opens a socket through _request() and sends a command
# code of 2 to the SOCKS server.  Upon success, it returns
# an array of (32 bit IP address, IP address as dotted decimal,
# port number) where the SOCKS server is listening on the
# client's behalf.  Upon failure, return undef.

sub bind {
  my $self = shift;
  my $rc = $self->_request(2, @_);

  # if the listen address is zero, assume it is the same as the socks host
  if (defined ${*self}{listen_addr} && ${*self}{listen_addr} == 0) {
    ${*self}{listen_addr} = ${*self}{socks_addr};
  }

  my $dotted_dec = inet_ntoa( pack ("N", ${*self}{listen_addr} ) );
  if ($rc==STATUS_OKAY) {
    return (${*self}{listen_addr}, $dotted_dec, ${*self}{listen_port})
  }

  return undef;
}

# Upon success, return a reference to a socket.  Otherwise, return undef.

sub accept {
  my ($self) = @_;
  if ($self->_get_response() == STATUS_OKAY ) {  return ${*self}{fh} }
  return undef;
}

sub close {
  my ($self) = @_;
  close(${*self}{fh})
}

# Validate that destination host/port exists

sub _validate {
  my $self = shift;

  # check the method parameters
  unless (defined ${*self}{socks_addr} && length ${*self}{socks_addr}) {
    return ${*self}{status_num} = STATUS_MISSING_SOCKS_SERVER_NET_DATA;
  }
  unless (defined ${*self}{socks_port} && ${*self}{socks_port} > 0) {
    return ${*self}{status_num} = STATUS_MISSING_SOCKS_SERVER_NET_DATA;
  }
  unless (defined ${*self}{peer_addr} && length ${*self}{peer_addr}) {
    return ${*self}{status_num} = STATUS_MISSING_PEER_NET_DATA;
  }
  unless (defined ${*self}{peer_port} && ${*self}{peer_port} > 0) {
    return ${*self}{status_num} = STATUS_MISSING_PEER_NET_DATA;
  }
  unless (defined ${*self}{protocol_version} && ${*self}{protocol_version}==4){
    return ${*self}{status_num} = STATUS_UNSUPPORTED_PROTOCOL_VERSION;
  }

  if ( ! defined ${*self}{user_id} ) {  ${*self}{user_id}='' }

  return ${*self}{status_num} = STATUS_OKAY;
}

sub _request {

  my $self    = shift;
  my $req_num = shift;
  my $rc;

  $self->_import_args(@_);
  $rc=$self->_validate();

  if ($rc != STATUS_OKAY) { return ${*self}{status_num} = $rc }

  # connect to the SOCKS server
  $rc=$self->_connect();

  if ($rc==STATUS_OKAY) {

    # send the request
    print  { ${*self}{fh} } pack ('CCn', 4, $req_num, ${*self}{peer_port}) .
	inet_aton(${*self}{peer_addr}) . ${*self}{user_id} . (pack 'x');

    # get server response, returns server response code
    return $self->_get_response();
  }
  return ${*self}{status_num} = $rc;
}

# connect to socks server

sub _connect {
  my ($self) = @_;

  ${*self}{fh} = new IO::Socket::INET (
		   PeerAddr => ${*self}{socks_addr},
		   PeerPort => ${*self}{socks_port},
		   Proto  => 'tcp'
		  ) || return ${*self}{status_num} = STATUS_FAILED;

  my $old_fh = select(${*self}{fh});
  $|=1;
  select($old_fh);

  return ${*self}{status_num} = STATUS_OKAY;
}

# reads response from server, returns status_code, sets object values

sub _get_response {
  my ($self) = @_;
  my $received = '';

  while ( read(${*self}{fh}, $received, 8) && (length($received) < 8) ) {}

  ( ${*self}{vn},  ${*self}{cd}, ${*self}{listen_port},
    ${*self}{listen_addr} ) = unpack 'CCnN', $received;

  return ${*self}{status_num} = ${*self}{cd};
}

sub _import_args {
  my $self = shift;
  my (%arg, $key);

  # if a reference was passed, dereference it first
  if (ref($_[0]) eq 'HASH') { %arg = %{$_[0]} } else { %arg = @_ }

  foreach $key (keys %arg) { ${*self}{$key} = $arg{$key} }
}

# get/set an internal variable

# Currently known are:
# socks_addr, socks_port, listen_addr, listen_port,
# peer_addr, peer_port, fh, user_id, vn, cd, status_num.

sub param {
  my ($self, $key, $value) = @_;

  if (! defined $value) {
    # No value given.  We're doing a "get"

    if ( defined ${*self}{$key} ) { return ${*self}{$key} }
    else { return undef }
  }
  
  # Value given.  We're doing a "set"

  ${*self}{$key} = $value;
  return $value;
}

1;

