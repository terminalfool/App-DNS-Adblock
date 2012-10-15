package App::DNS::Adblock;

use strict;
use warnings;

use Net::DNS;
use Net::DNS::Nameserver;
use Sys::HostIP;
use Try::Tiny;
use IO::CaptureOutput qw( capture );
use LWP::Simple qw($ua getstore);
$ua->agent("");

use POSIX qw( strftime );
use Carp;

#use Data::Dumper;

sub new {
	my ( $class, $self ) = @_;
	bless $self, $class;

	my $host = Sys::HostIP->new;
	my %devices = reverse %{ $host->interfaces };
	my $hostip = $host->ip;

	$self->{interface} = $devices{ $hostip };
        $self->{host} = $hostip unless $self->{host};
        $self->{port} = 53 unless $self->{port};
	$self->{debug} = 0 unless $self->{debug};

	$self->read_config();

	my $ns = Net::DNS::Nameserver->new(
		LocalAddr    => $self->{host},
		LocalPort    => $self->{port},
		ReplyHandler => sub { $self->reply_handler(@_); },
		Verbose	     => ($self->{debug} > 1 ? 1 : 0)
	) || die "couldn't create nameserver object:  $!";

	$self->{nameserver} = $ns;

	my $res = Net::DNS::Resolver->new(
		nameservers => [ @{ $self->{forwarders} } ],
		port	    => $self->{forwarders_port} || 53,
		recurse     => 1,
		debug       => ($self->{debug} > 2 ? 1 : 0),
	);

	$self->{resolver} = $res;

	return $self;
}

sub run {
	my ( $self ) = shift;

        $self->set_local_dns();

	$SIG{KILL} = sub { $self->signal_handler(@_) };
	$SIG{QUIT} = sub { $self->signal_handler(@_) };
	$SIG{TERM} = sub { $self->signal_handler(@_) };
	$SIG{INT}  = sub { $self->signal_handler(@_) };
	$SIG{HUP}  = sub { $self->read_config() };

	$self->{nameserver}->main_loop;
};

sub set_local_dns {
	my ( $self ) = shift;

        if ($^O	=~ /darwin/i) {                                                          # is osx
                try {
		        capture sub { system("networksetup -listallhardwareports | grep -B 1 $self->{interface} | cut -c 16-32") } => \$self->{service}, \$self->{error};
		        $self->{service} =~ s/\n//g;
		        system("networksetup -setdnsservers $self->{service} $self->{host}");
		        system("networksetup -setsearchdomains $self->{service} empty");
                } catch {
	                $self->log("failed to switch local dns settings: $_");
                }
	}

	if (!grep { $^O eq $_ } qw(VMS MSWin32 os2 dos MacOS darwin NetWare beos vos)) { # is unix
	        try {
		        system("cp /etc/resolv.conf /etc/resolv.bk");
			open(CONF, ">", "/etc/resolv.conf");
			print CONF "nameserver $self->{host}\n";
			close CONF;
                } catch {
	                $self->log("failed to switch local dns settings: $_");
                }
        }

        if ($^O	=~ /MSWin32/i) {                                                         # is windows
	        try {
                        system("netsh interface ip add dns \"Local Area Connection\" $self->{host} index=1");
                } catch {
	                $self->log("failed to switch local dns settings: $_");
                }
        }

	$self->log("nameserver accessible locally @ $self->{host}; local dns settings ($self->{interface}) switched", 1);
}

sub signal_handler {
	my ( $self, $signal ) = @_;

        if ($^O	=~ /darwin/i) {                                                         # is osx
	        try {
                	system("networksetup -setdnsservers $self->{service} empty");
			system("networksetup -setsearchdomains $self->{service} empty");
                } catch {
	                $self->log("failed to restore local dns settings: $_");
                }
        }

	if (!grep { $^O eq $_ } qw(VMS MSWin32 os2 dos MacOS darwin NetWare beos vos)) { # is unix
	        try {
		        system("mv /etc/resolv.bk /etc/resolv.conf");
                } catch {
	                $self->log("failed to restore local dns settings: $_");
                }
        }

        if ($^O	=~ /MSWin32/i) {                                                         # is windows
	        try {
                        system("netsh interface ip delete dns \"Local Area Connection\" $self->{host} index=1");
                } catch {
	                $self->log("failed to restore local dns settings: $_");
                }
        }

	$self->log("shutting down: signal $signal; local dns settings restored");

	exit;
}

sub reply_handler {
	my ($self, $qname, $qclass, $qtype, $peerhost, $query,$conn) = @_;

	my ($rcode, @ans, @auth, @add);

 	if ($self->{adfilter} && ($qtype eq 'AAAA' || $qtype eq 'A' || $qtype eq 'PTR')) {
    
 		if (my $ip = $self->query_adfilter( $qname, $qtype )) {

                 	$self->log("received query from $peerhost: qtype '$qtype', qname '$qname'");
 			$self->log("[local] resolved $qname to $ip NOERROR");

 			my ($ttl, $rdata) = ( 300, $ip );
        
 			push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");

 			$rcode = "NOERROR";
      
 			return ($rcode, \@ans, \@auth, \@add, { aa => 1, ra => 1 });
 		}
 	}

	my $answer = $self->{resolver}->send($qname, $qtype, $qclass);

	if ($answer) {

       	        $rcode = $answer->header->rcode;
       	        @ans   = $answer->answer;
       	        @auth  = $answer->authority;
       	        @add   = $answer->additional;
    
	        $self->log("[proxy] response from remote resolver: $qname $rcode");

		return ($rcode, \@ans, \@auth, \@add);
	} else  {

		$self->log("[proxy] can not resolve $qtype $qname - no answer from remote resolver. Sending NXDOMAIN response.");

		$rcode = "NXDOMAIN";

		return ($rcode, \@ans, \@auth, \@add, { aa => 1, ra => 1 });
	}
}

sub log {
	my ( $self, $msg, $force_flag ) = @_;
	print "[" . strftime('%Y-%m-%d %H:%M:%S', localtime(time)) . "] " . $msg . "\n" if $self->{debug} || $force_flag;
}

sub read_config {
	my ( $self ) = shift;
        my $cache = ();

	$self->{forwarders} = ([ $self->parse_resolv_conf() ]);		              # /etc/resolv.conf

        if ($self->{adblock_stack}) {
        	for ( @{ $self->{adblock_stack} } ) {
 	                $cache = { $self->load_adblock_filter($_) };                  # adblock plus hosts
                        %{ $self->{adfilter} } = $self->{adfilter} ? ( %{ $self->{adfilter} }, %{ $cache } ) 
                                         : %{ $cache };
	        }
	}
        if ($self->{blacklist}) {
 	        $cache = { $self->parse_single_col_hosts($self->{blacklist}->{path}) }; # local, custom hosts
                %{ $self->{adfilter} } = $self->{adfilter} ? ( %{ $self->{adfilter} }, %{ $cache } ) 
                                         : %{ $cache };
 	}
        if ($self->{whitelist}) {
 	        $cache = { $self->parse_single_col_hosts($self->{whitelist}->{path}) }; # remove entries
                for ( keys %{ $cache } ) { delete ( $self->{adfilter}->{$_} ) };
 	}

#	$self->dump_adfilter;

 	return;
}

sub query_adfilter {
	my ( $self, $qname, $qtype ) = @_;

	return $self->search_ip_in_adfilter( $qname ) if  ($qtype eq 'A' || $qtype eq 'AAAA');
	return $self->search_hostname_by_ip( $qname ) if $qtype eq 'PTR';
}

sub search_ip_in_adfilter {
        my ( $self, $hostname ) = @_;

	my $trim = $hostname;
	my $sld = $hostname;
	$trim =~ s/^www\.//i;
	$sld =~ s/^.*\.(\w+\.\w+)$/$1/;

	return '::1' if ( exists $self->{adfilter}->{$hostname} ||
			  exists $self->{adfilter}->{$trim} ||
			  exists $self->{adfilter}->{$sld} );
        return;
}

sub search_hostname_by_ip {
	my ( $self, $ip ) = @_;

	$ip = $self->get_in_addr_arpa( $ip ) || return;
}

sub get_in_addr_arpa {
	my ( $self, $ptr ) = @_;

	my ($reverse_ip) = ($ptr =~ m!^([\d\.]+)\.in-addr\.arpa$!);
	return unless $reverse_ip;
	my @octets = reverse split(/\./, $reverse_ip);
	return join('.', @octets);
}

sub parse_resolv_conf {
	my ( $self ) = shift;

	return @{$self->{forwarders}} if $self->{forwarders};

	#need windows case
	$self->log('reading /etc/resolv.conf file');

	my @dns_servers;

	open (RESOLV, "/etc/resolv.conf") || croak "cant open /etc/resolv.conf file: $!";

	while (<RESOLV>) {
		if (/^nameserver\s+([\d\.]+)/) {
			push @dns_servers, $1;
		}
	}

	close (RESOLV);
	croak "no nameservers listed in /etc/resolv.conf!" unless @dns_servers;
	return @dns_servers;
}

sub load_adblock_filter {
	my ( $self ) = shift;
	my %cache;

	my $hostsfile = $_->{path} or die "adblock {path} is undefined";
	my $refresh = $_->{refresh} || 7;
	my $age = -M $hostsfile || $refresh;

	if ($age >= $refresh) {
        	my $url = $_->{url} or die "attempting to refresh $hostsfile failed as {url} is undefined";
	        $url =~ s/^\s*abp:subscribe\?location=//;
                $url =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
                $url =~ s/&.*$//;
	        $self->log("refreshing hosts: $hostsfile", 1);
	        getstore($url, $hostsfile);
	}

	%cache = $self->parse_adblock_hosts($hostsfile);

	return %cache;
}

sub parse_adblock_hosts {
	my ( $self, $hostsfile ) = @_;
	my %hosts;

	open(HOSTS, $hostsfile) or die "cant open $hostsfile file: $!";

	while (<HOSTS>) {
	        chomp;
		next unless s/^\|\|((\w+\.)+\w+)\^(\$third-party)?$/$1/;  #extract adblock host
		$hosts{$_}++;
	}

	close(HOSTS);

	return %hosts;
}

sub parse_single_col_hosts {
	my ( $self, $hostsfile ) = @_;
	my %hosts;

	open(HOSTS, $hostsfile) or die "cant open $hostsfile file: $!";

	while (<HOSTS>) {
	        chomp;
		next if /^\s*#/; # skip comments
		next if /^$/;    # skip empty lines
		s/\s*#.*$//;     # delete in-line comments and preceding whitespace
		$hosts{$_}++;
	}

	close(HOSTS);

	return %hosts;
}

sub dump_adfilter {
	my $self = shift;

	my $str = Dumper(\%{ $self->{adfilter} });
	open(OUT, ">/var/named/adfilter_dumpfile") or die "cant open dump file: $!";
	print OUT $str;
	close OUT;
}

1;

=head1 NAME

App::DNS::Adblock - A DNS based implementation of Adblock Plus

=head1 DESCRIPTION

This is a DNS server intended for use as an ad filter for a local area network. 
Its function is to load lists of ad domains and nullify DNS queries for those 
domains to the loopback address. Any other DNS queries are proxied upstream, 
either to a specified list of nameservers or to those listed in /etc/resolv.conf. 

The module loads externally maintained lists of ad hosts intended for use by 
Adblock Plus, a popular ad filtering extension for the Firefox browser. Use 
of the lists focuses only on third-party listings that define dedicated 
advertising and tracking hosts.

A locally maintained blacklist/whitelist can also be loaded. In this case, host 
listings must conform to a one host per line format.

Once running, local network dns queries can be addressed to the host's ip. This 
ip is echoed to stdout.

=head1 SYNOPSIS

    my $adfilter = App::DNS::Adblock->new( { } );

    $adfilter->run();

Without any arguments, the module will function simply as a proxy, forwarding all 
requests upstream to nameservers defined in /etc/resolv.conf.

=head1 ATTRIBUTES

=head2 adblock_stack

    my $adfilter = App::DNS::Adblock->new( {

        adblock_stack => [
            {
            url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&startdate[day]=&startdate[month]=&startdate[year]=&mimetype=plaintext',
	    path => '/var/named/pgl-adblock.txt',     #path to ad hosts
            refresh => 7,                             #refresh value in days (default = 7)
            },

            {
            url => 'abp:subscribe?location=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasyprivacy.txt&title=EasyPrivacy&requiresLocation=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasylist.txt&requiresTitle=EasyList';
            path => '/var/named/easyprivacy.txt',
            refresh => 5,
            },
        ],
    } );

The adblock_stack arrayref encloses one or more hashrefs composed of three 
parameters: a url that returns a list of ad hosts in adblock plus format; 
a path string that defines where the module will write a local copy of 
the list; a refresh value that determines what age (in days) the local copy 
may be before it is refreshed.

There are dozens of adblock plus filters scattered throughout the internet. 
You can load as many as you like, though one or two lists such as those listed 
above should suffice.

A collection of lists is available at http://adblockplus.org/en/subscriptions. 
The module will accept standard or abp:subscribe? urls. You can cut and paste 
encoded links directly.

=head2 blacklist

    my $adfilter = App::DNS::Adblock->new( {

        blacklist => {
            path => '/var/named/blacklist',  #path to secondary hosts
        },
    } );

The blacklist hashref contains only a path string that defines where the module will 
access a local list of ad hosts to nullify. As mentioned above, a single column is the 
only acceptable format:

    # ad nauseam
    googlesyndication.com
    facebook.com
    twitter.com
    ...
    adinfinitum.com

=head2 whitelist

    my $adfilter = App::DNS::Adblock->new( {

        whitelist => {
            path => '/var/named/whitelist',  #path to whitelist
        },
    } );

The whitelist hashref, like the blacklist hashref, contains only a path parameter 
to a single column list of hosts. These hosts will be removed from the filter.

=head2 host

The IP address to bind to. If not defined, the server attempts binding to the local ip.

=head2 port

The tcp & udp port to run the DNS server under. Defaults to 53.

=head2 nameservers

An arrayref of one or more nameservers to forward any DNS queries to. Defaults to nameservers 
listed in /etc/resolv.conf.

=head2 nameservers_port

The port of the remote nameservers. Defaults 53.

=head1 CAVEATS

The module attempts to set dns settings to the host's local ip. This may or may not work if 
there are multiple active interfaces. You may need to manually set your dns settings to your 
local ip.

=head1 AUTHOR

David Watson <dwatson@cpan.org>

=head1 SEE ALSO

scripts/adfilter.pl in the distribution

=head1 COPYRIGHT AND LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included with this module.

=cut

