#!/usr/bin/env perl

use lib "../lib/";

use strict;
use warnings;

use App::DNS::Adblock;
use Getopt::Long;
use Pod::Usage;

my $host 	      = undef;         # defaults to (local ip)
my $port	      = undef;         # defaults to 53
my $debug 	      = 0;
my $verbose	      = 0;
my $help	      = 0;
my $background	      = 0;
my $nameserver	      = undef;
my $nameserver_port   = undef;
my $setdns            = undef;
my $loopback          = undef;

GetOptions(
    'debug|d'	               => \$debug,
    'verbose|v'	               => \$verbose,
    'help|?|h'	               => \$help,
    'host=s'	               => \$host,
    'port|p=s'	               => \$port,
    'background|bg'            => \$background,
    'nameserver|ns=s'          => \$nameserver,
    'setdns'    	       => \$setdns,
    'loopback=s'    	       => \$loopback,
);

pod2usage(1) if $help;

#system("killall named"); #any local nameservers should be halted

fork && exit if $background;

($nameserver, $nameserver_port) = split(':', $nameserver) if $nameserver && $nameserver =~ /\:/;

my $args = {};

$args->{debug}		  = ($verbose ? 1 : ($debug ? 3 : 0));
$args->{host}		  = $host if $host;
$args->{port}		  = $port if $port;
$args->{forwarders}	  = [ $nameserver ] if $nameserver;
$args->{forwarders_port}  = $nameserver_port if $nameserver_port;
$args->{setdns}	          = 1 if $setdns;
$args->{loopback}         = $loopback if $loopback;
$args->{adblock_stack}    = [
			       { url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&startdate[day]=&startdate[month]=&startdate[year]=&mimetype=plaintext',
			         path => '/var/named/pgl-adblock.txt',
			         refresh => 7,
			       },
			       { url => "abp:subscribe?location=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasyprivacy.txt&title=EasyPrivacy&requiresLocation=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasylist.txt&requiresTitle=EasyList",
			         path => '/var/named/easyprivacy.txt',
			         refresh => 5,
			       },
			    ];
#$args->{blacklist}	  = '/var/named/blacklist';

#$args->{whitelist}	  = '/var/named/whitelist';

App::DNS::Adblock->new( $args )->run();

=head1 NAME

adblock.pl - command line stub

=head1 SYNOPSIS

adblock.pl [options]

 Options:
   -h   -help                   display this help
   -v   -verbose                show server activity
   -d   -debug                  enable debug mode
        -host                   host (defaults to local ip)
   -p   -port                   port (defaults to 53)
   -bg  -background             run the process in the background
   -ns  -nameserver             forward queries to this nameserver (<ip>:<port>)
        -setdns                 adjust dns settings on local host
        -loopback               set specific loopback address (defaults to 127.0.0.1)

=head1 DESCRIPTION

This script implements a DNS-based ad blocker.

=head1 CAVEATS

Though the module permits the use of as many lists as you like, it should be sufficient to use one or two lists, accept the defaults and run it in the background:

     sudo perl adblock.pl -bg -setdns
     # you must manually kill this process

Edit the adblock_stack, blacklist and whitelist args to your liking.

=head1 AUTHOR

David Watson <dwatson@cpan.org>

=head1 SEE ALSO

App::DNS::Adblock

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
