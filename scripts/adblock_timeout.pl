#!/usr/bin/env perl

use strict;
use warnings;

use App::DNS::Adblock;
use Try::Tiny;

my $timeout = 1;  # 1 day timeout
$timeout *= 86400;

my $adfilter =  App::DNS::Adblock->new({
					adblock_stack => [
							  { url => 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&startdate[day]=&startdate[month]=&startdate[year]=&mimetype=plaintext',
							    path => '/var/named/pgl-adblock.txt',
							    refresh => 7,
							    },
							  { url => "abp:subscribe?location=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasyprivacy.txt&title=EasyPrivacy&requiresLocation=https%3A%2F%2Feasylist-downloads.adblockplus.org%2Feasylist.txt&requiresTitle=EasyList",
							    path => '/var/named/easyprivacy.txt',
							    refresh => 5,
							    },
							  ],
					forwarders => [ "8.8.8.8", "8.8.4.4" ],
#					blacklist => '/var/named/blacklist',
#					whitelist => '/var/named/whitelist',
#					debug => 1,
					setdns => 1,
				       }
);

while (1) {
  try {
        local $SIG{ALRM} = sub { $adfilter->restore_local_dns if $adfilter->{setdns};
				 die "alarm\n"
				   };
        alarm $timeout;
        main();
        alarm 0;
      }

  catch {
        die $_ unless $_ eq "alarm\n";
        print "restarted\n";
      };
}

sub main {
  $adfilter->run();
}

=head1 NAME

adblock_timeout.pl - data refresh stub

=head1 SYNOPSIS

    sudo perl adblock_timeout.pl

=head1 DESCRIPTION

This script implements a DNS-based ad blocker. Execution is wrapped in a timeout function for the purpose of refreshing the adblock stack.

Edit the timeout, adblock_stack, blacklist and whitelist parameters to your liking.

=head1 CAVEATS

Tested on darwin only.

=head1 AUTHOR

David Watson <dwatson@cpan.org>

=head1 SEE ALSO

App::DNS::Adblock

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
