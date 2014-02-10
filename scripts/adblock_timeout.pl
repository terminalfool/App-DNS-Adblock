#!/usr/bin/env perl

use strict;
use warnings;

use App::DNS::Adblock;
use Try::Tiny;
use Hash::Util::FieldHash 'fieldhash';
fieldhash my %adfilter;

$adfilter =  App::DNS::Adblock->new({

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
});

try {
        local $SIG{ALRM} = sub { $adfilter->restore_local_dns if $adfilter->{setdns};
				 die "alarm\n"
				   };
        alarm 604800; # 7 day timeout
        main();
        alarm 0;
}

catch {
        die $_ unless $_ eq "alarm\n";
        print "timed out\n";
};

print "done\n";

sub main {
  $adfilter->run();
}

=head1 NAME

adblock_timeout.pl - Sample script using App::DNS::Adblock

=head1 SYNOPSIS

sudo nohup perl adblock_timeout.pl &

=head1 DESCRIPTION

This script implements a DNS-based ad blocker. Intended for use as a persistent process, execution is wrapped in a timeout function for the purpose of refreshing the adblock stack. 

=head1 CAVEATS

Tested on darwin only, using launchctl to handle persistence.

app.dns.adblock_timeout.plist:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
   <key>Label</key>
<string>app.dns.adblock_timeout</string>
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/adblock_timeout.pl</string>
</array>
        <key>KeepAlive</key>
        <true/>
        <key>RunAtLoad</key>
        <true/>
</dict>
</plist>

=head1 AUTHOR

David Watson <dwatson@cpan.org>

=head1 SEE ALSO

App::DNS::Adblock

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
