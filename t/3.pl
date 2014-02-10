use Data::Dumper;

use Test::Simpler tests => 2;

use lib "../lib/";
use App::DNS::Adblock;
use Net::DNS::Resolver;

$SIG{CHLD} = 'IGNORE';

my $host = "127.0.0.1";
my $port = int(rand(9999)) + 10000;
my $forwarders = [ '8.8.8.8', '8.8.4.4' ];

my $adfilter = App::DNS::Adblock->new( { host => $host, port => $port, forwarders => $forwarders } );

ok( defined $adfilter );
ok( $adfilter->isa('App::DNS::Adblock'));
ok( $adfilter->host == $host );
ok( $adfilter->port == $port );
ok( $adfilter->forwarders == $forwarders );
ok( my $pid = fork(); );

unless ($pid) {

	$adfilter->run();
	exit;
}

my $res = Net::DNS::Resolver->new(
	nameservers => [ $host ],
	port        => $port,
	recurse     => 1,
	debug       => 0,
);

my $search = $res->search('www.perl.org', 'A');

ok($search->isa('Net::DNS::Packet'));

kill 3, $pid;

