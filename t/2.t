use Data::Dumper;

use Test;
BEGIN { plan tests => 1 };

use lib "../lib/";
use App::DNS::Adblock;
use Net::DNS::Resolver;

$SIG{CHLD} = 'IGNORE';

my $host = "127.0.0.1";
my $port = int(rand(9999)) + 10000;

my $adfilter = App::DNS::Adblock->new( { host => $host, port => $port } );

my $pid = fork();

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

