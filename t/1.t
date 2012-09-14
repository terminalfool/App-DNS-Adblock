use Test;
BEGIN { plan tests => 1 }

eval { use lib "../lib/"; use Net::DNS::Adblock; return 1; };
ok($@,'');
warn() if $@;
