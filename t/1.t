use Test;
BEGIN { plan tests => 1 }

eval { use lib "../lib/"; use App::DNS::Adblock; return 1; };
ok($@,'');
warn() if $@;
