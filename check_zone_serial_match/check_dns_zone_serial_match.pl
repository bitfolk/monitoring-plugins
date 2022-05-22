#!/usr/bin/env perl

# Copyright 2022 Andy Smith <andy@bitfolk.com>
# License: GPLv2.

use 5.010;
use warnings;
use strict;

use lib qw(/usr/local/bitfolk/cpanm/lib/perl5);

use Monitoring::Plugin;
use Net::DNS;
use List::Util qw(max min);

my $plugin = Monitoring::Plugin->new(
    usage   => 'Usage: %s -H <host> -z <zone>',
    version => '0.1',
    blurb   => 'Check consistency of zone serial number',
);

$plugin->add_arg(
    spec => 'host|H=s',
    help => 'nameserver to query',
);

$plugin->add_arg(
    spec => 'zone|z=s',
    help => 'zone name (e.g. example.com)',
);

$plugin->getopts;

if (not defined $plugin->opts->host) {
    $plugin->plugin_die(UNKNOWN, '--host/-H is required');
}

if (not defined $plugin->opts->zone) {
    $plugin->plugin_die(UNKNOWN, '--zone/-z is required');
}

my @ns = ns_for_zone($plugin->opts->zone, $plugin->opts->host);

if (scalar @ns == 0) {
    # No NS records for zone.
    $plugin->plugin_die(UNKNOWN,
        "Couldn't find any NS records for zone " . $plugin->opts->zone);
}

my %serials;
my @list;

foreach my $server (@ns) {
    $serials{$server} = get_serial($plugin->opts->zone, $server);
    push(@list, $serials{$server});
}

my $own_serial = get_serial($plugin->opts->zone, $plugin->opts->host);
push(@list, $own_serial);

if ((min @list) == (max @list)) {
    $plugin->plugin_exit(OK,
        "All serials for " . $plugin->opts->zone
        . " match mine ($own_serial)");
}

# There was a mismatch.
foreach my $server (keys %serials) {
    if ($serials{$server} != $own_serial) {
        print "MISMATCH: $server $serials{$server}\n";
    }
}

$plugin->plugin_exit(CRITICAL,
    "At least one server's serial for zone " . $plugin->opts->zone
        . " did not match mine ($own_serial)");

# Not reached.
exit 0;

sub ns_for_zone {
    my ($zone, $server) = @_;

    # Query their server for the NS list.
    my $res = Net::DNS::Resolver->new(
        nameservers => [ $server ],
        recurse     => 0,
    );

    # Allow 2 retries after 5 seconds each.
    $res->retrans(5);
    $res->retry(2);

    # UDP timeout after 15 seconds (Icinga otherwise allows 60s for plugin to
    # return answer).
    $res->udp_timeout(15);

    my @ns;

    my $packet = $res->query($zone, 'NS')
        or $plugin->plugin_die(UNKNOWN,
            "Problem querying $server for nameservers for zone $zone: "
            . $res->errorstring);

    foreach my $rr (grep { $_->type eq 'NS' } $packet->answer) {
        push(@ns, $rr->nsdname);
    }

    return @ns;
}

sub get_serial {
    my ($zone, $server) = @_;

    my $res    = Net::DNS::Resolver->new(
        nameservers => [ $server ],
        recurse     => 0,
    );

    # Allow 2 retries after 5 seconds each.
    $res->retrans(5);
    $res->retry(2);

    # UDP timeout after 15 seconds (Icinga otherwise allows 60s for plugin to
    # return answer).
    $res->udp_timeout(15);

    my $packet = $res->send($zone, 'SOA')
        or $plugin->plugin_die(UNKNOWN,
            "Problem querying $server for SOA of zone $zone: "
            . $res->errorstring);

    if (scalar $packet->answer == 0) {
        $plugin->plugin_die(UNKNOWN, "No SOA record for $zone from $server");
    }

    return ($packet->answer)[0]->serial;
}
