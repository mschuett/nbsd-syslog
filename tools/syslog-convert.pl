#!/usr/bin/perl
# syslog-convert.pl
# 
# Convert Syslog lines from syslog-protocol to traditional BSD Syslog format
#
# 2008, Martin Schütte <info@mschuette.name>

use strict;
use warnings "all";

use DateTime::Format::DateParse;
use Date::Format;
my $date_outformat = "%b %e %T";

while (<STDIN>) {
  # assume leading priority and version are already stripped
  if (/^(.{10}T.{8}(?:\.\d{1,6})(?:Z|.{6})) ((?:\d+\.\d+\.\d+\.\d+)|\S+?)(?:\.\S+)* (\S+) (\d+) (\S+) (-|\[.+\]) ?(.+)?$/o) {
    my $rfc3339_time = $1;
    my $hostname = $2;
    my $appname = $3;
    my $pid = $4;
    my $msgid = $5;
    my $sd = $6;
    # if no message present then use SD as Msg:
    my $msg = $7 ? $7 : $sd;

    my $timestamp = DateTime::Format::DateParse->parse_datetime( $rfc3339_time );
    my $time_output = time2str($date_outformat, $timestamp);
    $appname = "$appname\[$pid\]" unless ($pid eq "-");

    print "$time_output $hostname $appname: $msg\n";
  }
  else {
    print STDERR "cannot parse line: $_\n"
  }
}

