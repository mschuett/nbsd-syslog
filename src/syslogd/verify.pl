#! /usr/bin/perl
#
# verify logfile with syslog-sign messages
# reads logfile from STDIN
# does not yet verify signatures but only checks for missing messages

use strict;
use warnings "all";

use Digest::SHA1 qw( sha1 );
use MIME::Base64;
use Data::Dumper;

my (%SG, %msglist, %authmsglist, @CBlist, @SBlist);
my ($line, $hash, @a, @b);
my ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign, $gbc, $fmn, $cnt, $hb);

while (<>) {
        if (/^<\d+>1 \S+ (\S+) \S+ \S+ \S+ \[ssign-cert VER="(\d+)" RSID="(\d+)" SG="(\d+)" SPRI="(\d+)" TBPL="(\d+)" INDEX="(\d+)" FLEN="(\d+)" FRAG="([^"]+)" SIGN="(\S+)"\]/) {
                ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
                push @CBlist, [$1, $2, $3, $4, $5, $6, $7, $8, $9, $10];
                #print "--Found ssign-cert ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)\n";
        } elsif (/^<\d+>1 \S+ (\S+) \S+ \S+ \S+ \[ssign VER="(\d+)" RSID="(\d+)" SG="(\d+)" SPRI="(\d+)" GBC="(\d+)" FMN="(\d+)" CNT="(\d+)" HB="([^"]+)" SIGN="(\S+)"\]/) {
                ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
                push @SBlist, [$1, $2, $3, $4, $5, $6, $7, $8, $9, $10];
                #print "--Found ssign ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)\n";
        } else {
                chomp;
                $hash = encode_base64(sha1($_));
                chomp $hash;
                #print "--Found msg, hash '$hash', line '$_'\n";
                if (($msglist{$hash}) && ($msglist{$hash} cmp $_)) {
                        print "!!! Hash collision for lines:\n$msglist{$hash}\n$_\n";
                }
                $msglist{$hash} = $_;
        }
}

my (%SGfrags);

print "now process CBs\n";
@CBlist = sort {@{$a}[6] <=> @{$b}[6] } @CBlist;       #sort by index
for my $i ( 0 .. $#CBlist ) {
        #print Dumper(@{$CBlist[$i]});
        ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag) = @{$CBlist[$i]};
        #print "($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag)\n";

        if ($flen != length($frag)) {
                print "Warning: ignore CB with $flen != length($frag)\n";
                next;
        }
        if ($index == 1) {
                $SGfrags{($host, $ver, $rsid, $sg, $spri, $tbpl)} = $frag;
        } else {
                # CBs are sorted, so all $SGfrags created now
                if (defined($SGfrags{($host, $ver, $rsid, $sg, $spri, $tbpl)}) &&
                    $index == 1 + length $SGfrags{($host, $ver, $rsid, $sg, $spri, $tbpl)}) {
                        $SGfrags{($host, $ver, $rsid, $sg, $spri, $tbpl)} .=  $frag;
                } else {
                        print "Warning: ignore CB with wrong index\n";
                }
        }
}

print "now process SBs\n";
@SBlist = sort {@{$a}[6] <=> @{$b}[6] } @SBlist;  #sort by FMN
for my $i ( 0 .. $#SBlist ) {
        ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign) = @{$SBlist[$i]};
        #print "($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign)\n";
        print "TBD: check signature\n";
        my @hbs = split / /,$hb;
        my $hbslen = @hbs;
        if ($hbslen != $cnt) {
                print "found $hbslen != $cnt hashes in SB\n";
        }
        my $i = 0;
        while ($i < $hbslen) {
                my $idx = $fmn+$i;
                if (!(defined $msglist{$hbs[$i]})) {
                        print "*** did not receive msg #$idx with hash $hbs[$i]\n";
                } else {
                        #print "found msg #$idx with hash $hbs[$i]\n";
                        $authmsglist{$idx} = $msglist{$hbs[$i]};
                }
                $i++;
        }
}

print "Result:\n";
my $prevkey = 0;
foreach my $key (sort {$a <=> $b} keys %authmsglist) {
        if ($key != ($prevkey + 1)) {
                for my $missing ( ($prevkey + 1) .. ($key-1)) {
                        print "!$missing msg lost\n"
                }
        }
        print "$key\t$authmsglist{$key}\n";
        $prevkey = $key;
}


