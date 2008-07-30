#! /usr/bin/perl
#
# verify logfile with syslog-sign messages
# reads logfile from STDIN
# does not yet enforce valid signatures but only checks
# and reports missing messages

use strict;
use warnings "all";

use Digest::SHA1 qw( sha1 );
use MIME::Base64;
use Data::Dumper;
use Crypt::OpenSSL::X509;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::DSA;

my (%SG, %msglist, %authmsglist, @CBlist, @SBlist);
my (%SGfrags, %seenhashlish);
my ($line, $hash, @a, @b);
my ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign, $gbc, $fmn, $cnt, $hb, $text);


sub check_sig {
        my ($text, $key, $type) = @_;
        my $rc = -1;
        my $signtext = "";
        my $signature = "";

        if ($text =~ m/^(.+) SIGN="(\S+)"(\].*)$/) {
                $signtext = $1.$3;
                $signature = decode_base64($2);
                if ($type eq 'RSA' || $type eq 'DSA') {
                        $rc = $key->verify($signtext, $signature);
#                        print "verify('$signtext', '$2') ---> $rc\n";
                }
        } else {
                print "check_sig() on invalid text: $text\n";
        }

        return $rc;
}

print "reading input...\n";
while (<>) {
        chomp;
        if (/^<\d+>1 \S+ (\S+) \S+ \S+ \S+ \[ssign-cert VER="(\d+)" RSID="(\d+)" SG="(\d+)" SPRI="(\d+)" TBPL="(\d+)" INDEX="(\d+)" FLEN="(\d+)" FRAG="([^"]+)" SIGN="(\S+)"\]/) {
                ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign, $text) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
                push @CBlist, [$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_];
                #print "--Found ssign-cert ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_)\n";
        } elsif (/^<\d+>1 \S+ (\S+) \S+ \S+ \S+ \[ssign VER="(\d+)" RSID="(\d+)" SG="(\d+)" SPRI="(\d+)" GBC="(\d+)" FMN="(\d+)" CNT="(\d+)" HB="([^"]+)" SIGN="(\S+)"\]/) {
                ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign, $text) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_);
                push @SBlist, [$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_];
                #print "--Found ssign ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_)\n";
        } else {
                $hash = encode_base64(sha1($_));
                chomp $hash;
                #print "--Found msg, hash '$hash', line '$_'\n";
                if (($msglist{$hash}) && ($msglist{$hash} cmp $_)) {
                        print "!!! Hash collision for lines:\n$msglist{$hash}\n$_\n";
                }
                $msglist{$hash} = $_;
        }
}

print "processing CBs...\n";
@CBlist = sort {@{$a}[6] <=> @{$b}[6] } @CBlist;       #sort by index
for my $i ( 0 .. $#CBlist ) {
        #print Dumper(@{$CBlist[$i]});
        ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $text) = @{$CBlist[$i]};
        #print "($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag)\n";

        if ($flen != length($frag)) {
                print "Warning: ignore CB with $flen != length($frag)\n";
                next;
        }
        my $key = "$host,$ver,$rsid,$sg,$spri";
        if ($index == 1) {
                $SGfrags{$key} = { tbpl => $tbpl, frag => $frag };
        } else {
                # CBs are sorted, so all $SGfrags created now
                if (defined($SGfrags{$key})
                 && $index == 1 + length $SGfrags{$key}{frag}
                 && $SGfrags{$key}{tbpl} == $tbpl) {
                        $SGfrags{$key}{frag} .=  $frag;
                        print "got key for SG ($key)\n";
                } else {
                        print "Warning: ignore CB with wrong index\n";
                }
        }
}

print "decoding SGs...\n";
foreach my $key (keys %SGfrags) {
        if ($SGfrags{$key}{frag} =~ /^(\S+) (\C) (\S+)/) {
                if ($2 eq "C") {  #PKIX
                        my $der = decode_base64($3);
                        my $cert = Crypt::OpenSSL::X509->new_from_string($der,
                            Crypt::OpenSSL::X509::FORMAT_ASN1);
                        my $pubkey_der = $cert->pubkey();
                        # I cannot find a method to get the key type :-/
                        if ($pubkey_der =~ /^-----BEGIN RSA PUBLIC KEY-----/) {
                                $SG{$key} = {
                                    type => "RSA",
                                    key  => Crypt::OpenSSL::RSA->new_public_key($pubkey_der)
                                };
                                print "got RSA key\n";
                        } elsif ($pubkey_der =~ /^-----BEGIN DSA PUBLIC KEY-----/) {
                                $SG{$key} = {
                                    type => "DSA",
                                    key  => Crypt::OpenSSL::DSA->read_pub_key_str($pubkey_der)
                                };
                                print "got DSA key\n";
                        }
                } else {
                        print "unsupported key type\n";
                }
        } else {
                print "malformed payload $SGfrags{$key}{frag}\n";
        }
}

print "verifying CBs...\n";
for my $i ( 0 .. $#CBlist ) {
        ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign, $text) = @{$CBlist[$i]};
        my $key = "$host,$ver,$rsid,$sg,$spri";
        if (!(defined $SG{$key})) {
                print "do not verify incomplete CB for SG ($key)\n";
        } else {
                my $rc = check_sig($text, $SG{$key}{key}, $SG{$key}{type});
                print "check_sig() returns '$rc'\n";
        }
}

print "now process SBs\n";
@SBlist = sort {@{$a}[6] <=> @{$b}[6] } @SBlist;  #sort by FMN
for my $i ( 0 .. $#SBlist ) {
        ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign, $text) = @{$SBlist[$i]};
        #print "\nSB values: ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign, $text)\n";
        my $key = "$host,$ver,$rsid,$sg,$spri";
        if (!(defined $SG{$key})) {
                print "SB for unknown SG ($host, $ver, $rsid, $sg, $spri)\n";
        } else {
                my $rc = check_sig($text, $SG{$key}{key}, $SG{$key}{type});
                print "check_sig() returns '$rc'\n";

                #next;
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
                                $seenhashlish{$hbs[$i]} = 1;
                        }
                        $i++;
                }
        }
}

print "signed messages:\n";
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

print "unsigned messages:\n";
foreach my $key (keys %msglist) {
        if (!(defined($seenhashlish{$key}))) {
                print "$msglist{$key}\n";
        }
}
