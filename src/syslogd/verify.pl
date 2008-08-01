#! /usr/bin/perl
#
# verify logfile with syslog-sign messages
#
# tested with PKIX DSA key (type 'C') and DER encoded DSA key (type 'K')

use strict;
use warnings "all";

use Getopt::Long;
use Digest::SHA qw( sha1 sha256 );
use MIME::Base64;
#use Data::Dumper;
use Crypt::OpenSSL::X509;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::DSA;

my (%SG, %msglist_sha1, %msglist_sha256, %authmsglist, @CBlist, @SBlist);
my (%SGfrags, %seenhashlish);
my (@a, @b);
my ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign, $gbc, $fmn, $cnt, $hb, $text);

# subroutines
sub read_PKIX;
sub read_DER_DSA;
sub check_sig;
sub usage;

# command line arguments and global options
my $verbose;
my $quiet;
my $in;
my $out;
my $unsigned_out;
my $sha1;
my $sha256;
my $help;

my $result = GetOptions ("i|in=s"       => \$in,
                         "o|out=s"      => \$out,
                         "u|unsigned=s" => \$unsigned_out,
                         "v|verbose"    => \$verbose,
                         "q|quiet"      => \$quiet,
                         "sha1"         => \$sha1,
                         "sha256"       => \$sha256,
						 "h|help"       => \$help
					 );
if ($help || !$result
  || ($verbose && $quiet)) {
		usage();
		exit;
}
if (!$sha1 && !$sha256) {
		$sha1 = 1;   # default
}
if ($in) {
		open(STDIN, "< $in") || die "can't open $in: $!";
}
if ($out) {
		open(STDOUT, ">> $out") || die "can't open $out: $!";
}

print STDERR "reading input...\n" unless $quiet;
while (<>) {
        chomp;
        if (/^<\d+>1 \S+ (\S+) \S+ \S+ \S+ \[ssign-cert VER="(\d+)" RSID="(\d+)" SG="(\d+)" SPRI="(\d+)" TBPL="(\d+)" INDEX="(\d+)" FLEN="(\d+)" FRAG="([^"]+)" SIGN="(\S+)"\]/) {
                ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign, $text) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
                push @CBlist, [$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_];
                print STDERR "--Found ssign-cert ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)\n" if $verbose;
        } elsif (/^<\d+>1 \S+ (\S+) \S+ \S+ \S+ \[ssign VER="(\d+)" RSID="(\d+)" SG="(\d+)" SPRI="(\d+)" GBC="(\d+)" FMN="(\d+)" CNT="(\d+)" HB="([^"]+)" SIGN="(\S+)"\]/) {
                ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign, $text) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_);
                push @SBlist, [$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_];
                print STDERR "--Found ssign ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)\n" if $verbose;
        } else {
				my ($hash1, $hash2);
				if ($sha1) {
						$hash1 = encode_base64(sha1($_));
            			chomp $hash1;
            			if (($msglist_sha1{$hash1}) && ($msglist_sha1{$hash1} cmp $_)) {
            			        print STDERR "Warning: found SHA-1 hash collision '$hash1' for lines:\n$msglist_sha1{$hash1}\n$_\n" unless $quiet;
            			}
            			$msglist_sha1{$hash1} = $_;
				}
				if ($sha256) {
						$hash2 = encode_base64(sha256($_));
            			chomp $hash2;
            			if (($msglist_sha256{$hash2}) && ($msglist_sha256{$hash2} cmp $_)) {
            			        print STDERR "Warning: found SHA-256 hash collision '$hash2' for lines:\n$msglist_sha256{$hash2}\n$_\n" unless $quiet;
            			}
            			$msglist_sha256{$hash2} = $_;
				}
				print STDERR "--Found msg, hash '"
							  . ($sha1 ? $hash1 : "")
							  . ($sha1 && $sha256 ? "'/'" : "")
							  . ($sha256 ? $hash2 : "")
							  ."', line '$_'\n" if $verbose;
        }
}

print STDERR "processing CBs...\n" unless $quiet;
@CBlist = sort {@{$a}[6] <=> @{$b}[6] } @CBlist;       #sort by index
for my $i ( 0 .. $#CBlist ) {
        ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $text) = @{$CBlist[$i]};
		print "($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag)\n" if $verbose;

        if ($flen != length($frag)) {
                print STDERR "Warning: ignore CB with invalid lenght field ($flen != length($frag))\n" unless $quiet;
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
                        print STDERR "got key for SG ($key)\n" if $verbose;
                } else {
                        print STDERR "Warning: ignore CB with wrong index ($_)\n" unless $quiet;
                }
        }
}

print STDERR "decoding SGs...\n" unless $quiet;
foreach my $key (keys %SGfrags) {
        if ($SGfrags{$key}{frag} =~ /^(\S+) (\C) (\S+)/) {
			    my $pubkey_der;
                if ($2 eq "C") {  #PKIX
						read_PKIX($1, $3, $key);
				} elsif ($2 eq "K") {
						# without PKIX there is no real encoding rule.
						# I only try DER/DSA because my syslogd generates that
						read_DER_DSA($1, $3, $key);
                } else {
                        print STDERR "unsupported key type $2\n" unless $quiet;
                }
        } else {
                print STDERR "malformed payload: $SGfrags{$key}{frag}\n" unless $quiet;
        }
}

# syslog-sign requires a small leap of faith because one first has to reassemble
# the certificate blocks to get the public keys
# only after that one can check if the certificate blocks themselves were signed
# correctly.
print STDERR "verifying CBs...\n" unless $quiet;
for my $i ( 0 .. $#CBlist ) {
        ($host, $ver, $rsid, $sg, $spri, $tbpl, $index, $flen, $frag, $sign, $text) = @{$CBlist[$i]};
        my $key = "$host,$ver,$rsid,$sg,$spri";
        if (!(defined $SG{$key})) {
                print STDERR "do not verify incomplete CB for SG ($key)\n" unless $quiet;
        } else {
                my $rc = check_sig($text, $SG{$key}{key}, $SG{$key}{type});
				if ($rc != 1) {
					  print STDERR "invalid signature in CB. will not trust SG $key\n" unless $quiet;
					  delete $SG{$key};
				}
        }
}
foreach my $key (keys %SG) {
	print STDERR "verified CB and got key for SG: $key\n" unless $quiet;
}

print STDERR "now process SBs\n" unless $quiet;
@SBlist = sort {@{$a}[6] <=> @{$b}[6] } @SBlist;  #sort by FMN
for my $i ( 0 .. $#SBlist ) {
        ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign, $text) = @{$SBlist[$i]};
        print STDERR "SB values: ($host, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign, $text)\n" if $verbose;
        my $key = "$host,$ver,$rsid,$sg,$spri";
        if (!(defined $SG{$key})) {
                print STDERR "Warning: SB for unknown SG ($key)\n" unless $quiet;
				next;
        }

		my $rc = check_sig($text, $SG{$key}{key}, $SG{$key}{type});
		if ($rc != 1) {
			  print STDERR "Warning: invalid signature. ignoring this SB.\n" unless $quiet;
			  next;
		}

		my $msglist;
		if ($ver eq "0111")    { $msglist = \%msglist_sha1;   }
		elsif ($ver eq "0121") { $msglist = \%msglist_sha256; }
		else                   { print STDERR "Error: found SB with invalid version field: $ver\n" unless $quiet; }

        my @hbs = split / /,$hb;
        my $hbslen = @hbs;
        if ($hbslen != $cnt) {
                print STDERR "Warning: found wrong number of hashes in SB: $hbslen != $cnt\n" unless $quiet;
        }
        my $i = 0;
        while ($i < $hbslen) {
                my $idx = $fmn+$i;
                if (!(defined ${$msglist}{$hbs[$i]})) {
                        print STDERR "*** missing msg $key/#$idx with hash $hbs[$i]\n" if $verbose;
                } else {
                        print STDERR "found msg $key/#$idx with hash $hbs[$i]\n" if $verbose;
                        $authmsglist{$key}->{$idx} = ${$msglist}{$hbs[$i]};
                        $seenhashlish{$hbs[$i]} = 1;
                }
                $i++;
        }
}

print STDERR "signed messages:\n" unless $quiet;
my $prevkey = 0;
foreach my $sgkey (sort {$a cmp $b} keys %authmsglist) {
  foreach my $key (sort {$a <=> $b} keys %{$authmsglist{$sgkey}}) {
        if ($key != ($prevkey + 1)) {
                for my $missing ( ($prevkey + 1) .. ($key-1)) {
                        print STDOUT "$sgkey,$missing **** msg lost\n"
                }
        }
        print STDOUT "$sgkey,$key\t$authmsglist{$sgkey}->{$key}\n";
        $prevkey = $key;
  }
}

if ($unsigned_out) {
		open(STDOUT, ">> $unsigned_out") || die "can't open $unsigned_out: $!";
}
if (!($sha1 && $sha256)) {
		my $msglist;
		if    ($sha1)   { $msglist = \%msglist_sha1;   }
		elsif ($sha256) { $msglist = \%msglist_sha256; }

		print STDOUT "messages without signature:\n" unless $quiet;
		foreach my $key (keys %{$msglist}) {
				if (!(defined($seenhashlish{$key}))) {
		                print STDOUT "${$msglist}{$key}\n";
				}
		}
}

sub read_DER_DSA {
		my ($timestamp, $blob, $key) = @_;

		# WTF?
		# openssl/crypto/evp/encode.c:253
		# /* If the current line is > 80 characters, scream alot */

		my $b64oneline = $3;
		my $b64broken = "";
		while ($b64oneline =~ /^(\S{64})(.*)$/) {
			$b64broken .= $1."\n";
			$b64oneline = $2;
		}
		my $pubkey_der = "-----BEGIN PUBLIC KEY-----\n"
					  .$b64broken.$b64oneline."\n"
					  ."-----END PUBLIC KEY-----\n";
		my $dsakey = eval {
			Crypt::OpenSSL::DSA->read_pub_key_str($pubkey_der)
		};
		if ($@) {
				print STDERR "Unable to read DSA key: $@\n";
		} else {
				$SG{$key} = {
						type => "DSA",
						key  => $dsakey,
						time => $timestamp
				};
				print STDERR "got DER DSA key\n" unless $quiet;
		}
}

sub read_PKIX {
		my ($timestamp, $blob, $key) = @_;

		my $der = decode_base64($blob);
        my $cert = Crypt::OpenSSL::X509->new_from_string($der, Crypt::OpenSSL::X509::FORMAT_ASN1);
		my $pubkey_der = $cert->pubkey();
        
		# I cannot find a method to get the key type so I
		# trust $cert->pubkey() to generate head/foot lines :-/
		# tested for RSA and DSA keys
        if ($pubkey_der =~ /^-----BEGIN RSA PUBLIC KEY-----/) {
                $SG{$key} = {
                    type => "RSA",
                    key  => Crypt::OpenSSL::RSA->new_public_key($pubkey_der),
					time => $timestamp
                };
                print STDERR "Warning: got PKIX RSA key, but cannot use it to verify signatures\n" unless $quiet;
        } elsif ($pubkey_der =~ /^-----BEGIN PUBLIC KEY-----/) {
                $SG{$key} = {
                    type => "DSA",
                    key  => Crypt::OpenSSL::DSA->read_pub_key_str($pubkey_der),
					time => $timestamp
                };
				$SG{$key}{key}->write_pub_key("test.dsa");

                print STDERR "got PKIX DSA key\n" unless $quiet;
        } else {
				print STDERR "cannot read PKIX key blob: $3\n" unless $quiet;
				if ($pubkey_der =~ /---/) {
						print STDERR $pubkey_der."\n" unless $quiet;
				}
		}
}

# check signatures
# $text - line with ssign or ssign-cert SD element, including the SIGN param
# $key  - public key
# $type - key type
# currently only DSA keys and DSS signatures are supported
sub check_sig {
        my ($text, $key, $type) = @_;
        my $rc = -1;
        my $signtext = "";
        my $signature = "";

        if ($type eq 'DSA' && $text =~ m/^(.+) SIGN="(\S+)"(\].*)$/) {
				$signtext = sha1($1.$3);
                $signature = decode_base64($2);
                $rc = $key->verify($signtext, $signature);
        } else {
                print STDERR "check_sig() on invalid key type or wrong text: $text\n" if $verbose;
        }
		print STDERR "check_sig() returns $rc\n" if $verbose;
        return $rc;
}

sub usage {
#             0         1         2         3         4         5         6         7         8
#             012345678901234567890123456789012345678901234567890123456789012345678901234567890
		print "\nsyslog-sign verifier\nreads logfile and verifies message signatures\n\n";
		print "Notes:\n";
		print "- By default uses only SHA-1 hashes. Use option \"--sha256\" to use only\n";
		print "  SHA-256 and \"--sha1 --sha256\"to use both types.\n";
		print "- Some status messages are printed to stderr.\n";
		print "  Use option \"--quiet\" to disable them.\n";
		print "- All verified messages are printed with their identifying signature group.\n";
	    print "  Every line starts with a comma-separated tuple: hostname, version,\n";
		print "  reboot session ID, SG value, SPRI value, and message number.\n";
		print "- If only one hash is used then all messages not signed are printed as well.\n\n";
		print "Limitations: handles only key type 'C' (PKIX) with DSA key and DSA signatures\n\n";
		print "Command Line Options:\n";
		print "  -i  --in         input file (default: stdin)\n";
		print "  -o  --out        output file for verified messages (default: stdout)\n";
		print "  -u  --unsigned   output file for unsigned messages (default: stdout)\n";
		print "      --sha1       use SHA-1 hashes (default)\n";
		print "      --sha256     use SHA-256 hashes\n";
		print "  -v  --verbose    shows some internals (every CB,SB,hash,...)\n";
		print "  -q  --quiet      no status messages to stderr\n";
		print "  -h  --help       this help\n";
}
