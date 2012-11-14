use strict;
use warnings;
use diagnostics;

use sha256;

#
# hmac() was taken from the Digest::HMAC CPAN module
# Copyright 1998-2001 Gisle Aas.
# Copyright 1998 Graham Barr.
# This library is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

sub hmac
{
	my($data, $key, $hash_func, $block_size) = @_;
	$block_size ||= 64;
	$key = &$hash_func($key) if length($key) > $block_size;

	my $k_ipad = $key ^ (chr(0x36) x $block_size);
	my $k_opad = $key ^ (chr(0x5c) x $block_size);

	&$hash_func($k_opad, &$hash_func($k_ipad, $data));
}

#
# end of hmac()
#


# 
# sha256 interface
#

sub sha256_sha256 {
	use sha256;
	
	my $objeto = SHA256->new(join("", @_));
	
	return ($objeto->get_hash);
}


my @test_vectors = (
	{	kk => "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		dat => "4869205468657265",
		dig => "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"	},
	{	kk => "4a656665",
		dat => "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
		dig => "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"	},
	{	kk => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		dat => "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		dig => "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"	},
	{	kk => "0102030405060708090a0b0c0d0e0f10111213141516171819",
		dat => "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		dig => "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"	},
	{	kk => "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
		dat => "546573742057697468205472756e636174696f6e",
		dig => "a3b6167473100ee06e0c796c2955552b"	},
	{	kk => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		dat => "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
		dig => "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"	},
	{	kk => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		dat => "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
		dig => "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"	}
);



#my $teststring = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

#my $shavar = SHA256->new($teststring);

#my $sha2 = SHA256->new;


#print $shavar->get_hash_hex . "\n";
#print $sha2->calc_hash([unpack "C*", "abc"])->get_hash_hex . "\n";
#print SHA256->new->calc_hash([unpack "C*", $teststring])->get_hash_hex . "\n\n\n\n";

for (@test_vectors) {
	my $k = pack "H*", $_->{kk};
	my $m = pack "H*", $_->{dat};
	my $d = pack "H*", $_->{dig};
	
	my $hdig = hmac($m, $k, \&sha256_sha256);

	printf "%02x ", $_ for unpack "C*", $hdig;
	print "\n";
	printf "%02x ", $_ for unpack "C*", $d;
	print "\n\n";
}
