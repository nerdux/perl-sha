package SHA256;

use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(calc_hash);

use strict;
#use warnings;
#use diagnostics;

use utf8;



my	@K256 = (
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);


sub _sum_mod32 {
	my $result = 0;
	
	foreach (@_) {
		my $lsw = ($_ & 0xffff) + ($result & 0xffff);
		my $msw = ($_ >> 16) + ($result >> 16) + ($lsw >> 16);
		
		$result = (($msw & 0xffff) << 16) | ($lsw & 0xffff);

	}
	
	return ($result);
}


sub _ch {
	my ($x, $y, $z) = @_;
	
	return (($x & $y) ^ (~$x & $z & 0xffffffff));
}


sub _maj {
	my ($x, $y, $z) = @_;
	
	return (($x & $y) ^ ($x & $z) ^ ($y & $z));
}


# Gets:
#    $b  number of bits to rotate (should be < 32)
#    $x  value to rotate (word32)
# Returns value rotated right by n bits
sub _rotr_32 {
	my ($b, $x) = @_;
	
	return (($x >> $b) | (($x & ((1 << $b) - 1)) << (32 - $b)));
}


sub _SIGMA0_32 {
	my $x = shift;
	
	return (_rotr_32(2, $x) ^ _rotr_32(13, $x) ^ _rotr_32(22, $x));
}


sub _SIGMA1_32 {
	my $x = shift;
	
	return (_rotr_32(6, $x) ^ _rotr_32(11, $x) ^ _rotr_32(25, $x));
}


sub _sigma0_32 {
	my $x = shift;
	
	return (_rotr_32(7, $x) ^ _rotr_32(18, $x) ^ ($x >> 3));
}


sub _sigma1_32 {
	my $x = shift;
	
	return (_rotr_32(17, $x) ^ _rotr_32(19, $x) ^ ($x >> 10));
}


# Word32 to Byte list
# Gets a Word32 integer (truncates to 32 bit if bigger)
# Returns a 4 Byte list
sub _w32_to_bl {
	my $j = shift;
	
	return (($j >> 24) & 0xff, ($j >> 16) & 0xff, ($j >> 8) & 0xff, $j & 0xff);
}


# Gets a word32 array
sub _sha256_transform {
	my ($self, @W256) = @_;
	
	my ($T1, $T2);
	my ($a, $b, $c, $d, $e, $f, $g, $h) = @{$self->{_state}};
	
	for (my $t = 0; $t < 64; $t++) {
		
		if ($t >= 16) {
			$W256[$t] = _sum_mod32(
				_sigma1_32($W256[$t - 2]),
				$W256[$t - 7],
				_sigma0_32($W256[$t - 15]),
				$W256[$t - 16]
			);
		}
		
		$T1 = _sum_mod32($h, _SIGMA1_32($e), _ch($e, $f, $g), $K256[$t], $W256[$t]);
		$T2 = _sum_mod32(_SIGMA0_32($a), _maj($a, $b, $c));

		$h = $g;
		$g = $f;
		$f = $e;
		$e = _sum_mod32($d, $T1);
		$d = $c;
		$c = $b;
		$b = $a;
		$a = _sum_mod32($T1, $T2);
	}
	
	$self->{_state}[0] = _sum_mod32($self->{_state}[0], $a);
	$self->{_state}[1] = _sum_mod32($self->{_state}[1], $b);
	$self->{_state}[2] = _sum_mod32($self->{_state}[2], $c);
	$self->{_state}[3] = _sum_mod32($self->{_state}[3], $d);
	$self->{_state}[4] = _sum_mod32($self->{_state}[4], $e);
	$self->{_state}[5] = _sum_mod32($self->{_state}[5], $f);
	$self->{_state}[6] = _sum_mod32($self->{_state}[6], $g);
	$self->{_state}[7] = _sum_mod32($self->{_state}[7], $h);
}


###################################################

# Gets:
#    Reference to Array of Bytes
# Returns:
#    Hash as an hexadecimal string
sub calc_hash {
	my $self = shift;
	my $data_ref = shift;
	
	return (undef) if not defined($data_ref);
	
	my $len = scalar @{ $data_ref };

	return (undef) if $len == 0;
	
	$self->{_state} = [
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	];
	

	$self->{_bitcount}[1] = $len >> 29;
	$self->{_bitcount}[0] = ($len & 0x1fffffff) << 3;

	# Process data in chunks of 64 bytes
	for (my $j = 0; $j < $len; $j += 64) {
		if (($len - $j) < 64) {
			@{$self->{_buffer}} = (@$data_ref[$j .. ($len - 1)], 0x80, (0) x (64 - ($len - $j) - 1));
			$len++;

			if (($len - $j) > 56) {
				$self->_sha256_transform(unpack("N*",pack("C*", @{$self->{_buffer}})));
				@{$self->{_buffer}} = (0) x 64;
			}
			
			@{$self->{_buffer}}[56 .. (64 - 1)] = (
				_w32_to_bl($self->{_bitcount}[1]),
				_w32_to_bl($self->{_bitcount}[0])
			);
		} else {
			@{$self->{_buffer}} = @$data_ref[$j .. ($j + 64 - 1)];
		}

		$self->_sha256_transform(unpack("N*", pack("C*", @{$self->{_buffer}})));
	}
		
	return ($self);
}


sub get_hash_hex {
	my $self = shift;
	
	return (undef) unless defined($self->{_state});
	
	my $hex = "";
	$hex .= sprintf("%08x",$_) foreach (@{$self->{_state}});
	
	return ($hex);
}


sub get_hash {
	my $self = shift;
	
	return (undef) unless defined($self->{_state});
	
	return (pack("N*", @{$self->{_state}}));
}


sub new {
	my $class = shift;
	my $datastring = shift;
	
	my $self = {
		_bitcount => [0, 0],
		_buffer => [(0) x 64],
		_state => undef
	};
	
	bless $self, $class;
	
	if (defined($datastring)) {
		$self->calc_hash([unpack("C*", $datastring)]);
	}
	
	return ($self);
}

1;
