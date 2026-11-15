from entropy import shannon_entropy


def test_empty_data_has_zero_entropy():
    assert shannon_entropy(b"") == 0.0


def test_constant_bytes_have_zero_entropy():
    assert shannon_entropy(b"\x00" * 1000) == 0.0


def test_two_equally_common_symbols_give_one_bit():
    assert abs(shannon_entropy(b"ab" * 500) - 1.0) < 1e-9


def test_all_byte_values_give_eight_bits():
    assert abs(shannon_entropy(bytes(range(256)) * 4) - 8.0) < 1e-9
