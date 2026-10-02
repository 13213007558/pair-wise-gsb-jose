require 'test_helper'

class JOSE::JWA::AES_KWPTest < Minitest::Test

  def test_rfc_5649_test_vectors
    kek = ['000102030405060708090a0b0c0d0e0f'].pack('H*')
    vectors = [
      [
        ['00010203040506'].pack('H*'),
        ['298772b606c2e4c89d823ac25e9fe1a2'].pack('H*')
      ],
      [
        ['000102030405060708090a0b0c0d0e0f10111213'].pack('H*'),
        ['2bdd65f7d5d1850b076568a76b931c26af41a4a9aee0412cf9ae52927b10f141'].pack('H*')
      ]
    ]

    vectors.each do |plain_text, cipher_text|
      assert_equal cipher_text, JOSE::JWA::AES_KWP.wrap(plain_text, kek)
      assert_equal plain_text, JOSE::JWA::AES_KWP.unwrap(cipher_text, kek)
    end
  end

  def test_round_trip_for_single_block_and_wrap_loop
    [128, 192, 256].each do |bits|
      kek = SecureRandom.random_bytes(bits / 8)
      [1, 7, 8, 9, 15, 16, 17, 20, 24, 25].each do |length|
        plain_text = SecureRandom.random_bytes(length)
        cipher_text = JOSE::JWA::AES_KWP.wrap(plain_text, kek)

        expected_length = length <= 8 ? 16 : (length + 8 + 7) & ~7
        assert_equal expected_length, cipher_text.bytesize
        assert_equal plain_text, JOSE::JWA::AES_KWP.unwrap(cipher_text, kek)
      end
    end
  end

  def test_unwrap_rejects_tampered_aiv_length_and_padding
    kek = SecureRandom.random_bytes(16)
    plain_text = SecureRandom.random_bytes(7)
    cipher_text = JOSE::JWA::AES_KWP.wrap(plain_text, kek)
    block = aes_ecb_decrypt(kek, cipher_text)

    aiv_tampered = block.dup
    aiv_tampered.setbyte(0, aiv_tampered.getbyte(0) ^ 0x01)

    length_tampered = block.dup
    length_tampered.setbyte(4, 0x00)
    length_tampered.setbyte(7, 0x10)

    padding_tampered = block.dup
    padding_tampered.setbyte(15, padding_tampered.getbyte(15) ^ 0x01)

    [aiv_tampered, length_tampered, padding_tampered].each do |tampered_block|
      assert_raises(ArgumentError) do
        JOSE::JWA::AES_KWP.unwrap(aes_ecb_encrypt(kek, tampered_block), kek)
      end
    end

    long_plain_text = SecureRandom.random_bytes(20)
    long_cipher_text = JOSE::JWA::AES_KWP.wrap(long_plain_text, kek)
    long_block = JOSE::JWA::AES_KW.send(:do_unwrap, long_cipher_text, 5, 3, kek, 128)
    long_length_tampered = long_block.dup
    long_length_tampered.setbyte(4, 0x00)
    long_length_tampered.setbyte(7, 0x04)
    long_padding_tampered = long_block.dup
    long_padding_tampered.setbyte(-1, long_padding_tampered.getbyte(-1) ^ 0x01)

    assert_raises(ArgumentError) do
      JOSE::JWA::AES_KWP.unwrap(JOSE::JWA::AES_KW.send(:do_wrap, long_length_tampered, 0, 3, kek, 128), kek)
    end
    assert_raises(ArgumentError) do
      JOSE::JWA::AES_KWP.unwrap(JOSE::JWA::AES_KW.send(:do_wrap, long_padding_tampered, 0, 3, kek, 128), kek)
    end
  end

  def test_invalid_inputs_use_argument_error
    kek = SecureRandom.random_bytes(16)
    plain_text = SecureRandom.random_bytes(7)
    cipher_text = JOSE::JWA::AES_KWP.wrap(plain_text, kek)

    assert_raises(ArgumentError) { JOSE::JWA::AES_KWP.wrap('', kek) }
    assert_raises(ArgumentError) { JOSE::JWA::AES_KWP.wrap(plain_text, SecureRandom.random_bytes(15)) }
    assert_raises(ArgumentError) { JOSE::JWA::AES_KWP.unwrap(cipher_text.byteslice(0, 15), kek) }
    assert_raises(ArgumentError) { JOSE::JWA::AES_KWP.unwrap(cipher_text, SecureRandom.random_bytes(15)) }
  end

  private

  def aes_ecb_decrypt(key, cipher_text)
    cipher = OpenSSL::Cipher::AES.new(128, :ECB)
    cipher.decrypt
    cipher.key = key
    cipher.padding = 0
    cipher.update(cipher_text) + cipher.final
  end

  def aes_ecb_encrypt(key, plain_text)
    cipher = OpenSSL::Cipher::AES.new(128, :ECB)
    cipher.encrypt
    cipher.key = key
    cipher.padding = 0
    cipher.update(plain_text) + cipher.final
  end

end
