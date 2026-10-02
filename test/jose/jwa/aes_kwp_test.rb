require 'test_helper'

class JOSE::JWA::AES_KWPTest < Minitest::Test

  KEK = ['5840df6e29b02af1ab493b705bf16ea1'].pack('H*').freeze

  def test_rfc_5649_vectors
    vectors = [
      [
        ['c37b7e64925843'].pack('H*'),
        ['aad20fa6beb84b0a59b3229531efc74e'].pack('H*')
      ],
      [
        ['c37b7e6492584340be93905dd108261cb9c29f9'].pack('H*'),
        ['05ba47f195f014973405ed105c8c1bf18c44acf65b497e109937f296e87dfcb4'].pack('H*')
      ]
    ]

    vectors.each do |plain_text, cipher_text|
      assert_equal cipher_text, JOSE::JWA::AES_KWP.wrap(plain_text, KEK)
      assert_equal plain_text, JOSE::JWA::AES_KWP.unwrap(cipher_text, KEK)
    end
  end

  def test_tampered_length_field_is_rejected
    plain_text = ['c37b7e6492584340be93905dd108261cb9c29f9'].pack('H*')
    key_data = plain_text + ("\0".b * 4)
    tampered_aiv = JOSE::JWA::AES_KWP::AIV_PREFIX + [25].pack('N')
    cipher_text = JOSE::JWA::AES_KW.wrap(key_data, KEK, tampered_aiv)

    assert_invalid_wrap(cipher_text)
  end

  def test_tampered_trailing_padding_is_rejected
    plain_text = ['c37b7e6492584340be93905dd108261cb9c29f9'].pack('H*')
    key_data = plain_text + ("\0".b * 4)
    key_data.setbyte(-1, 1)
    aiv = JOSE::JWA::AES_KWP::AIV_PREFIX + [plain_text.bytesize].pack('N')
    cipher_text = JOSE::JWA::AES_KW.wrap(key_data, KEK, aiv)

    assert_invalid_wrap(cipher_text)
  end

  def test_invalid_inputs_use_a_consistent_failure
    plain_text = ['c37b7e64925843'].pack('H*')
    cipher_text = JOSE::JWA::AES_KWP.wrap(plain_text, KEK)

    assert_invalid_wrap('')
    assert_invalid_wrap(nil)
    assert_invalid_wrap(cipher_text.byteslice(0, 15))
    assert_invalid_wrap(['11' * 17].pack('H*'))
    assert_invalid_wrap(cipher_text, ['11' * 16].pack('H*'))

    wrong_key = cipher_text.dup
    wrong_key.setbyte(0, wrong_key.getbyte(0) ^ 1)
    assert_invalid_wrap(wrong_key, KEK)
    assert_invalid_wrap(cipher_text, nil)
  end

  private

  def assert_invalid_wrap(cipher_text, kek = KEK)
    error = assert_raises(ArgumentError) do
      JOSE::JWA::AES_KWP.unwrap(cipher_text, kek)
    end
    assert_equal 'invalid wrapped key', error.message
  end

end
