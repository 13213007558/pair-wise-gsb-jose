module JOSE::JWA::AES_KWP

  extend self
  extend JOSE::JWA::AES_KW_Primitive

  AIV_PREFIX = OpenSSL::BN.new(0xA65959A6).to_s(2)

  def unwrap(cipher_text, kek)
    if cipher_text.is_a?(String) and kek.is_a?(String)
      bits = kek.bytesize * 8
      if cipher_text.bytesize >= 16 and cipher_text.bytesize % 8 == 0 and valid_bits?(bits)
        block_count = cipher_text.bytesize.div(8) - 1
        if block_count == 1
          buffer = aes_ecb_decrypt(bits, kek, cipher_text)
        else
          buffer = do_unwrap(cipher_text, 5, block_count, kek, bits)
        end

        length_bytes = buffer.byteslice(4, 4)
        length = length_bytes.unpack1('N')
        payload_size = block_count * 8
        expected_aiv = [AIV_PREFIX, length_bytes].join
        valid = JOSE::JWA.constant_time_compare(buffer.byteslice(0, 8), expected_aiv)
        valid &= length > 0
        valid &= length <= payload_size
        valid &= length > payload_size - 8 unless block_count == 1
        if valid
          padding_size = payload_size - length
          plain_text = buffer.byteslice(8, length)
          padding = buffer.byteslice(8 + length, padding_size)
          valid &= padding_size.zero? || JOSE::JWA.constant_time_compare(padding, "\0".b * padding_size)
          return plain_text if valid
        end
      end
    end

    raise ArgumentError, "invalid wrapped key"
  end

  def wrap(plain_text, kek)
    if plain_text.is_a?(String) and kek.is_a?(String)
      bits = kek.bytesize * 8
      length = plain_text.bytesize
      if length > 0 and valid_bits?(bits)
        padding_size = (8 - (length % 8)) % 8
        aiv = [AIV_PREFIX, [length].pack('N')].join
        key_data = plain_text.b + ("\0".b * padding_size)
        buffer = [aiv, key_data].join
        if buffer.bytesize == 16
          return aes_ecb_encrypt(bits, kek, buffer)
        else
          block_count = buffer.bytesize.div(8) - 1
          return do_wrap(buffer, 0, block_count, kek, bits)
        end
      end
    end

    raise ArgumentError, "bad plain_text or kek"
  end

end
