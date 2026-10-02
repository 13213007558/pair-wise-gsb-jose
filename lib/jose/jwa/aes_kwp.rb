module JOSE::JWA::AES_KWP

  extend self

  AIV = [0xA65959A6].pack('N')

  def unwrap(cipher_text, kek)
    bits = kek.bytesize * 8
    unless cipher_text.is_a?(String) and kek.is_a?(String) and
        (bits == 128 or bits == 192 or bits == 256) and
        cipher_text.bytesize >= 16 and cipher_text.bytesize % 8 == 0
      raise ArgumentError, "bad cipher_text or kek"
    end

    if cipher_text.bytesize == 16
      plain_text_block = aes_ecb_decrypt(bits, kek, cipher_text)
    else
      block_count = cipher_text.bytesize.div(8) - 1
      plain_text_block = JOSE::JWA::AES_KW.send(:do_unwrap, cipher_text, 5, block_count, kek, bits)
    end
    aiv = plain_text_block.byteslice(0, 4)
    key_length = plain_text_block.byteslice(4, 4).unpack('N').first
    key_data = plain_text_block.byteslice(8, plain_text_block.bytesize - 8)

    unless aiv == AIV and key_length > 0 and key_length <= key_data.bytesize
      raise ArgumentError, "bad cipher_text or kek"
    end

    pad_length = key_data.bytesize - key_length
    unless pad_length < 8
      raise ArgumentError, "bad cipher_text or kek"
    end

    unless key_data.byteslice(key_length, pad_length) == ("\0".b * pad_length)
      raise ArgumentError, "bad cipher_text or kek"
    end

    return key_data.byteslice(0, key_length)
  end

  def wrap(plain_text, kek)
    bits = kek.bytesize * 8
    unless plain_text.is_a?(String) and kek.is_a?(String) and
        plain_text.bytesize > 0 and (bits == 128 or bits == 192 or bits == 256)
      raise ArgumentError, "bad plain_text or kek"
    end

    pad_length = (8 - plain_text.bytesize) % 8
    padded_key = plain_text + ("\0".b * pad_length)
    iv = AIV + [plain_text.bytesize].pack('N')

    if iv.bytesize + padded_key.bytesize == 16
      return aes_ecb_encrypt(bits, kek, iv + padded_key)
    else
      return JOSE::JWA::AES_KW.wrap(padded_key, kek, iv)
    end
  end

private

  def aes_ecb_decrypt(bits, key, cipher_text)
    cipher = OpenSSL::Cipher::AES.new(bits, :ECB)
    cipher.decrypt
    cipher.key = key
    cipher.padding = 0
    return cipher.update(cipher_text) + cipher.final
  end

  def aes_ecb_encrypt(bits, key, plain_text)
    cipher = OpenSSL::Cipher::AES.new(bits, :ECB)
    cipher.encrypt
    cipher.key = key
    cipher.padding = 0
    return cipher.update(plain_text) + cipher.final
  end

end
