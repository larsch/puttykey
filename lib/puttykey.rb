# -*- coding: utf-8 -*-
require 'openssl'

class PuttyKey

  VERSION = "0.1.0"

  # Exception raises if decryption fails due to missing or invalid
  # passphrase.
  class DecryptError < RuntimeError
  end

  # Load a PuTTY private key from a file, with an optional
  # passphrase. Raises DecryptError if passphrase is missing or
  # incorrect.
  def self.load(filename, passphrase = nil)
    self.new(IO.read(filename), passphrase)
  end

  # Parse a PuTTY private key from a string, with an optional
  # passphrase. Raises DecryptError if passphrase is missing or
  # incorrect.
  def self.parse(string, passphrase = nil)
    self.new(string, passphrase)
  end

  # The SSH key comment. Can be set before calling to_ppk. Not
  # preserved when converting to OpenSSL key.
  attr_accessor :comment

  # The key type (ssh-rsa).
  attr_reader :name

  # Initialize the PuTTY key from either a ppk formatted string, or a
  # OpenSSL::PKey::RSA instance.
  def initialize(key = nil, passphrase = nil)
    @encryption = "none"
    case key
    when OpenSSL::PKey::RSA
      raise ArgumentError, "Expected only 1 argument" if passphrase
      @name = "ssh-rsa"
      @comment = "OpenSSL RSA Key"
      @exponent = key.public_key.e.to_s(2)
      @modulus = "\x00" + key.public_key.n.to_s(2)
      @private_exponent = "\x00" + key.d.to_s(2)
      @pk_q = "\x00" + key.q.to_s(2)
      @pk_p = "\x00" + key.p.to_s(2)
      @iqmp = key.iqmp.to_s(2)
    when String
      parse(key, passphrase)
    when NilClass
    else
      raise ArgumentError, "Unexpected argument type #{from.class.name}"
    end
  end

  # Convert the private key to PPK format, optionally protected by a
  # passphrase.
  def to_ppk(passphrase = nil)
    if passphrase
      encrypt passphrase
      priv_blob = @private_blob_encrypted
    else
      passphrase = ""
      @encryption = "none"
      priv_blob = private_blob
    end

    public_key_lines = [public_blob].pack("m0").gsub(/(.{1,64})/, "\\1\n")
    private_key_lines = [priv_blob].pack("m0").gsub(/(.{1,64})/, "\\1\n")

    mac = private_mac(passphrase)
    mac_hex = mac.unpack("H*").first

    "PuTTY-User-Key-File-2: #{@name}\n" +
      "Encryption: #{@encryption}\n" +
      "Comment: #{@comment}\n" +
      "Public-Lines: #{public_key_lines.lines.count}\n" +
      public_key_lines +
      "Private-Lines: #{private_key_lines.lines.count}\n" +
      private_key_lines +
      "Private-MAC: #{mac_hex}\n"
  end

  # Convert the key to an OpenSSL::PKey::RSA
  def to_openssl
    key = OpenSSL::PKey::RSA.new
    key.e = OpenSSL::BN.new(@exponent, 2)
    key.n = OpenSSL::BN.new(@modulus, 2)
    key.q = OpenSSL::BN.new(@pk_q, 2)
    key.p = OpenSSL::BN.new(@pk_p, 2)
    key.iqmp = OpenSSL::BN.new(@iqmp, 2)
    key.d = OpenSSL::BN.new(@private_exponent, 2)
    key.dmp1 = key.d % (key.p - 1)
    key.dmq1 = key.d % (key.q - 1)
    return key
  end

  private

  def encrypted?
    @encryption != "none"
  end

  def decrypt(passphrase)
    case @encryption
    when "aes256-cbc"
      raise DecryptError, "Passphrase required" if passphrase.nil?
      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.decrypt
      cipher.padding = 0
      key = Digest::SHA1.digest("\0\0\0\0" + passphrase) + Digest::SHA1.digest("\0\0\0\1" + passphrase)
      cipher.key = key[0, 32]
      cipher.iv = "\0" * cipher.iv_len
      @private_blob = cipher.update(@private_blob_encrypted) + cipher.final
      mac = private_mac(passphrase)
      raise DecryptError, "Failed to decrypt" unless mac == @private_mac
      unpack_private_blob
    when "none"
      @private_blob = @private_blob_encrypted
    end
  end

  def private_blob
    @private_blob ||= [ @private_exponent.length, @private_exponent, @pk_p.length, @pk_p, @pk_q.length, @pk_q, @iqmp.length, @iqmp ].pack("Na*Na*Na*Na*")
  end

  def public_blob
    @public_blob ||= [ @name.length, @name, @exponent.length, @exponent, @modulus.length, @modulus ].pack("Na*Na*Na*")
  end

  def mac_blob
    @mac_blob ||= [ @name.length, @name,
      @encryption.length, @encryption,
      @comment.length, @comment,
      @public_blob.length, @public_blob,
      @private_blob.length, @private_blob ].pack("Na*Na*Na*Na*Na*")
  end

  def encrypt(passphrase)
    @encryption = "aes256-cbc"

    cipher_key = Digest::SHA1.digest("\0\0\0\0" + passphrase) + Digest::SHA1.digest("\0\0\0\1" + passphrase)
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.padding = 0
    cipher.key = cipher_key[0, cipher.key_len]
    cipher.iv = "\0" * cipher.iv_len

    blob = private_blob
    block_size = cipher.block_size
    final_size = ((blob.size + block_size - 1) / block_size) * block_size
    missing = final_size - blob.size
    blob << Digest::SHA1.digest(blob)[0, missing]

    @private_blob_encrypted = cipher.update(blob) + cipher.final

    self
  end

  def load(filename)
    parse(IO.read(filename))
  end

  def parse(string, passphrase = nil)
    # Ensure we only have unix line breaks
    string.encode!(universal_newline: true)
    lns = string.lines.to_a
    until lns.empty?
      if lns.shift =~ /(\S+): (.*)/
        key, value = $1, $2
        case key
        when "PuTTY-User-Key-File-2"
          @name = value
        when "Encryption"
          @encryption = value
        when "Comment"
          @comment = value
        when "Public-Lines"
          @public_blob = lns.shift(value.to_i).join.unpack("m").first
        when "Private-Lines"
          @private_blob_encrypted = lns.shift(value.to_i).join.unpack("m").first
          @private_blob = @private_blob_encrypted unless encrypted?
        when "Private-MAC"
          @private_mac = [value].pack("H*")
        end
      end
    end
    unpack_public_blob
    decrypt passphrase if encrypted?
    unpack_private_blob
    self
  end

  def private_mac(passphrase)
    mac_key = Digest::SHA1.digest("putty-private-key-file-mac-key" + passphrase)
    hmac_sha1_simple(mac_key, mac_blob)
  end

  def unpack_public_blob
    s = @public_blob
    name_length, s = s.unpack("Na*")
    @name, exponent_length, s = s.unpack("a#{name_length}Na*")
    @exponent, modulus_length, s = s.unpack("a#{exponent_length}Na*")
    @modulus, s = s.unpack("a#{modulus_length}")
  end

  def unpack_private_blob
    s = @private_blob
    private_exponent_length, s = s.unpack("Na*")
    @private_exponent, pk_p_length, s = s.unpack("a#{private_exponent_length}Na*")
    @pk_p, pk_q_length, s = s.unpack("a#{pk_p_length}Na*")
    @pk_q, iqmp_length, s = s.unpack("a#{pk_q_length}Na*")
    @iqmp, _ = s.unpack("a#{iqmp_length}a*")
  end

  def hmac_sha1_simple(key, data)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new("SHA1"), key, data)
  end

end
