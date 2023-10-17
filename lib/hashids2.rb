# frozen_string_literal: true

# encoding: utf-8

class Hashids2
  VERSION = "1.0.6"

  MIN_ALPHABET_LENGTH = 16
  SEP_DIV             = 3.5
  GUARD_DIV           = 12.0

  DEFAULT_SEPS        = "cfhistuCFHISTU".freeze

  DEFAULT_ALPHABET    = ("abcdefghijklmnopqrstuvwxyz" +
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                        "1234567890").freeze

  attr_reader :salt, :min_hash_length, :alphabet, :seps, :guards

  def initialize(salt = "", min_hash_length = 0, alphabet = DEFAULT_ALPHABET)
    @salt             = salt
    @min_hash_length  = min_hash_length
    @alphabet         = alphabet.freeze

    validate_attributes
    setup_alphabet
  end

  def encode(*numbers)
    numbers.flatten! if numbers.length == 1

    numbers.map! { |n| Integer(n) } # raises if conversion fails

    return '' if numbers.empty? || numbers.any? { |n| n < 0 }

    internal_encode(numbers)
  end

  def encode_hex(str)
    return "" unless hex_string?(str)

    numbers = str.scan(/[\w\W]{1,12}/).map do |num|
      "1#{num}".to_i(16)
    end

    encode(numbers)
  end

  def decode(hash)
    return [] if hash.nil? || hash.empty?

    internal_decode(hash, @alphabet)
  end

  def decode_hex(hash)
    ret = ""
    numbers = decode(hash)

    numbers.length.times do |i|
      ret += numbers[i].to_s(16)[1 .. -1]
    end

    ret.upcase
  end

  protected

  def internal_encode(numbers)
    alphabet = @alphabet.chars
    alphabet_length = alphabet.length
    length   = numbers.length

    hash_int = numbers.each_with_index.sum(0) do |n, i|
      n % (i + 100)
    end

    lottery = alphabet[hash_int % alphabet_length]
    ret = lottery.dup
    seasoning = (lottery + salt).chars

    numbers.each_with_index do |num, i|
      buf = seasoning + alphabet

      alphabet = consistent_shuffle(alphabet, buf[0, alphabet_length])
      last     = hash_one_number(num, alphabet, alphabet_length)

      ret << last

      if (i + 1) < length
        num %= (last.ord + i)
        ret << seps[num % seps.length]
      end
    end

    if ret.length < min_hash_length
      ret.prepend(guards[(hash_int + ret[0].ord) % guards.length])

      if ret.length < min_hash_length
        ret << guards[(hash_int + ret[2].ord) % guards.length]
      end
    end

    half_length = alphabet.length.div(2)

    while(ret.length < min_hash_length)
      alphabet = consistent_shuffle(alphabet, alphabet)
      ret.prepend(*alphabet[half_length .. -1])
      ret.concat(*alphabet[0, half_length])

      excess = ret.length - min_hash_length
      ret = ret[excess / 2, min_hash_length] if excess > 0
    end

    ret
  end

  def internal_decode(hash, alphabet)
    ret = []

    breakdown = hash.tr(@escaped_guards_selector, " ")
    array     = breakdown.split(" ")

    i = [3,2].include?(array.length) ? 1 : 0

    if breakdown = array[i]
      lottery   = breakdown[0]
      breakdown = breakdown[1 .. -1].tr(@escaped_seps_selector, " ")
      array     = breakdown.split(" ")

      array.length.times do |time|
        sub_hash = array[time]
        buffer   = lottery + salt + alphabet
        alphabet = consistent_shuffle(alphabet, buffer[0, alphabet.length])

        ret.push unhash(sub_hash, alphabet)
      end

      if encode(ret) != hash
        ret = []
      end
    end

    ret
  end

  # Keep alphabet and salt as arrays internally
  def consistent_shuffle(alphabet, salt)
    chars = alphabet.dup

    return chars if salt.nil? || salt.empty?

    salt_ords = salt.map(&:ord)
    salt_length = salt_ords.length
    idx = ord_total = 0

    (alphabet.length-1).downto(1) do |i|
      ord_total += n = salt_ords[idx]
      j = (n + idx + ord_total) % i

      chars[i], chars[j] = chars[j], chars[i]

      idx = (idx + 1) % salt_length
    end

    chars
  end

  def hash_one_number(num, alphabet, alphabet_length)
    res = +""

    begin
      res.prepend alphabet[num % alphabet_length]
      num = num / alphabet_length
    end while num > 0

    res
  end

  def unhash(input, alphabet)
    num = 0

    input.length.times do |i|
      pos = alphabet.index(input[i])

      raise InputError, "unable to unhash" unless pos

      num += pos * alphabet.length ** (input.length - i - 1)
    end

    num
  end

  private

  def setup_alphabet
    @alphabet = uniq_characters(alphabet)

    validate_alphabet

    setup_seps
    setup_guards

    @escaped_guards_selector = @guards.gsub(/([-\\^])/) { "\\#{$1}" }
    @escaped_seps_selector = @seps.gsub(/([-\\^])/) { "\\#{$1}" }
  end

  def setup_seps
    @seps = DEFAULT_SEPS.dup

    seps.length.times do |i|
      # Seps should only contain characters present in alphabet,
      # and alphabet should not contains seps
      if j = alphabet.index(seps[i])
        @alphabet = pick_characters(alphabet, j)
      else
        @seps = pick_characters(seps, i)
      end
    end

    alphabet.delete!(' ')
    seps.delete!(' ')

    @seps = consistent_shuffle(seps, salt)

    if seps.length == 0 || (alphabet.length / seps.length.to_f) > SEP_DIV
      seps_length = (alphabet.length / SEP_DIV).ceil
      seps_length = 2 if seps_length == 1

      if seps_length > seps.length
        diff = seps_length - seps.length;

        @seps    += alphabet[0, diff]
        @alphabet = alphabet[diff .. -1]
      else
        @seps = seps[0, seps_length]
      end
    end

    @alphabet = consistent_shuffle(alphabet, salt)
  end

  def setup_guards
    gc = (alphabet.length / GUARD_DIV).ceil

    if alphabet.length < 3
      @guards = seps[0, gc]
      @seps   = seps[gc .. -1]
    else
      @guards   = alphabet[0, gc]
      @alphabet = alphabet[gc .. -1]
    end
  end

  SaltError       = Class.new(ArgumentError)
  MinLengthError  = Class.new(ArgumentError)
  AlphabetError   = Class.new(ArgumentError)
  InputError      = Class.new(ArgumentError)

  def validate_attributes
    unless salt.kind_of?(String)
      raise SaltError, "The salt must be a String"
    end

    unless min_hash_length.kind_of?(Integer)
      raise MinLengthError, "The min length must be a Integer"
    end

    unless min_hash_length >= 0
      raise MinLengthError, "The min length must be 0 or more"
    end

    unless alphabet.kind_of?(String)
      raise AlphabetError, "The alphabet must be a String"
    end

    if alphabet.include?(' ')
      raise AlphabetError, "The alphabet can’t include spaces"
    end
  end

  def validate_alphabet
    unless alphabet.length >= MIN_ALPHABET_LENGTH
      raise AlphabetError, "Alphabet must contain at least " +
                           "#{MIN_ALPHABET_LENGTH} unique characters."
    end
  end

  def hex_string?(string)
    string.to_s.match(/\A[0-9a-fA-F]+\Z/)
  end

  def pick_characters(array, index)
    array[0, index] + " " + array[index + 1 .. -1]
  end

  def uniq_characters(string)
    string.split('').uniq.join('')
  end
end
