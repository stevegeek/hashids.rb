# frozen_string_literal: true

require "hashids"
require "fuzzbert"

fuzz "hashids" do
  deploy do |data|
    # Remove null bytes and whitespace as hashids wont accept them and doesnt currently validate alphabet contents
    alphabet = FuzzBert::Generators.random.call.gsub(/\s|\0/, "").chars.uniq
    salt = FuzzBert::Generators.random.call
    length = rand(-500..10_000)

    hashids = Hashids.new(salt, length, alphabet.join)

    # Test decode random fuzzed input
    hashids.decode(data)

    # Test encode/decode with integer inputs
    ids = FuzzBert::Generators.random.call
    input = ids.codepoints
    encoded = hashids.encode(*input)
    decoded = hashids.decode(encoded)

    raise StandardError, "Decoded does not match input" unless decoded == input
  rescue Hashids::InputError,
    Hashids::SaltError,
    Hashids::MinLengthError,
    Hashids::AlphabetError
    # fine, these are expected errors
  rescue => e
    puts "\n\nFailure\n--------------\n"
    puts "Random Input: #{Base64.strict_encode64(data)}"
    puts "Alphabet: #{Base64.strict_encode64(alphabet.join)}"
    puts "Salt: #{Base64.strict_encode64(salt)}"
    puts "Length: #{length}"
    puts "ids (codepoints): #{ids.codepoints}"
    puts "encoded: #{Base64.strict_encode64(encoded)}"
    puts "decoded: #{decoded}"

    raise e
  end

  data "completely random" do
    FuzzBert::Generators.random
  end
end
