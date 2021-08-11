require 'base64'
require 'openssl'

def generate_totp(time: Time.now.to_i, time_steps: 0, hasher: 'sha512', totp_length: 10, secret_key:)
  t = ((time - time_steps) / 30).to_s(16)

  while t.length < 16
    t = '0' << t
  end
  #puts "T = #{t}"
  msg = [t].pack("H*")

  digest = OpenSSL::Digest.new(hasher)
  hash = OpenSSL::HMAC.digest(digest, secret_key, msg)

  hash_array = hash.bytes

  offset = hash_array[hash_array.length - 1] & 0xf

  binary =
    ((hash_array[offset] & 0x7f) << 24) |
    ((hash_array[offset + 1] & 0xff) << 16) |
    ((hash_array[offset + 2] & 0xff) << 8) |
    (hash_array[offset + 3] & 0xff)

  res = (binary % 10**totp_length).to_s

  while res.length < totp_length
    res = '0' << res
  end

  puts "TOTP: #{res}"
  res
end

# Cases are taken from RFC6238
TEST_CASES = {
  59 => '90693936',
  1111111109 => '25091201',
  1111111111 => '99943326',
  1234567890 => '93441116',
  2000000000 => '38618901',
  20000000000 => '47863826'
}.freeze

totp_length = 8
key = '1234567890123456789012345678901234567890123456789012345678901234'

TEST_CASES.each do |test_time, expected|
  res = generate_totp(time: test_time, totp_length: totp_length, secret_key: key)
  raise "Incorrect: RES: #{res} -- Expected: #{expected}" unless res == expected
end
