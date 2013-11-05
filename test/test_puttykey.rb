require "puttykey"
require "openssl"

class TestPuttykey < Minitest::Test
  def reference
    @reference ||= OpenSSL::PKey.read(SSH_REFERENCE)
  end

  def assert_reference(key)
    assert key.kind_of?(PuttyKey)
    ssl = key.to_openssl
    assert_equal_ssl_rsa reference, ssl
  end

  def assert_equal_ssl_rsa(reference, ssl)
    assert_equal reference.public_key.e, ssl.public_key.e
    assert_equal reference.n, ssl.n
    assert_equal reference.p, ssl.p
    assert_equal reference.q, ssl.q
    assert_equal reference.d, ssl.d
    assert_equal reference.dmp1, ssl.dmp1
    assert_equal reference.dmq1, ssl.dmq1
    assert_equal reference.iqmp, ssl.iqmp
  end

  def test_parse
    assert_reference PuttyKey.parse(PPK_CLEAR)
  end

  def test_parse_decrypt
    assert_reference PuttyKey.parse(PPK_ENCRYPTED, PPK_PASSPHRASE)
  end

  def test_from_openssl
    assert_reference PuttyKey.new(reference)
  end

  def test_to_ppk_clear
    key = PuttyKey.new(reference)
    key.comment = "imported-openssh-key"
    assert_equal PPK_CLEAR, key.to_ppk
  end

  def test_encrypt_from_openssl
    key = PuttyKey.new(reference)
    ppk_encrypted = key.to_ppk(PPK_PASSPHRASE)
    parsed = PuttyKey.parse(ppk_encrypted, PPK_PASSPHRASE)
    assert_reference parsed
  end

  def test_generate
    openssl_key = OpenSSL::PKey::RSA.generate(128)
    ppk = PuttyKey.new(openssl_key)
    text = ppk.to_ppk(PPK_PASSPHRASE)
    ppk = PuttyKey.new(text, PPK_PASSPHRASE)
    assert_equal_ssl_rsa openssl_key, ppk.to_openssl
  end

end

SSH_REFERENCE = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxulYoU4TFxLO1Wg3hVlOtamFIQsbM3na9qM4GhSVgwgjuwpJ
B2Herz6Lx89yXsLKvQYE+e+Zm7yeM7l92pa6swbMcy7W2kQHIOZB03VrazMT23+v
2cVpPZdS7MqX0SXu8VNmACDVM0+E36UcuG5CjJp1m9rMVkudqn0vMTcqX3K13007
PrTd5pSNf1KbhYab5ZuaceL0v4jYi99KYXhjmmUjA2gG8pxW6uCQA1gMI7/TOYId
H5X8d/BkEHvWkiKvyDUZ28yWKjfurCDEeDOCeJdPTsZVT4QTM3+WK+L+qfdBXc57
2dZuSYEMdeaH7lROA+dZqqQy0L+2lE84ZXtO5QIDAQABAoIBAQCrQ8dYO80cFMmZ
3f3QBzFKIQfLh7CIBeeObMKlUgvZomyBYz216YK/CO95vxgOl1HQpxopyS9NdH4S
sye1ygo+kx/+HNpJXEF3BkqvM26mAniaibpzmxIeQejYkSdeoXa2usQcYCix4Una
9mNgOS97uJKC+0TtGHZMkTTM/16whqMtZ1iJ3tp4ONB80+sScNs3e8U1aU0BipwS
9e+/KUjprTPq4ZDaAhB2ZIJkoivNGAuNmHHeitxm80Wk+mB7HJHuZMsnEJSXfDVX
yZ1HUYXBXS/kCAl2lXAUvJ2QoR6J4NMIVVv8RR7YDOTFlfBVFPYFEW8VNrvppYZc
EHtd7eMRAoGBAOwMxWEAihr//MTPhYI8LYD2Yboojm2T/pQVPBe3AUvCYkIC/14x
oTKtWsaR61G1hTqHQ0q0LLvlkuCcioujrxGmRA+GgsGTSaaPYGqv5yl2+jDNlrUO
HT+I2nMOg+p+GqD7slqWCqGI+UpRtJqNYgcIcq4M15B4zv7OnlCkwg9vAoGBANe5
CnKi0Ct8eO5Hp1Ev0Mb8HXRqSrxdPx0BMvJB0ycS6CjFzizB1r7eds/hTGyxLIeT
gR2NhjOWoZ3WaH5tClw6MReitG11szD07GOBRrecnLt9LQYxi9EGgIrWYuATZww+
blpGfrcdkj5dWIkRAL6ZIz533SSQlroNMg9pSRzrAoGBAOlgmwkTuneFXkjLkAk6
LBcUAX1HOcIXDx0jfX1I30wizHjNc+OSF/j9sgEfJdRsLmO2dg524r+G89eEjeoP
lDhT9XiQGdj/IVM+8Cmq7lZtnmD/8p/ha4N0b95PnJcLxJIjJ6wuKiaZQTd8Xp5r
aF7huFhitAHPn4AHkjjTHFabAoGARgahJ5lGbfdX4jGMVMRqx00r2pBudjrms+mh
uhY4DuUKS8H6LXk21nqsosqF3nqc892j+g3o1HI/QFdLUE7hIBMbwIpme2nLo0a+
PYbHh+7kyc/Wf74xnsa3j1oMeqSRvN2/QLrFg3er82alyMimLzjSwgJy3N26r+Z8
q5gHzcUCgYADeyPRPNZkng+7wdqQpcgkDgshzfgH59KhPbgtWzFwMD4Q0s2L9YWY
AaT3Tipypb4FNm/QwFjUuNxwsGJZZVvrNVJTrzF1Fq/33hIqLI5mCEFvLwey3toc
8pZbbXJwXVliimEkItD1UI/7nbTVW0iuJUAirMDTHMbuuWj2mQMnKA==
-----END RSA PRIVATE KEY----- "

PPK_CLEAR = "PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: imported-openssh-key
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDG6VihThMXEs7VaDeFWU61qYUhCxszedr2
ozgaFJWDCCO7CkkHYd6vPovHz3Jewsq9BgT575mbvJ4zuX3alrqzBsxzLtbaRAcg
5kHTdWtrMxPbf6/ZxWk9l1LsypfRJe7xU2YAINUzT4TfpRy4bkKMmnWb2sxWS52q
fS8xNypfcrXfTTs+tN3mlI1/UpuFhpvlm5px4vS/iNiL30pheGOaZSMDaAbynFbq
4JADWAwjv9M5gh0flfx38GQQe9aSIq/INRnbzJYqN+6sIMR4M4J4l09OxlVPhBMz
f5Yr4v6p90FdznvZ1m5JgQx15ofuVE4D51mqpDLQv7aUTzhle07l
Private-Lines: 14
AAABAQCrQ8dYO80cFMmZ3f3QBzFKIQfLh7CIBeeObMKlUgvZomyBYz216YK/CO95
vxgOl1HQpxopyS9NdH4Ssye1ygo+kx/+HNpJXEF3BkqvM26mAniaibpzmxIeQejY
kSdeoXa2usQcYCix4Una9mNgOS97uJKC+0TtGHZMkTTM/16whqMtZ1iJ3tp4ONB8
0+sScNs3e8U1aU0BipwS9e+/KUjprTPq4ZDaAhB2ZIJkoivNGAuNmHHeitxm80Wk
+mB7HJHuZMsnEJSXfDVXyZ1HUYXBXS/kCAl2lXAUvJ2QoR6J4NMIVVv8RR7YDOTF
lfBVFPYFEW8VNrvppYZcEHtd7eMRAAAAgQDsDMVhAIoa//zEz4WCPC2A9mG6KI5t
k/6UFTwXtwFLwmJCAv9eMaEyrVrGketRtYU6h0NKtCy75ZLgnIqLo68RpkQPhoLB
k0mmj2Bqr+cpdvowzZa1Dh0/iNpzDoPqfhqg+7JalgqhiPlKUbSajWIHCHKuDNeQ
eM7+zp5QpMIPbwAAAIEA17kKcqLQK3x47kenUS/QxvwddGpKvF0/HQEy8kHTJxLo
KMXOLMHWvt52z+FMbLEsh5OBHY2GM5ahndZofm0KXDoxF6K0bXWzMPTsY4FGt5yc
u30tBjGL0QaAitZi4BNnDD5uWkZ+tx2SPl1YiREAvpkjPnfdJJCWug0yD2lJHOsA
AACAA3sj0TzWZJ4Pu8HakKXIJA4LIc34B+fSoT24LVsxcDA+ENLNi/WFmAGk904q
cqW+BTZv0MBY1LjccLBiWWVb6zVSU68xdRav994SKiyOZghBby8Hst7aHPKWW21y
cF1ZYophJCLQ9VCP+5201VtIriVAIqzA0xzG7rlo9pkDJyg=
Private-MAC: 0c33023ee5155968d30088bde5e89dd5af23b688
"

PPK_ENCRYPTED = "PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes256-cbc
Comment: imported-openssh-key
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDG6VihThMXEs7VaDeFWU61qYUhCxszedr2
ozgaFJWDCCO7CkkHYd6vPovHz3Jewsq9BgT575mbvJ4zuX3alrqzBsxzLtbaRAcg
5kHTdWtrMxPbf6/ZxWk9l1LsypfRJe7xU2YAINUzT4TfpRy4bkKMmnWb2sxWS52q
fS8xNypfcrXfTTs+tN3mlI1/UpuFhpvlm5px4vS/iNiL30pheGOaZSMDaAbynFbq
4JADWAwjv9M5gh0flfx38GQQe9aSIq/INRnbzJYqN+6sIMR4M4J4l09OxlVPhBMz
f5Yr4v6p90FdznvZ1m5JgQx15ofuVE4D51mqpDLQv7aUTzhle07l
Private-Lines: 14
D4ZSGsZwN5j1mpSIh464KYzyNGRQaL3ySP7WdKRFT9k4uUFt7F+3KGO8kxsRjqcf
qZMDe7E+aRlF/ylFDJkoiaQF54bcDaRaYaihBds/ZhW2N7ja19Mf0cDNp3eGMqaH
JCiAwWyWRl+5jYQOFSD17oEi++sWi5ni7IiEoXx4I6R42E06xgSCyRcdgt3wXQfr
myOCOwxvpRINxiG1v7qKSlfDVyuOGBduTVSXa5br5gSqPOeRp9b1Dyy0Q4asDvzF
n0PrkFEj9GSGCF9y803rVUtVcYIfVvjX3E07R/spIsO+JW7e0MVt+r66KTKL5LUU
7zsSuPLUrwrewI0I4OuWQNDgnNmQsk47rCg4mGzz/P14MaefAkZ5U3OWJDCg6O76
zBMzVyXre1s64mGjYZdfbfwGiaib0TTdAHwZSBBuYBzmQN9aJa+CfQ/zctmYWvsa
/JEu608sv7H4HngAo7tku6d5fAEuY4dS9gvZ2WARWAcp00sBIIRw9B3y019udEyB
AuAtnJ3TaxbYuZq6ZhV3Xtjp9uV49cYxgrfO/djrO9CFMk98lMX7VmiH4P/CHPbu
aGW5tIUJ2PB/L4mXjjwecqqGAteCKjFqvE6cdcEPZlVtgZhBejX4TXJlA4vQvDb5
11Q7mwr94TriVrV+Jy57Dje8CufrWktCbfXp3AhfZEqpeSszs5RrNrNniTsasoVV
9IaXt/rvy7H4iCZOKJU4w0uYzdF0zhrjdD4i4oqA26padvVbyPe43BZCa1F8wI8E
+GiEG35lTXAb6dat3VmrD7FyYrs430AQg1AFVKbXBJ00RGKBXYWfsnB4S10HdU3C
rxgZVVq6KPFH9ZwQemxWrg8EhxUJt3tWd07qpflsnbnaxGMy5VIIFoGp23LGjpFa
Private-MAC: 865dc67d9192307d80aa6847ac7aa53475562e2d
"

PPK_PASSPHRASE = "asdf"
