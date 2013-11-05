= puttykey

* http://github.com/larsch/puttykey (url)

== DESCRIPTION:

Parse, format PuTTY private keys (.ppk) format. Convert PuTTY keys to
SSL keys.

== FEATURES/PROBLEMS:

* Parse & decrypt PuTTY private keys (.ppk format)
* Format PuTTY private keys (encryption supported)
* Convert to/from OpenSSL::PKey::RSA

== SYNOPSIS:

  PuttyKey.load filename, passphrase # => PuttyKey

  PuttyKey.parse string, passphrase # => PuttyKey
  
  putty_key.to_ppk(passphrase) # => String

  putty_key.to_openssl # => OpenSSL::PKey::RSA

== Examples:

Convert OpenSSH key to PuTTY format:

  ssh_key = OpenSSL::PKey::RSA.new(IO.read(filename))
  putty_key = PuttyKey.new(key)
  ppk = putty_key.to_ppk(passphrase)

Save authorized_keys public key from PPK file:

  putty_key = PuttyKey.load(ppk_filename, passphrase)
  ssh_key = putty_key.to_openssl
  authorized_keys = "#{ssh_key.type} #{ssh_key.to_blob} comment"

Load Putty Key, requesting passphrase if required:

  require 'io/console'
  passphrase = nil
  begin
    PuttyPrivateKey.load(path, passphrase)
  rescue PuttyPrivateKey::DecryptError => e
    puts e.message
    IO.console.noecho do
      print "Passphrase: "
      passphrase = STDIN.gets.chomp
      puts
    end
    retry
  end
  
== REQUIREMENTS:

* None

== INSTALL:

* gem install puttykey

== DEVELOPERS:

After checking out the source, run:

  $ rake newb

This task will install any missing dependencies, run the tests/specs,
and generate the RDoc.

== LICENSE:

(The MIT License)

Copyright (c) 2013 Lars Christensen

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
