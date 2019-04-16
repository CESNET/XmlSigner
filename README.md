# XmlSigner #

XmlSigner is a federation metadata signer.

## How to try it ##

### Create PKCS12 file  ###

openssl req -x509 -newkey rsa:2048 -keyout private_key.pem -out certificate.pem -days 3650

openssl pkcs12 -export -out sample-signer.p12 -inkey private_key.pem -in certificate.pem -name sample-signer

### Get binary application ###

Checkout project, including binary application XmlSigner.jar:

git clone https://github.com/CESNET/XmlSigner.git

### Configure the application ###

1) Copy XmlSigner.jar to /opt/signer

2) Copy PKCS12 file to /etc/signer

3) Create file /etc/signer/signer.cfg with the following content:

    keystore = /etc/signer/sample-signer.p12
    
    keystoretype = pkcs12
    
    keystoreprovider = SunJSSE
    
    password = ***
    
    signingalias = sample-signer

### Run the application ###

java -jar /opt/signer/XmlSigner.jar -cfg /etc/signer/signer.cfg -i <input_metadata_to_sign.xml> -o <output_signed_metadata.xml>

## License ##

&copy; 2010-2018 [CESNET](https://www.cesnet.cz/?lang=en), all rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
