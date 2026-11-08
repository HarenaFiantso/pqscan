# Evaluation results

Written by `python3 bench/bench.py evaluate --write`. Do not edit by hand.

| Project | Labels | Found | False positives | Missed | Precision | Recall | File precision | File recall | Key sizes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| openssh | 94 | 22 | 0 | 72 | 100.0% | 23.4% | 100.0% | 90.0% | 0/0 |
| curl | 35 | 11 | 0 | 24 | 100.0% | 31.4% | 100.0% | 83.3% | 0/0 |
| nginx | 19 | 11 | 0 | 8 | 100.0% | 57.9% | 100.0% | 66.7% | 0/0 |
| mosquitto | 7 | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 3/3 |
| haproxy | 43 | 18 | 1 | 25 | 94.7% | 41.9% | 100.0% | 66.7% | 2/2 |
| postgres | 17 | 9 | 0 | 8 | 100.0% | 52.9% | 100.0% | 66.7% | 1/1 |
| **All** | 215 | 78 | 1 | 137 | 98.7% | 36.3% | 100.0% | 76.1% | 6/6 |

## What pqscan got wrong

- missed: `openssh/dh.c:243` DH
- missed: `openssh/dh.c:288` DH
- missed: `openssh/dh.c:300` DH
- missed: `openssh/dh.c:305` DH
- missed: `openssh/dh.c:322` DH
- missed: `openssh/dh.c:343` DH
- missed: `openssh/kexecdh.c:107` EC
- missed: `openssh/kexecdh.c:113` EC
- missed: `openssh/kexecdh.c:151` EC
- missed: `openssh/kexecdh.c:168` EC
- missed: `openssh/kexecdh.c:61` EC
- missed: `openssh/kexecdh.c:62` EC
- missed: `openssh/ssh-ecdsa.c:103` EC
- missed: `openssh/ssh-ecdsa.c:105` EC
- missed: `openssh/ssh-ecdsa.c:107` EC
- missed: `openssh/ssh-ecdsa.c:156` EC
- missed: `openssh/ssh-ecdsa.c:175` EC
- missed: `openssh/ssh-ecdsa.c:197` EC
- missed: `openssh/ssh-ecdsa.c:204` EC
- missed: `openssh/ssh-ecdsa.c:205` EC
- missed: `openssh/ssh-ecdsa.c:214` EC
- missed: `openssh/ssh-ecdsa.c:247` EC
- missed: `openssh/ssh-ecdsa.c:248` EC
- missed: `openssh/ssh-ecdsa.c:256` EC
- missed: `openssh/ssh-ecdsa.c:267` EC
- missed: `openssh/ssh-ecdsa.c:268` EC
- missed: `openssh/ssh-ecdsa.c:291` EC
- missed: `openssh/ssh-ecdsa.c:295` EC
- missed: `openssh/ssh-ecdsa.c:301` EC
- missed: `openssh/ssh-ecdsa.c:344` ECDSA
- missed: `openssh/ssh-ecdsa.c:348` ECDSA
- missed: `openssh/ssh-ecdsa.c:452` ECDSA
- missed: `openssh/ssh-ecdsa.c:456` ECDSA
- missed: `openssh/ssh-ecdsa.c:462` ECDSA
- missed: `openssh/ssh-ecdsa.c:472` ECDSA
- missed: `openssh/ssh-ecdsa.c:50` EC
- missed: `openssh/ssh-ecdsa.c:51` EC
- missed: `openssh/ssh-ecdsa.c:512` EC
- missed: `openssh/ssh-ecdsa.c:52` EC
- missed: `openssh/ssh-ecdsa.c:524` EC
- missed: `openssh/ssh-ecdsa.c:536` EC
- missed: `openssh/ssh-ecdsa.c:548` EC
- missed: `openssh/ssh-ecdsa.c:560` EC
- missed: `openssh/ssh-ecdsa.c:572` EC
- missed: `openssh/ssh-ecdsa.c:61` EC
- missed: `openssh/ssh-ecdsa.c:62` EC
- missed: `openssh/ssh-ecdsa.c:72` EC
- missed: `openssh/ssh-ecdsa.c:76` EC
- missed: `openssh/ssh-ecdsa.c:78` EC
- missed: `openssh/ssh-ecdsa.c:87` EC
- missed: `openssh/ssh-ecdsa.c:88` EC
- missed: `openssh/ssh-ecdsa.c:89` EC
- missed: `openssh/ssh-rsa.c:100` RSA
- missed: `openssh/ssh-rsa.c:101` RSA
- missed: `openssh/ssh-rsa.c:163` RSA
- missed: `openssh/ssh-rsa.c:167` RSA
- missed: `openssh/ssh-rsa.c:173` RSA
- missed: `openssh/ssh-rsa.c:179` RSA
- missed: `openssh/ssh-rsa.c:208` RSA
- missed: `openssh/ssh-rsa.c:213` RSA
- missed: `openssh/ssh-rsa.c:220` RSA
- missed: `openssh/ssh-rsa.c:243` RSA
- missed: `openssh/ssh-rsa.c:256` RSA
- missed: `openssh/ssh-rsa.c:270` RSA
- missed: `openssh/ssh-rsa.c:275` RSA
- missed: `openssh/ssh-rsa.c:280` RSA
- missed: `openssh/ssh-rsa.c:285` RSA
- missed: `openssh/ssh-rsa.c:289` RSA
- missed: `openssh/ssh-rsa.c:78` RSA
- missed: `openssh/ssh-rsa.c:81` RSA
- missed: `openssh/ssh-rsa.c:97` RSA
- missed: `openssh/ssh-rsa.c:99` RSA
- missed: `curl/lib/curl_ntlm_core.c:167` DES
- missed: `curl/lib/curl_ntlm_core.c:170` DES
- missed: `curl/lib/vtls/openssl.c:1571` RSA
- missed: `curl/lib/vtls/openssl.c:1572` RSA
- missed: `curl/lib/vtls/openssl.c:272` RSA
- missed: `curl/lib/vtls/openssl.c:277` RSA
- missed: `curl/lib/vtls/openssl.c:278` RSA
- missed: `curl/lib/vtls/openssl.c:280` RSA
- missed: `curl/lib/vtls/openssl.c:300` DSA
- missed: `curl/lib/vtls/openssl.c:307` DSA
- missed: `curl/lib/vtls/openssl.c:308` DSA
- missed: `curl/lib/vtls/openssl.c:309` DSA
- missed: `curl/lib/vtls/openssl.c:312` DSA
- missed: `curl/lib/vtls/openssl.c:313` DSA
- missed: `curl/lib/vtls/openssl.c:335` DH
- missed: `curl/lib/vtls/openssl.c:342` DH
- missed: `curl/lib/vtls/openssl.c:343` DH
- missed: `curl/lib/vtls/openssl.c:344` DH
- missed: `curl/lib/vtls/openssl.c:347` DH
- missed: `curl/lib/vtls/openssl.c:348` DH
- missed: `curl/lib/vtls/openssl.c:5337` MD5
- missed: `curl/lib/vtls/openssl.c:5337` SHA-1
- missed: `curl/lib/vtls/openssl.c:5380` MD5
- missed: `curl/lib/vtls/openssl.c:5380` SHA-1
- missed: `nginx/src/event/ngx_event_openssl.c:1608` DH
- missed: `nginx/src/event/ngx_event_openssl.c:1616` DH
- missed: `nginx/src/event/ngx_event_openssl.c:1788` ECDH
- missed: `nginx/src/event/ngx_event_openssl.c:1792` ECDH
- missed: `nginx/src/event/ngx_event_openssl.c:1832` ECDH
- missed: `nginx/src/event/ngx_event_openssl.c:1834` ECDH
- missed: `nginx/src/event/ngx_event_openssl.c:368` DH
- missed: `nginx/src/event/quic/ngx_event_quic_protection.c:105` AES-128
- spurious: `haproxy/reg-tests/jwt/cert.ecdsa.pem:1` EC
- missed: `haproxy/reg-tests/jwt/cert.ecdsa.pem:1` ECDSA
- missed: `haproxy/src/jws.c:151` RSA
- missed: `haproxy/src/jws.c:153` RSA
- missed: `haproxy/src/jws.c:158` RSA
- missed: `haproxy/src/jws.c:160` RSA
- missed: `haproxy/src/jws.c:162` RSA
- missed: `haproxy/src/jws.c:312` EC
- missed: `haproxy/src/jws.c:314` EC
- missed: `haproxy/src/jws.c:317` EC
- missed: `haproxy/src/jws.c:321` EC
- missed: `haproxy/src/jws.c:325` EC
- missed: `haproxy/src/jws.c:329` EC
- missed: `haproxy/src/jws.c:426` ECDSA
- missed: `haproxy/src/jws.c:429` ECDSA
- missed: `haproxy/src/jws.c:432` ECDSA
- missed: `haproxy/src/jws.c:62` EC
- missed: `haproxy/src/jws.c:64` EC
- missed: `haproxy/src/jws.c:85` EC
- missed: `haproxy/src/jws.c:87` EC
- missed: `haproxy/src/jws.c:89` EC
- missed: `haproxy/src/jws.c:97` EC
- missed: `haproxy/src/jws.c:99` EC
- missed: `haproxy/src/ssl_gencert.c:271` DH
- missed: `haproxy/src/ssl_gencert.c:296` ECDH
- missed: `haproxy/src/ssl_gencert.c:531` EC
- missed: `postgres/contrib/pgcrypto/openssl.c:633` AES-128
- missed: `postgres/src/backend/libpq/be-secure-openssl.c:1055` DH
- missed: `postgres/src/backend/libpq/be-secure-openssl.c:1068` DH
- missed: `postgres/src/backend/libpq/be-secure-openssl.c:1114` DH
- missed: `postgres/src/backend/libpq/be-secure-openssl.c:1391` DH
- missed: `postgres/src/backend/libpq/be-secure-openssl.c:1405` DH
- missed: `postgres/src/backend/libpq/be-secure-openssl.c:1617` MD5
- missed: `postgres/src/backend/libpq/be-secure-openssl.c:1618` SHA-1
