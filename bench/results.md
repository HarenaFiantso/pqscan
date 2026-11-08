# Evaluation results

Written by `python3 bench/bench.py evaluate --write`. Do not edit by hand.

## Tuned on

| Project | Labels | Found | False positives | Missed | Precision | Recall | File precision | File recall | Key sizes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| curl | 35 | 29 | 0 | 6 | 100.0% | 82.9% | 100.0% | 100.0% | 0/0 |
| haproxy | 43 | 43 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 5/5 |
| mosquitto | 7 | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 3/3 |
| nginx | 20 | 20 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |
| openssh | 94 | 94 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 12/12 |
| postgres | 17 | 17 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 1/1 |
| **All** | 216 | 210 | 0 | 6 | 100.0% | 97.2% | 100.0% | 100.0% | 21/21 |

### What pqscan got wrong

- missed: `curl/lib/vtls/openssl.c:307` DSA
- missed: `curl/lib/vtls/openssl.c:308` DSA
- missed: `curl/lib/vtls/openssl.c:309` DSA
- missed: `curl/lib/vtls/openssl.c:342` DH
- missed: `curl/lib/vtls/openssl.c:343` DH
- missed: `curl/lib/vtls/openssl.c:344` DH

## Held out

| Project | Labels | Found | False positives | Missed | Precision | Recall | File precision | File recall | Key sizes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| curl | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |
| haproxy | 40 | 40 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |
| mosquitto | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |
| nginx | 2 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |
| openssh | 25 | 25 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |
| postgres | 4 | 4 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |
| **All** | 73 | 73 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0/0 |

### What pqscan got wrong

None.
