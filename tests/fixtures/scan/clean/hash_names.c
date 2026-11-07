/* A project's own names, not OpenSSL's one-shot MD5() and SHA1(). */
enum digest_kind { MD5, SHA1 };

void MD5_of(int kind);
int digest_size(void);

static int kind = MD5;

int is_sha1(int value) {
    return value == SHA1;
}
