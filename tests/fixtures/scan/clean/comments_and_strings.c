/* RSA_new in a block comment is not a use. */
// DSA_new() in a line comment is not a use either.
const char *note = "DH_new in a string is not a use";
const char *name = "RSA";

void log_name(const char *text);

void f(void) {
    log_name("EVP_PKEY_RSA");
    log_name("RSA"); /* A known name, but not in a known call. */
}
