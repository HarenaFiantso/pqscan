void digest(const unsigned char *data, size_t len, unsigned char *out) {
    MD5(data, len, out);
    SHA1(data, len, out);
}
