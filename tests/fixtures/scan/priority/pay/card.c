/* Card data must stay secret for decades. */
void sign_payment(RSA *rsa) { RSA_generate_key_ex(rsa, 2048, NULL, NULL); }
