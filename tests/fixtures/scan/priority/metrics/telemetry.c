/* Telemetry is worthless after a year. */
void sign_metrics(void) { ECDSA_sign(0, NULL, 0, NULL, NULL, NULL); }
