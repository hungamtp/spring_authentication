package com.example.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

import java.security.cert.X509Certificate;

/**
 * ═══════════════════════════════════════════════════════════════════
 *  mTLS / TLS / PKI CONFIGURATION
 *
 *  TLS is configured in application.yml (server.ssl.*).
 *  This class handles:
 *   - Logging of mTLS client certificate details
 *   - PKI certificate validation helpers
 *
 *  PKI Trust Chain:
 *
 *    Root CA (self-signed)
 *        └── Intermediate CA (signed by Root CA)
 *                ├── Server Certificate (signed by Intermediate CA)
 *                └── Client Certificate (signed by Intermediate CA)
 *
 *  The truststore holds the CA certificates that Spring uses to
 *  verify client certificates in mTLS.
 *
 *  See: generate-certs.sh for creating test certificates with keytool/openssl
 * ═══════════════════════════════════════════════════════════════════
 */
@Configuration
@Slf4j
public class MtlsConfig {

    /**
     * Log client certificate details when mTLS is active.
     * Spring sets "javax.servlet.request.X509Certificate" attribute on the request.
     *
     * In SecurityConfig, .x509() extracts the CN from the client cert
     * and uses it as the principal name for authentication.
     */
    @Bean
    public CommonsRequestLoggingFilter requestLoggingFilter() {
        CommonsRequestLoggingFilter filter = new CommonsRequestLoggingFilter() {
            @Override
            protected void beforeRequest(jakarta.servlet.http.HttpServletRequest request, String message) {
                // Extract and log the client certificate (mTLS)
                java.security.cert.X509Certificate[] certs =
                    (java.security.cert.X509Certificate[])
                        request.getAttribute("jakarta.servlet.request.X509Certificate");

                if (certs != null && certs.length > 0) {
                    X509Certificate clientCert = certs[0];
                    log.info("mTLS Client Certificate: subject={}, issuer={}, validUntil={}",
                        clientCert.getSubjectX500Principal().getName(),
                        clientCert.getIssuerX500Principal().getName(),
                        clientCert.getNotAfter()
                    );
                }
                super.beforeRequest(request, message);
            }
        };
        filter.setIncludeHeaders(false);
        filter.setIncludeQueryString(true);
        return filter;
    }
}
