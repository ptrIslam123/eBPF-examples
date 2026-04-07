#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <ostream>

#include <cinttypes>

#include <netinet/in.h>

extern "C" {

#include <bpf/bpf.h>

}

namespace tls {

/**
 * TLS Supported Groups (Named Groups) as defined by IANA
 * 
 * References:
 * - RFC 8446 (TLS 1.3), Section 4.2.7
 * - RFC 7919 (FFDHE groups)
 * - IANA TLS Supported Groups Registry:
 *   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-supported-groups
 * 
 * Values are based on the official IANA registry and various RFCs.
 */
typedef enum tls_supported_group : __u16 {
    // =============================================================
    // Elliptic Curve Groups (ECDHE) - RFC 8422, 8446
    // =============================================================
    SECP256R1 = 0x0017,               ///< NIST P-256 curve
    SECP384R1 = 0x0018,               ///< NIST P-384 curve
    SECP521R1 = 0x0019,               ///< NIST P-521 curve
    X25519 = 0x001D,                  ///< Curve25519 - RFC 8422
    X448 = 0x001E,                    ///< Curve448 - RFC 8422
    
    // Brainpool curves (RFC 8734 - TLS 1.3)
    BRAINPOOL_P256R1 = 0x001A,        ///< brainpoolP256r1
    BRAINPOOL_P384R1 = 0x001B,        ///< brainpoolP384r1
    BRAINPOOL_P512R1 = 0x001C,        ///< brainpoolP512r1
    
    // =============================================================
    // Finite Field Groups (FFDHE) - RFC 7919
    // =============================================================
    FFDHE2048 = 0x0100,               ///< 2048-bit group
    FFDHE3072 = 0x0101,               ///< 3072-bit group
    FFDHE4096 = 0x0102,               ///< 4096-bit group
    FFDHE6144 = 0x0103,               ///< 6144-bit group
    FFDHE8192 = 0x0104,               ///< 8192-bit group
    
    // =============================================================
    // Post-Quantum Key Exchange (ML-KEM) - IANA registry
    // =============================================================
    MLKEM512 = 0x0200,                ///< ML-KEM-512 (NIST Level 1)
    MLKEM768 = 0x0201,                ///< ML-KEM-768 (NIST Level 3)
    MLKEM1024 = 0x0202,               ///< ML-KEM-1024 (NIST Level 5)
    
    // =============================================================
    // Hybrid Key Exchange - IANA registry
    // =============================================================
    SECP256R1_MLKEM768 = 0x11EB,      ///< secp256r1 + ML-KEM-768
    X25519_MLKEM768 = 0x11EC,         ///< X25519 + ML-KEM-768
    SECP384R1_MLKEM1024 = 0x11ED,     ///< secp384r1 + ML-KEM-1024
    
    // =============================================================
    // Legacy / Obsolete (NOT RECOMMENDED)
    // =============================================================
    SECP224R1 = 0x0016,               ///< NIST P-224 - obsolete
    SECP192R1 = 0x0013,               ///< NIST P-192 - deprecated
    SECP256K1 = 0x0014,               ///< Bitcoin curve - not recommended
    
    // =============================================================
    // Reserved / Unknown
    // =============================================================
    TLS_GROUP_UNKNOWN = 0xFFFF,
} tls_supported_group;

typedef enum tls_cipher_suite : __u16 {
    // =============================================================
    // TLS 1.3 Cipher Suites (RFC 8446) - RECOMMENDED
    // =============================================================
    TLS_AES_128_GCM_SHA256              = 0x1301,
    TLS_AES_256_GCM_SHA384              = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256        = 0x1303,
    TLS_AES_128_CCM_SHA256              = 0x1304,
    TLS_AES_128_CCM_8_SHA256            = 0x1305,

    // =============================================================
    // TLS 1.2 ECDHE Cipher Suites - RECOMMENDED
    // =============================================================
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    = 0xC02B,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    = 0xC02C,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256      = 0xC02F,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384      = 0xC030,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256    = 0xC023,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256      = 0xC027,

    // =============================================================
    // Legacy TLS 1.2/1.1/1.0 Cipher Suites (NOT RECOMMENDED)
    // Included for parsing legacy traffic only
    // =============================================================
    TLS_RSA_WITH_AES_256_GCM_SHA384      = 0x009D,
    TLS_RSA_WITH_AES_128_GCM_SHA256      = 0x009C,
    TLS_RSA_WITH_AES_256_CBC_SHA256      = 0x003D,
    TLS_RSA_WITH_AES_128_CBC_SHA256      = 0x003C,
    TLS_RSA_WITH_AES_256_CBC_SHA         = 0x0035,
    TLS_RSA_WITH_AES_128_CBC_SHA         = 0x002F,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA        = 0x000A,
    TLS_RSA_WITH_RC4_128_SHA             = 0x0005,
    TLS_RSA_WITH_RC4_128_MD5             = 0x0004,

    // Weak NULL/Anonymous ciphers
    TLS_DH_anon_WITH_AES_256_CBC_SHA     = 0x003A,
    TLS_DH_anon_WITH_AES_128_CBC_SHA     = 0x0034,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA    = 0x001B,
    TLS_DH_anon_WITH_RC4_128_MD5         = 0x0018,
    TLS_NULL_WITH_NULL_NULL              = 0x0000,

    // =============================================================
    // Utility/Unknown
    // =============================================================
    TLS_CIPHER_SUITE_UNKNOWN             = 0xFFFF
} tls_cipher_suite;

typedef enum tls_compression_method : __u8 {
    TLS_NO_COMPRESSION = 0x00,
    TLS_COMPRESSION_DEFLATE = 0x01,
    TLS_COMPRESSION_UNKNOW,
} tls_compression_method;

/**
 * TLS ExtensionType values as defined by IANA
 * Reference: https://www.iana.org/assignments/tls-extensiontype-values/
 * 
 * This enum includes extensions from:
 * - RFC 6066 (Certificate Extensions, SNI, etc.)
 * - RFC 7301 (ALPN)
 * - RFC 8446 (TLS 1.3)
 * - RFC 8449 (Record Size Limit)
 * - RFC 8422 (ECC/Supported Groups)
 * 
 * For a complete list of all 100+ extensions, refer to the IANA registry.
 * The most common extensions for modern TLS (1.2/1.3) are included here.
 */
typedef enum tls_extensions_type : __u16 {
    // =============================================================
    // Core Extensions (RFC 6066 and legacy)
    // =============================================================
    SERVER_NAME = 0,                        ///< SNI - Server Name Indication [RFC 6066]
    MAX_FRAGMENT_LENGTH = 1,                ///< Maximum fragment length negotiation [RFC 6066]
    CLIENT_CERTIFICATE_URL = 2,             ///< Client certificate URL [RFC 6066]
    TRUSTED_CA_KEYS = 3,                    ///< Trusted CA keys [RFC 6066]
    TRUNCATED_HMAC = 4,                     ///< Truncated HMAC [RFC 6066]
    STATUS_REQUEST = 5,                     ///< OCSP status request (stapling) [RFC 6066]
    USER_MAPPING = 6,                       ///< User mapping [RFC 4681]
    
    // =============================================================
    // ECC and Key Exchange (RFC 8422, 7919)
    // =============================================================
    CERT_TYPE = 9,                          ///< Certificate type [RFC 5081]
    SUPPORTED_GROUPS = 10,                  ///< Supported groups (formerly elliptic_curves) [RFC 8422, 7919]
    EC_POINT_FORMATS = 11,                  ///< EC point formats [RFC 8422]
    SRP = 12,                               ///< Secure Remote Password [RFC 5054]
    
    // =============================================================
    // Signature and Security
    // =============================================================
    SIGNATURE_ALGORITHMS = 13,              ///< Signature algorithms [RFC 8446]
    USE_SRTP = 14,                          ///< SRTP for DTLS [RFC 5764]
    HEARTBEAT = 15,                         ///< Heartbeat extension [RFC 6520]
    
    // =============================================================
    // Application Layer
    // =============================================================
    ALPN = 16,                                    ///< ALPN [RFC 7301]
    STATUS_REQUEST_V2 = 17,                       ///< OCSP v2 [RFC 6961]
    SIGNED_CERTIFICATE_TIMESTAMP = 18,            ///< Certificate Transparency [RFC 6962]
    CLIENT_CERTIFICATE_TYPE = 19,                 ///< Client certificate type [RFC 7250]
    SERVER_CERTIFICATE_TYPE = 20,                 ///< Server certificate type [RFC 7250]
    
    // =============================================================
    // TLS 1.3 and Modern Extensions
    // =============================================================
    PADDING = 21,                           ///< Padding [RFC 7685]
    ENCRYPT_THEN_MAC = 22,                  ///< Encrypt-then-MAC [RFC 7366]
    EXTENDED_MASTER_SECRET = 23,            ///< Extended master secret [RFC 7627]
    SESSION_TICKET = 35,                    ///< Session ticket [RFC 5077]
    RECORD_SIZE_LIMIT = 28,                 ///< Record size limit [RFC 8449]
    PRE_SHARED_KEY = 41,                    ///< PSK key exchange [RFC 8446]
    EARLY_DATA = 42,                        ///< 0-RTT early data [RFC 8446]
    SUPPORTED_VERSIONS = 43,                ///< TLS version negotiation [RFC 8446]
    COOKIE = 44,                            ///< Cookie (DTLS DoS protection) [RFC 8446]
    PSK_KEY_EXCHANGE_MODES = 45,            ///< PSK key exchange modes [RFC 8446]
    CERTIFICATE_AUTHORITIES = 47,           ///< Certificate authorities [RFC 8446]
    OID_FILTERS = 48,                       ///< OID filters [RFC 8446]
    POST_HANDSHAKE_AUTH = 49,               ///< Post-handshake authentication [RFC 8446]
    SIGNATURE_ALGORITHMS_CERT = 50,         ///< Signature algorithms for certificates [RFC 8446]
    KEY_SHARE = 51,                         ///< Key share for TLS 1.3 [RFC 8446]
    
    // =============================================================
    // Special / Private Use
    // =============================================================
    RENEGOTIATION_INFO = 65281,             ///< Renegotiation info [RFC 5746]
    
    // =============================================================
    // Unknown - for parsing unrecognized extensions
    // =============================================================
    TLS_EXTENSIONS_UNKNOWN = 0xFFFF,
} tls_extensions_type;

typedef struct tls_client_hello {
    /* Part 1: Fixed fields */
    __u16 client_version;           // offset 0-1: TLS version client supports

    /* Part 2: Random (32 bytes) */
    __u8  random[32];               // offset 2-33: 4 bytes timestamp + 28 random

    /* Part 3: Session ID */
    __u8  session_id_len;           // offset 34: length of session ID
    __u8* session_id;               // variable: session ID (if any)

    /* Part 4: Cipher Suites */
    __u16 cipher_suites_len;        // length in bytes
    __u16* cipher_suites;           // variable: list of cipher suites (each 2 bytes)

    /* Part 5: Compression Methods */
    __u8  compression_methods_len;  // length in bytes
    __u8* compression_methods;      // variable: list of compression methods

    /* Part 6: Extensions */
    __u16 extensions_len;           // length in bytes
    __u8* extensions;               // variable: TLS extensions
} tls_client_hello_t;


// Парсинг ClientHello
int parseClientHello(uint8_t *data, uint64_t len, tls_client_hello *out);

class ClientHelloContext final {
public:
    struct Extension {
        tls_extensions_type type;
        std::uint8_t* data;
        std::uint16_t len;
    };

    explicit ClientHelloContext(std::uint8_t *data, std::uint64_t len);

    /**
     * Converts a cipher suite enum value to a human-readable string.
     * Useful for debugging and logging TLS handshakes.
     */
    static std::string_view CipherSuite2Str(enum tls_cipher_suite cs);

    /**
     * Convert extension type to human-readable string
     * Based on IANA registry and RFC specifications
     */
    static std::string_view Extension2Str(enum tls_extensions_type ext);

    /**
    * Convert group ID to human-readable string
    */
    static std::string_view SupportedGroup2Str(enum tls_supported_group group);

    std::ostream& operator<<(std::ostream& os) const;

private:
    std::vector<tls_cipher_suite> extractCipherSuites(struct tls_client_hello* ch);
    std::vector<tls_compression_method> extractCompressionMethods(struct tls_client_hello* ch);
    std::vector<Extension> extractExtensions(struct tls_client_hello* ch);
    std::vector<std::string> extractAlpn(const std::vector<Extension>& extensions);
    std::vector<std::string> extractSNI(const std::vector<Extension>& extensions);
    std::vector<tls_supported_group> extractSupportedGroups(const std::vector<Extension>& extensions);

    struct tls_client_hello m_ch;
    std::vector<tls_cipher_suite> m_cipherSuites;
    std::vector<tls_compression_method> m_compressionMethods;
    std::vector<Extension> m_extensions;
    std::vector<std::string> m_alpn;
    std::vector<std::string> m_sni;
    std::vector<tls_supported_group> m_groupsId;
};

std::ostream& operator<<(std::ostream& os, const ClientHelloContext& chc);

} // namespace tls
