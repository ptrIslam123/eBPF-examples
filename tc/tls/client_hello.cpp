#include "client_hello.h"

#include <iomanip>

namespace {

int extractClientHello(uint8_t *data, uint64_t len, struct tls::tls_client_hello *out) {
    uint8_t *cursor = data;
    uint8_t *end = data + len;

    if (cursor + 2 > end) return -1;
    out->client_version = ntohs(*(uint16_t*)cursor);
    cursor += 2;

    if (cursor + 32 > end) return -1;
    memcpy(out->random, cursor, 32);
    cursor += 32;

    if (cursor + 1 > end) return -1;
    out->session_id_len = *cursor;
    cursor += 1;
    if (cursor + out->session_id_len > end) return -1;
    out->session_id = cursor;
    cursor += out->session_id_len;

    if (cursor + 2 > end) return -1;
    out->cipher_suites_len = ntohs(*(uint16_t*)cursor);
    cursor += 2;
    if (cursor + out->cipher_suites_len > end) return -1;
    out->cipher_suites = (uint16_t*)cursor;
    cursor += out->cipher_suites_len;

    if (cursor + 1 > end) return -1;
    out->compression_methods_len = *cursor;
    cursor += 1;
    if (cursor + out->compression_methods_len > end) return -1;
    out->compression_methods = cursor;
    cursor += out->compression_methods_len;

    if (cursor + 2 > end) return -1;
    out->extensions_len = ntohs(*(uint16_t*)cursor);
    cursor += 2;
    if (cursor + out->extensions_len > end) return -1;
    out->extensions = cursor;
    return 0;
}

} // namespace

namespace tls {

ClientHelloContext::ClientHelloContext(std::uint8_t *data, std::uint64_t len) {
    if (extractClientHello(data, len, &m_ch) != 0) {
        throw 0;
    }
    m_cipherSuites = extractCipherSuites(&m_ch);
    m_compressionMethods = extractCompressionMethods(&m_ch);
    m_extensions = extractExtensions(&m_ch);
    m_alpn = extractAlpn(m_extensions);
    m_sni = extractSNI(m_extensions);
    m_groupsId = extractSupportedGroups(m_extensions);
}

std::string_view ClientHelloContext::CipherSuite2Str(const enum tls_cipher_suite cs) {
    switch (cs) {
        // TLS 1.3
        case tls_cipher_suite::TLS_AES_128_GCM_SHA256: return "TLS_AES_128_GCM_SHA256";
        case tls_cipher_suite::TLS_AES_256_GCM_SHA384: return "TLS_AES_256_GCM_SHA384";
        case tls_cipher_suite::TLS_CHACHA20_POLY1305_SHA256: return "TLS_CHACHA20_POLY1305_SHA256";
        case tls_cipher_suite::TLS_AES_128_CCM_SHA256: return "TLS_AES_128_CCM_SHA256";
        case tls_cipher_suite::TLS_AES_128_CCM_8_SHA256: return "TLS_AES_128_CCM_8_SHA256";
        
        // TLS 1.2 ECDHE
        case tls_cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case tls_cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case tls_cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case tls_cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case tls_cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        case tls_cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
        
        // Legacy RSA
        case tls_cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
        case tls_cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
        case tls_cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA256: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
        case tls_cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA256: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
        case tls_cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case tls_cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case tls_cipher_suite::TLS_RSA_WITH_3DES_EDE_CBC_SHA: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        case tls_cipher_suite::TLS_RSA_WITH_RC4_128_SHA: return "TLS_RSA_WITH_RC4_128_SHA";
        case tls_cipher_suite::TLS_RSA_WITH_RC4_128_MD5: return "TLS_RSA_WITH_RC4_128_MD5";
        
        // Anonymous
        case tls_cipher_suite::TLS_DH_anon_WITH_AES_256_CBC_SHA: return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
        case tls_cipher_suite::TLS_DH_anon_WITH_AES_128_CBC_SHA: return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
        case tls_cipher_suite::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA: return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
        
        default: return "UNKNOWN_CIPHER_SUITE";
    }
}

std::string_view ClientHelloContext::Extension2Str(const enum tls_extensions_type ext) {
    switch (ext) {
        // Core extensions
        case tls_extensions_type::SERVER_NAME: return "server_name (SNI) [RFC 6066]";
        case tls_extensions_type::MAX_FRAGMENT_LENGTH: return "max_fragment_length [RFC 6066]";
        case tls_extensions_type::CLIENT_CERTIFICATE_URL: return "client_certificate_url [RFC 6066]";
        case tls_extensions_type::TRUSTED_CA_KEYS: return "trusted_ca_keys [RFC 6066]";
        case tls_extensions_type::TRUNCATED_HMAC: return "truncated_hmac [RFC 6066]";
        case tls_extensions_type::STATUS_REQUEST: return "status_request (OCSP stapling) [RFC 6066]";
        
        // ECC and key exchange
        case tls_extensions_type::SUPPORTED_GROUPS: return "supported_groups [RFC 8422, 7919]";
        case tls_extensions_type::EC_POINT_FORMATS: return "ec_point_formats [RFC 8422]";
        
        // Signature and security
        case tls_extensions_type::SIGNATURE_ALGORITHMS: return "signature_algorithms [RFC 8446]";
        case tls_extensions_type::USE_SRTP: return "use_srtp [RFC 5764]";
        case tls_extensions_type::HEARTBEAT: return "heartbeat [RFC 6520]";
        
        // Application layer
        case tls_extensions_type::ALPN: 
            return "application_layer_protocol_negotiation (ALPN) [RFC 7301]";
        case tls_extensions_type::SIGNED_CERTIFICATE_TIMESTAMP: 
            return "signed_certificate_timestamp (CT) [RFC 6962]";
        case tls_extensions_type::CLIENT_CERTIFICATE_TYPE: return "client_certificate_type [RFC 7250]";
        case tls_extensions_type::SERVER_CERTIFICATE_TYPE: return "server_certificate_type [RFC 7250]";
        
        // TLS 1.3 extensions
        case tls_extensions_type::PADDING: return "padding [RFC 7685]";
        case tls_extensions_type::ENCRYPT_THEN_MAC: return "encrypt_then_mac [RFC 7366]";
        case tls_extensions_type::EXTENDED_MASTER_SECRET: return "extended_master_secret [RFC 7627]";
        case tls_extensions_type::SESSION_TICKET: return "session_ticket [RFC 5077]";
        case tls_extensions_type::RECORD_SIZE_LIMIT: return "record_size_limit [RFC 8449]";
        case tls_extensions_type::PRE_SHARED_KEY: return "pre_shared_key (PSK) [RFC 8446]";
        case tls_extensions_type::EARLY_DATA: return "early_data (0-RTT) [RFC 8446]";
        case tls_extensions_type::SUPPORTED_VERSIONS: return "supported_versions [RFC 8446]";
        case tls_extensions_type::COOKIE: return "cookie [RFC 8446]";
        case tls_extensions_type::PSK_KEY_EXCHANGE_MODES: return "psk_key_exchange_modes [RFC 8446]";
        case tls_extensions_type::CERTIFICATE_AUTHORITIES: return "certificate_authorities [RFC 8446]";
        case tls_extensions_type::OID_FILTERS: return "oid_filters [RFC 8446]";
        case tls_extensions_type::POST_HANDSHAKE_AUTH: return "post_handshake_auth [RFC 8446]";
        case tls_extensions_type::SIGNATURE_ALGORITHMS_CERT: return "signature_algorithms_cert [RFC 8446]";
        case tls_extensions_type::KEY_SHARE: return "key_share [RFC 8446]";
        
        // Special
        case tls_extensions_type::RENEGOTIATION_INFO: return "renegotiation_info [RFC 5746]";
        
        default: return "unknown_extension";
    }
}

std::string_view ClientHelloContext::SupportedGroup2Str(enum tls_supported_group group) {
    switch (group) {
        // ECC groups
        case SECP256R1: return "secp256r1 (P-256) [RFC 8422]";
        case SECP384R1: return "secp384r1 (P-384) [RFC 8422]";
        case SECP521R1: return "secp521r1 (P-521) [RFC 8422]";
        case X25519: return "X25519 (Curve25519) [RFC 8422]";
        case X448: return "X448 (Curve448) [RFC 8422]";
        
        // Brainpool
        case BRAINPOOL_P256R1: return "brainpoolP256r1 [RFC 8734]";
        case BRAINPOOL_P384R1: return "brainpoolP384r1 [RFC 8734]";
        case BRAINPOOL_P512R1: return "brainpoolP512r1 [RFC 8734]";
        
        // FFDHE
        case FFDHE2048: return "ffdhe2048 [RFC 7919]";
        case FFDHE3072: return "ffdhe3072 [RFC 7919]";
        case FFDHE4096: return "ffdhe4096 [RFC 7919]";
        case FFDHE6144: return "ffdhe6144 [RFC 7919]";
        case FFDHE8192: return "ffdhe8192 [RFC 7919]";
        
        // Post-Quantum
        case MLKEM512: return "ML-KEM-512 [IANA]";
        case MLKEM768: return "ML-KEM-768 [IANA]";
        case MLKEM1024: return "ML-KEM-1024 [IANA]";
        
        // Hybrid
        case SECP256R1_MLKEM768: return "secp256r1 + ML-KEM-768 [IANA]";
        case X25519_MLKEM768: return "X25519 + ML-KEM-768 [IANA]";
        case SECP384R1_MLKEM1024: return "secp384r1 + ML-KEM-1024 [IANA]";
        
        // Legacy
        case SECP224R1: return "secp224r1 (P-224) [deprecated]";
        case SECP192R1: return "secp192r1 (P-192) [deprecated]";
        case SECP256K1: return "secp256k1 [not recommended]";
        
        default: return "unknown group";
    }
}

std::ostream& ClientHelloContext::operator<<(std::ostream& os) const {
    // Заголовок
    os << "=== TLS ClientHello ===\n";

    // Версия
    os << "Client Version: 0x" << std::hex << m_ch.client_version << std::dec;
    if (m_ch.client_version == 0x0303) os << " (TLS 1.2)";
    else if (m_ch.client_version == 0x0304) os << " (TLS 1.3)";
    os << "\n";

    // Random (первые 4 байта как timestamp, остальные как hex)
    os << "Random: ";
    for (int i = 0; i < 32; ++i) {
        os << std::hex << std::setw(2) << std::setfill('0') << (int)m_ch.random[i];
        if (i == 3) os << " (timestamp) ";
    }
    os << std::dec << "\n";

    // Session ID
    os << "Session ID: ";
    if (m_ch.session_id_len == 0) {
        os << "none (new session)";
    } else {
        for (int i = 0; i < m_ch.session_id_len; ++i) {
            os << std::hex << std::setw(2) << std::setfill('0') << (int)m_ch.session_id[i];
        }
        os << std::dec;
    }
    os << "\n";

    // Cipher Suites
    os << "Cipher Suites (" << m_cipherSuites.size() << " suites):\n";
    for (const auto& cs : m_cipherSuites) {
        os << "  - " << CipherSuite2Str(cs) << "\n";
    }

    // Compression Methods
    os << "Compression Methods:\n";
    for (const auto& cm : m_compressionMethods) {
        switch (cm) {
            case TLS_NO_COMPRESSION: os << "  - null (no compression)\n"; break;
            case TLS_COMPRESSION_DEFLATE: os << "  - DEFLATE\n"; break;
            default: os << "  - unknown\n"; break;
        }
    }

    // Extensions (общий список)
    os << "Extensions (" << m_extensions.size() << "):\n";
    for (const auto& ext : m_extensions) {
        os << "  - " << Extension2Str(ext.type) << " (" << ext.len << " bytes)\n";
    }

    // ALPN (детали)
    if (!m_alpn.empty()) {
        os << "ALPN: ";
        for (size_t i = 0; i < m_alpn.size(); ++i) {
            if (i > 0) os << ", ";
            os << m_alpn[i];
        }
        os << "\n";
    }

    // SNI (детали)
    if (!m_sni.empty()) {
        os << "SNI: ";
        for (size_t i = 0; i < m_sni.size(); ++i) {
            if (i > 0) os << ", ";
            os << m_sni[i];
        }
        os << "\n";
    }

    // Supported groups (детали)
    if (!m_groupsId.empty()) {
        os << "Supported group idiex: ";
        for (size_t i = 0; i < m_groupsId.size(); ++i) {
            if (i > 0) os << ", ";
            os << SupportedGroup2Str(m_groupsId[i]);
        }
        os << "\n";
    }

    os << "========================\n";
    return os;
}

std::ostream& operator<<(std::ostream& os, const ClientHelloContext& chc) {
    return chc.operator<<(os);
}

std::vector<tls_cipher_suite> ClientHelloContext::extractCipherSuites(struct tls_client_hello* ch) {
    std::vector<tls_cipher_suite> result;
    if (!ch || !ch->cipher_suites || ch->cipher_suites_len == 0) {
        return result;
    }

    const auto count = ch->cipher_suites_len / 2;
    result.reserve(count);
    for (auto i = 0; i < count; i++) {
        auto cs = ntohs(ch->cipher_suites[i]);
        if (cs >= TLS_CIPHER_SUITE_UNKNOWN) {
            cs = TLS_CIPHER_SUITE_UNKNOWN;
        }
        result.push_back(static_cast<tls_cipher_suite>(cs));
    }
    return result;
}

std::vector<tls_compression_method> ClientHelloContext::extractCompressionMethods(struct tls_client_hello* ch) {
    std::vector<tls_compression_method> methods;
    if (!ch || !ch->compression_methods || ch->compression_methods_len == 0) {
        return methods;
    }

    for (int i = 0; i < ch->compression_methods_len; i++) {
        auto method = ch->compression_methods[i];
        if (method >= TLS_COMPRESSION_UNKNOW) {
            method = TLS_COMPRESSION_UNKNOW;
        }
        methods.push_back(static_cast<tls_compression_method>(method));
    }
    return methods;
}

std::vector<ClientHelloContext::Extension> ClientHelloContext::extractExtensions(struct tls_client_hello* ch) {
    std::vector<ClientHelloContext::Extension> extensions;
    if (!ch || !ch->extensions || ch->extensions_len < 4) {
        return extensions;
    }

    auto ptr = ch->extensions;
    auto end = ptr + ch->extensions_len;
    while (ptr + 4 <= end) {
        ClientHelloContext::Extension ext;
        auto type = ntohs(*(uint16_t*)ptr);
        if (type >= TLS_EXTENSIONS_UNKNOWN) {
            type = TLS_EXTENSIONS_UNKNOWN;
        }
        ext.type = static_cast<tls_extensions_type>(type);
        ptr += 2;

        ext.len = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        
        if (ptr + ext.len > end) break;
        
        ext.data = ptr;
        extensions.push_back(ext);
        ptr += ext.len;
    }
    return extensions;
}

std::vector<std::string> ClientHelloContext::extractAlpn(const std::vector<Extension>& extensions) {
    std::vector<std::string> result;
    
    for (const auto& ext : extensions) {
        if (ext.type != ALPN) continue;
        
        // Минимальная длина: 2 байта (list_len)
        if (ext.len < 2) break;
        
        const uint8_t* ptr = ext.data;
        uint16_t list_len = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        
        // Проверка, что list_len не выходит за пределы расширения
        if (list_len > ext.len - 2) break;
        
        const uint8_t* list_end = ptr + list_len;
        
        while (ptr < list_end) {
            // Каждый протокол: [длина (1 байт)] [данные (длина байт)]
            uint8_t proto_len = *ptr++;
            if (ptr + proto_len > list_end) break;  // защита от malformed
            result.emplace_back(reinterpret_cast<const char*>(ptr), proto_len);
            ptr += proto_len;
        }
        break;  // нашли ALPN, дальше не ищем
    }
    return result;
}

std::vector<std::string> ClientHelloContext::extractSNI(const std::vector<Extension>& extensions) {
    std::vector<std::string> result;
    for (const auto& ext : extensions) {
        if (ext.type != SERVER_NAME) continue;  // используйте правильное имя типа
        
        if (ext.len < 4) return {};  // минимальная длина: list_len (2) + type(1) + name_len(2) + имя(минимум 1)
        
        const uint8_t* ptr = ext.data;
        uint16_t list_len = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        
        if (list_len > ext.len - 2) return {};
        
        const uint8_t* list_end = ptr + list_len;
        
        // Обычно SNI содержит только одну запись, но по RFC может быть несколько
        while (ptr + 3 <= list_end) {  // минимум type(1) + name_len(2)
            uint8_t name_type = *ptr++;
            uint16_t name_len = ntohs(*(uint16_t*)ptr);
            ptr += 2;
            
            if (ptr + name_len > list_end) break;
            
            if (name_type == 0x00) {  // host_name
                result.emplace_back(reinterpret_cast<const char*>(ptr), name_len);
            }
            ptr += name_len;  // пропустить другие типы, если есть
        }
        break;
    }
    return result;
}

std::vector<tls_supported_group> ClientHelloContext::extractSupportedGroups(const std::vector<Extension>& extensions) {
    std::vector<tls_supported_group> groups;
    for (const auto& ext : extensions) {
        if (ext.type != SUPPORTED_GROUPS || ext.len < 2) {
            continue;
        }

        const uint16_t* group_ptr = reinterpret_cast<const uint16_t*>(ext.data);
        uint16_t list_len_bytes = ntohs(*group_ptr); // Длина списка в байтах
        group_ptr++;
        int group_count = list_len_bytes / 2;

        for (int i = 0; i < group_count; ++i) {
            auto group = ntohs(group_ptr[i]);
            if (group >= TLS_GROUP_UNKNOWN) {
                group = TLS_GROUP_UNKNOWN;
            }
            groups.push_back(static_cast<tls_supported_group>(group));
        }
    }
    
    return groups;
}

} // namespace tls
