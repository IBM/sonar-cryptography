import json

def optional(value):
    if value == "" or value == "-":
        return "null"
    else:
        return "\"" + value + "\""

with open("./ciphersuites.json", "r") as stream:
    cipherList = list()

    data = json.load(stream)
    cipherSuites = data["ciphersuites"]
    for cipherSuite in cipherSuites:
        name, *_ = cipherSuite.keys()
        struct, *_ = cipherSuite.values()
        struct["name"] = name
        cipherList.append(struct)


    code = """
package com.ibm.mapper.mapper.ssl.json;

import java.util.Map;

@SuppressWarnings("java:S1192")
public final class JsonCipherSuites {

    private JsonCipherSuites() {
        // nothing
    }

    public static final Map<String, JsonCipherSuite> CIPHER_SUITES = Map.<String, JsonCipherSuite>ofEntries(
    """

    for i, cipherSuite in enumerate(cipherSuites):
        name, *_ = cipherSuite.keys()
        struct, *_ = cipherSuite.values()

        gnutlsName = optional(struct["gnutls_name"])
        openSSLName = optional(struct["openssl_name"])

        hex1 = struct["hex_byte_1"]
        hex2 = struct["hex_byte_2"]

        idsStr = ""
        if hex1 is not None or hex2 is not None:
            if hex1 is not None and hex2 is not None:
                idsStr = 'new String[]{ "'+hex1+'", "'+hex2+'" }'
            elif hex1 is not None and hex2 is None:
                idsStr = 'new String[]{ "'+hex1+'" }'
            elif hex1 is None and hex2 is not None:
                idsStr = 'new String[]{ "'+hex2+'" }'
        else:
            idsStr = 'null'

        keyExchangeAlgo = optional(struct["kex_algorithm"])
        authenticationAlgorithm = optional(struct["auth_algorithm"])
        encryptionAlgorithm = optional(struct["enc_algorithm"])
        hashAlgorithm = optional(struct["hash_algorithm"])

        code += f"""    Map.entry(\"{name}\", new JsonCipherSuite(\"{name}\", {gnutlsName}, {openSSLName}, {idsStr}, {keyExchangeAlgo}, {authenticationAlgorithm}, {encryptionAlgorithm}, {hashAlgorithm}))"""

        if i != len(cipherSuites) -1:
            code += ",\n"

    code += """
    );
}
    """
with open("./src/main/java/com/ibm/mapper/mapper/ssl/json/JsonCipherSuites.java", "w") as outfile:
    outfile.write(code)