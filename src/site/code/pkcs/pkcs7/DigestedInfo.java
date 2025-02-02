/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/1/2025
 */
package org.xpertss.crypto.pkcs.pkcs7;

/**
 * This class implements the PKCS#7 DigestInfo type.
 * <p/>
 * The PKCS#7 Cryptographic Message Standard specifies the DigestInfo type as ASN.1
 * structure whose BER encoded value serves as input for the digest-encryption
 * process when creating a SignedData object.
 * <pre>
 *  DigestInfo ::= SEQUENCE {
 *    digestAlgorithm DigestAlgorithmIdentifier,
 *    digest Digest }
 *
 *
 *  Digest ::= OCTET STRING
 * </pre>
 *
 */
public class DigestedInfo {}
