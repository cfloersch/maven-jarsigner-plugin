/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/31/2025
 */
package org.xpertss.crypto.pkcs_old;

import org.xpertss.crypto.asn1.ASN1Choice;

/**
 *  ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate, -- X.509
 *      extendedCertificate [0] IMPLICIT ExtendedCertificate
 *  }
 *
 *  ExtendedCertificatesAndCertificates ::=
 *      SET OF ExtendedCertificateOrCertificate
 */
public class Certificates extends ASN1Choice {




}
