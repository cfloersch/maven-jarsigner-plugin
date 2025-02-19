package org.xpertss.crypto.pkcs.pkcs7;


import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmId;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.pkcs.pkcs9.Attributes;
import org.xpertss.crypto.pkcs.pkcs9.Attribute;


import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * This class represents a PKCS#7 SignerInfo structure. It is defined as follows:
 * <pre>
 * SignerInfo ::= SEQUENCE {
 *   version Version,
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
 *   digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *   encryptedDigest EncryptedDigest,
 *   unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
 * }
 *
 * EncryptedDigest ::= OCTET STRING
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * </pre>
 * <p/>
 * For completeness, we also present the structures referenced in the SignerInfo
 * structure.
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *   issuer Name,
 *   serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER
 *
 * Attributes ::= SET OF Attribute -- from X.501
 * </pre>
 * <p/>
 * It seems that this spec views the digesting and encryption of that digest as separate
 * operations where as Java's Signature class views them as one in the same.
 */
public class SignerInfo extends ASN1Sequence {
   /**
    * The version number of this SignerInfo.
    */
   protected ASN1Integer version;


   protected IssuerAndSerialNumber identity;


   /**
    * The {@link AlgorithmIdentifier DigestAlgorithmIdentifier}.
    */
   protected AlgorithmIdentifier dAlg;

   /**
    * The {@link AlgorithmIdentifier DigestEncryptionAlgorithmIdentifier}.
    */
   protected AlgorithmIdentifier cAlg;

   /**
    * The authenticated attributes.
    */
   protected Attributes auth;

   /**
    * The unauthenticated attributes.
    */
   protected Attributes attr;

   /**
    * The encrypted digest.
    */
   protected ASN1OctetString edig;


   /**
    * The signature algorithm parameters spec to use when verifying
    * or signing {@link SignedData SignedData} instances.
    */
   protected AlgorithmParameters params;


   /**
    * Creates an instance ready for decoding.
    */
   public SignerInfo()
   {
      super(7);

      /* Global structure and Version */
      version = new ASN1Integer(1);
      add(version);

      /* Issuer and serial number */
      identity = new IssuerAndSerialNumber();
      add(identity);

      /* Digest Algorithm Identifier */
      dAlg = new AlgorithmIdentifier();
      add(dAlg);

      /* Authenticated Attributes */
      auth = new Attributes();
      add(new ASN1TaggedType(0, auth, false, true));

      /* Digest Encryption Algorithm Identifier */
      cAlg = new AlgorithmIdentifier();
      add(cAlg);

      /* Encrypted Digest */
      edig = new ASN1OctetString();
      add(edig);

      /* Unauthenticated Attributes */
      attr = new Attributes();
      add(new ASN1TaggedType(1, attr, false, true));
   }


   /**
    * Creates an instance ready for decoding. The given registry is used to resolve attributes.
    *
    * @param registry The <code>OIDRegistry</code> to use for resolving attributes, or
    *                 <code>null</code> if the default PKCS registry shall be used.
    */
   public SignerInfo(OIDRegistry registry)
   {
      super(7);

      /* Global structure and Version */
      version = new ASN1Integer(1);
      add(version);

      /* Issuer and serial number */
      identity = new IssuerAndSerialNumber();
      add(identity);

      /* Digest Algorithm Identifier */
      dAlg = new AlgorithmIdentifier();
      add(dAlg);

      /* Authenticated Attributes */
      auth = new Attributes(registry);
      add(new ASN1TaggedType(0, auth, false, true));

      /* Digest Encryption Algorithm Identifier */
      cAlg = new AlgorithmIdentifier();
      add(cAlg);

      /* Encrypted Digest */
      edig = new ASN1OctetString();
      add(edig);

      /* Unauthenticated Attributes */
      attr = new Attributes(registry);
      add(new ASN1TaggedType(1, attr, false, true));
   }


   /**
    * This method calls initialises this structure with the given arguments. This constructor
    * creates Version 1 SignerInfos.  The given algorithm must be a PKCS#1 Version 1.5
    * conformant signature algorithm. In other words, the signature algorithm MUST NOT have
    * algorithm parameters.
    * <p>
    * If PKCS#1 version 2.1 Draft 1 signatures (RSASSA-PSS) shall be used then the constructor
    * taking algorithm parameters must be called instead of this one.
    *
    * @param cert The signer's certificate.
    * @param algorithm The JCA standard name of the PKCS#1 version 1.5 compliant signature
    *                  algorithm.
    * @exception NoSuchAlgorithmException if the signature algorithm name cannot be resolved
    *    to the OIDs of the names of its raw cipher algorithm and its digest algorithm.
    * @exception IllegalArgumentException if the OID to which the given algorithm name is
    *    mapped by means of the aliases of the installed providers is not a valid OID string.
    */
   public SignerInfo(X509Certificate cert, String algorithm)
      throws NoSuchAlgorithmException
   {
      super(7);

      /* Global structure and Version */
      version = new ASN1Integer(1);
      add(version);

      /* Issuer and serial number */
      identity = new IssuerAndSerialNumber(cert);
      add(identity);


      /* We now initialise the algorithm identifiers.
       * The style is according to PKCS#1 Version 1.5,
       * no parameters for the signature algorithm.
       * Parameters are encoded as ASN1Null.
       */
      String digestAlgName = AlgorithmId.getDigAlgFromSigAlg(algorithm);
      ASN1ObjectIdentifier digOid = AlgorithmId.lookup(digestAlgName);

      /* Digest Algorithm Identifier */
      dAlg = new AlgorithmIdentifier(digOid);
      add(dAlg);

      /* Authenticated Attributes */
      auth = new Attributes();
      add(new ASN1TaggedType(0, auth, false, true));


      String encAlgName = AlgorithmId.getEncAlgFromSigAlg(algorithm);
      ASN1ObjectIdentifier encOid = AlgorithmId.lookup(encAlgName);

      /* Digest Encryption Algorithm Identifier */
      cAlg = new AlgorithmIdentifier(encOid);
      add(cAlg);

      /* Encrypted Digest */
      edig = new ASN1OctetString();
      add(edig);

      /* Unauthenticated Attributes */
      attr = new Attributes();
      add(new ASN1TaggedType(1, attr, false, true));
   }


   /**
    * This method calls initialises this structure with the given arguments. This constructor
    * creates Version 1 SignerInfos. The given algorithm must be a PKCS#1 Version 2.1 Draft 1
    * conformant signature algorithm. The signature algorithm identifier is put into the place
    * of the digest algorithm identifier. The given parameters are those of the signature
    * algorithm (e. g. RSASSA-PSS). If the parameters are <code>null</code> then they are
    * encoded as {@link ASN1Null}. The signature algorithm identifier is also put into the
    * place of the digest encryption algorithm identifier (without parameters). PKCS#1
    * Version 2.1 Draft 1 does not specify how this case should be handled so we picked
    * our choice.
    *
    * @param cert The signer's certificate.
    * @param algorithm The JCA standard name of the PKCS#1 Version 2.1 Draft 1 compliant
    *                  signature algorithm.
    * @exception NoSuchAlgorithmException if the signature algorithm name cannot be resolved
    *    to the OIDs of the names of its raw cipher algorithm and its digest algorithm.
    *
    *   TODO Looks like the RSASSA-PSS uses this
   public SignerInfo(X509Certificate cert, AlgorithmParameters params)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
   {
      super(7);

      version_ = new ASN1Integer(1);
      add(version_);


      identity = new IssuerAndSerialNumber(cert);
      add(identity);

      // We now initialise the algorithm identifiers.
      // The style is PKCS#1 Version 2.1 Draft 1 with
      // the signature algorithm identifier in the
      // place of the digest algorithm identifier.

      if (params == null)
         throw new NoSuchAlgorithmException("Cannot resolve signature algorithm!");

      String digestAlgName = AlgorithmId.getDigAlgFromSigAlg(params.getAlgorithm());

      // Digest Algorithm Identifier
      dAlg_ = new AlgorithmIdentifier(AlgorithmId.lookup(digestAlgName));
      add(dAlg_);

      // Authenticated Attributes
      auth_ = new Attributes();
      add(new ASN1TaggedType(0, auth_, false, true));

      // Digest Encryption Algorithm Identifier
      cAlg_ = new AlgorithmIdentifier(params);
      add(cAlg_);

      // Encrypted Digest
      edig_ = new ASN1OctetString();
      add(edig_);

      // Unauthenticated Attributes
      attr_ = new Attributes();
      add(new ASN1TaggedType(1, attr_, false, true));

      params_ = params;

   }
    */



   /**
    * This method updates the given Signature instance with the DER encoding
    * of the <code>authenticatedAttributes</code> file of the SignerInfo
    * structure if such attributes are given.
    *
    * @param sig The Signature instance to be updated.
    * @exception SignatureException if the signature
    *   instance is not properly initialised.
    */
   public void update(Signature sig)
      throws SignatureException
   {
      if (sig == null)
         throw new NullPointerException("Sig is null!");

      if (!auth.isEmpty()) {

         try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DEREncoder enc = new DEREncoder(bos);

            /* Because the authenticated attributes are
             * tagged IMPLICIT in version 1.5 we have to
             * set tagging to EXPLICIT during encoding.
             * Otherwise the identifier and length octets
             * would be missing in the encoding.
             */
            auth.setExplicit(true);
            auth.encode(enc);

            sig.update(bos.toByteArray());

            enc.close();
         } catch (IOException e) {
            throw new IllegalStateException(e.getMessage());
         } finally {
            /* No matter what happens, in order to
             * maintain the consistency of the internal
             * structure we have to set the tagging of
             * the authenticated attributes back to
             * IMPLICIT.
             */
            auth.setExplicit(false);
         }
      }
   }



   /**
    * This method sets the encrypted digest.
    *
    * @param edig The encrypted digest.
    */
   public void setEncryptedDigest(byte[] edig)
   {
      this.edig = new ASN1OctetString(edig);
      set(5, this.edig);
   }


   /**
    * This method returns the encrypted digest stored in this structure. The EncryptedDigest is
    * defined as
    * <pre>
    * EncryptedDigest ::= OCTET STRING
    * </pre>
    * This octet string contains the encrypted digest info structure, which is reproduced below
    * for completeness:
    * <pre>
    * DigestInfo ::= SEQUENCE {
    *   digestAlgorithm DigestAlgorithmIdentifier,
    *   digest Digest
    * }
    *
    * Digest ::= OCTET STRING
    * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
    * </pre>
    *
    * @return The encrypted digest.
    */
   public byte[] getEncryptedDigest()
   {
      return edig.getByteArray();
   }



   /**
    * Returns the authenticated attributes.
    *
    * @return The unmodifiable list of authenticated attributes.
    */
   public Attributes authenticatedAttributes()
   {
      return auth;
   }


   /**
    * Adds the given {@link Attribute} to the list of authenticated attributes. This method
    * should be used to add attributes because it clears the attributes instance's
    * <code>OPTIONAL</code> flag. Alternatively, this can be done manually.
    *
    * @param attr The attribute.
    */
   public void addAuthenticatedAttribute(Attribute attr)
   {
      if (attr == null) throw new NullPointerException("Need an attribute!");
      auth.addAttribute(attr);
   }



   /**
    * Returns the unauthenticated attributes.
    *
    * @return The unmodifiable list of unauthenticated attributes.
    */
   public Attributes unauthenticatedAttributes()
   {
      return attr;
   }


   /**
    * Adds the given {@link Attribute} to the list of unauthenticated attributes. This method
    * should be used to add attributes because it clears the attributes instance's
    * <code>OPTIONAL</code> flag. Alternatively, this can be done manually.
    *
    * @param attr The attribute.
    */
   public void addUnauthenticatedAttribute(Attribute attr)
   {
      if (attr == null) throw new NullPointerException("Need an attribute!");
      this.attr.addAttribute(attr);
   }


   /**
    * Returns the {@link X500Principal name} of the issuer of the certificate of this signer.
    *
    * @return The issuer name.
    */
   public X500Principal getIssuerDN()
   {
      return identity.getIssuerDN();
   }


   /**
    *
    * @return The serial number.
    */
   public BigInteger getSerialNumber()
   {
      return identity.getSerialNumber();
   }


   /**
    * This method returns the DigestAlgorithmIdentifier.
    *
    * @return The DigestAlgorithmIdentifier.
    */
   public AlgorithmIdentifier getDigestAlgorithmIdentifier()
   {
      return dAlg;
   }


   /**
    * This method returns the DigestEncryptionAlgorithmIdentifier.
    *
    * @return The DigestEncryptionAlgorithmIdentifier.
    */
   public AlgorithmIdentifier getDigestEncryptionAlgorithmIdentifier()
   {
      return cAlg;
   }




   /**
    * Returns the algorithm parameter spec for the parameters of the signature algorithm
    * (PKCS#1 Version 2.1 Draft 1) or <code>null</code> if there are none.
    *
    * @return The AlgorithmParameterSpec to use when initialising the signature engine.
    * @exception NoSuchAlgorithmException if the OIDs in this structure cannot be mapped
    *    onto an algorithm name by means of the alias definitions of the installed
    *    providers.
    * @exception InvalidAlgorithmParameterException if the signature algorithm identifier
    *    contains parameters but the parameters cannot be decoded.
    *
    *   TODO When I rework the constructor
    *
   public AlgorithmParameters getParameters()
   {
      return params_;
   }
    */




   /**
    * Checks if this <code>SignerInfo</code> has an issuer distinguished name and a serial
    * number that are equivalent to those in the given certificate.
    *
    * @param cert The certificate to compare to.
    * @return <code>true</code> if this <code>SignerInfo</code> matches the given
    *    certificate.
    */
   public boolean equivalent(X509Certificate cert)
   {
      return identity.equivalent(cert);
   }


   /**
    * Returns a string representation of this object.
    *
    * @return The string representation.
    */
   public String toString()
   {
      String alg;

      try {
         alg = AlgorithmId.lookup(cAlg.getAlgorithmOID());
      } catch (Exception e) {
         alg = "<unknown> - " + cAlg.getAlgorithmOID();
      }
      StringBuffer buf = new StringBuffer();
      buf.append(
         "PKCS#7 SignerInfo {\n" +
         "Version   : " + version.toString() + "\n" +
         "Issuer    : " + identity.getIssuerDN() + "\n" +
         "Serial    : " + identity.getSerialNumber().toString() + "\n" +
         "Algorithm : " + alg + "\n" +
         "Auth A    : " + auth.size() + " elements\n" +
         "Unauth A  : " + attr.size() + " elements\n" +
         "Signature : " + edig.toString() + "\n");

      if (!auth.isEmpty()) {
         buf.append("\n")
            .append(auth);
      }
      buf.append("}");

      return buf.toString();
   }


   /**
    * Encodes this <code>SignerInfo</code>.
    *
    * @param encoder The encoder to use.
    */
   public void encode(Encoder encoder)
      throws IOException
   {
      ASN1Type t = get(3);
      t.setOptional(auth.isEmpty());

      t = get(6);
      t.setOptional(attr.isEmpty());

      super.encode(encoder);
   }


}

