package org.xpertss.crypto.pkcs.pkcs7;


import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.pkcs.pkcs9.Attributes;
import org.xpertss.crypto.pkcs.pkcs9.Attribute;
import org.xpertss.crypto.x509.Name;
import org.xpertss.crypto.x509.BadNameException;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
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
 * It seems that this spec views the digesting and encryption of that digest as
 * separate operations where as Java's Signature class views them as one in the
 * same.
 */
public class SignerInfo extends ASN1Sequence {
   /**
    * The version number of this SignerInfo.
    */
   protected ASN1Integer version_;

   /**
    * The issuer name. Still of type ANY but being
    * replaced by RDName soon.
    */
   protected Name issuer_;

   /**
    * The serial number.
    */
   protected ASN1Integer serial_;

   /**
    * The {@link AlgorithmIdentifier DigestAlgorithmIdentifier}.
    */
   protected AlgorithmIdentifier dAlg_;

   /**
    * The {@link AlgorithmIdentifier DigestEncryptionAlgorithmIdentifier}.
    */
   protected AlgorithmIdentifier cAlg_;

   /**
    * The authenticated attributes.
    */
   protected Attributes auth_;

   /**
    * The unauthenticated attributes.
    */
   protected Attributes attr_;

   /**
    * The encrypted digest.
    */
   protected ASN1OctetString edig_;


   /**
    * The signature algorithm parameters spec to use when verifying
    * or signing {@link SignedData SignedData} instances.
    */
   protected AlgorithmParameters params_;


   /**
    * Creates an instance ready for decoding.
    */
   public SignerInfo()
   {
      super(7);

      /* Global structure and Version */
      version_ = new ASN1Integer(1);
      add(version_);

      /* Issuer and serial number */
      issuer_ = new Name();
      serial_ = new ASN1Integer();

      ASN1Sequence seq = new ASN1Sequence(2);
      seq.add(issuer_);
      seq.add(serial_);

      add(seq);

      /* Digest Algorithm Identifier */
      dAlg_ = new AlgorithmIdentifier();
      add(dAlg_);

      /* Authenticated Attributes */
      auth_ = new Attributes();
      add(new ASN1TaggedType(0, auth_, false, true));

      /* Digest Encryption Algorithm Identifier */
      cAlg_ = new AlgorithmIdentifier();
      add(cAlg_);

      /* Encrypted Digest */
      edig_ = new ASN1OctetString();
      add(edig_);

      /* Unauthenticated Attributes */
      attr_ = new Attributes();
      add(new ASN1TaggedType(1, attr_, false, true));
   }


   /**
    * Creates an instance ready for decoding. The given registry is used to
    * resolve attributes.
    *
    * @param registry The <code>OIDRegistry</code> to use for resolving
    *                 attributes, or <code>null</code> if the default
    *                 PKCS registry shall be used.
    */
   public SignerInfo(OIDRegistry registry)
   {
      super(7);

      /* Global structure and Version */
      version_ = new ASN1Integer(1);
      add(version_);

      /* Issuer and serial number */
      issuer_ = new Name();
      serial_ = new ASN1Integer();

      ASN1Sequence seq = new ASN1Sequence(2);
      seq.add(issuer_);
      seq.add(serial_);

      add(seq);

      /* Digest Algorithm Identifier */
      dAlg_ = new AlgorithmIdentifier();
      add(dAlg_);

      /* Authenticated Attributes */
      auth_ = new Attributes(registry);
      add(new ASN1TaggedType(0, auth_, false, true));

      /* Digest Encryption Algorithm Identifier */
      cAlg_ = new AlgorithmIdentifier();
      add(cAlg_);

      /* Encrypted Digest */
      edig_ = new ASN1OctetString();
      add(edig_);

      /* Unauthenticated Attributes */
      attr_ = new Attributes(registry);
      add(new ASN1TaggedType(1, attr_, false, true));
   }


   /**
    * This method calls initialises this structure with the given arguments.
    * This constructor creates Version 1 SignerInfos. The given algorithm
    * must be a PKCS#1 Version 1.5 conformant signature algorithm. In other
    * words, the signature algorithm MUST NOT have algorithm parameters
    * beyond those embedded in the
    * {@link SubjectPublicKeyInfo SubjectPublicKeyInfo} of the public key,
    * and aliases for a slashed name form MUST be defined by JSPs (Java
    * Security Providers). JSPs also MUST define OID aliases for the
    * signature's raw cipher and the message digest.
    * <p>
    * If PKCS#1 version 2.1 Draft 1 signatures (RSASSA-PSS) shall be used
    * then the constructor taking algorithm parameters must be called instead
    * of this one.
    *
    * @param cert The signer's certificate.
    * @param algorithm The JCA standard name of the PKCS#1
    *   version 1.5 compliant signature algorithm.
    * @exception NoSuchAlgorithmException if the signature algorithm
    *   name cannot be resolved to the OIDs of the names of its raw
    *   cipher algorithm and its digest algorithm.
    * @exception BadNameException if the issuer name in the
    *   given certificate cannot be parsed.
    * @exception IllegalArgumentException if the OID to which
    *   the given algorithm name is mapped by means of the
    *   aliases of the installed providers is not a valid
    *   OID string.
    */
   public SignerInfo(X509Certificate cert, String algorithm)
      throws BadNameException, NoSuchAlgorithmException
   {
      super(7);

      String d;

      /* Global structure and Version */
      version_ = new ASN1Integer(1);
      add(version_);

      /* Issuer and serial number */
      issuer_ = new Name(cert.getIssuerDN().getName());
      serial_ = new ASN1Integer(cert.getSerialNumber());

      ASN1Sequence seq = new ASN1Sequence(2);
      seq.add(issuer_);
      seq.add(serial_);

      add(seq);

      /* We now initialise the algorithm identifiers.
       * The style is according to PKCS#1 Version 1.5,
       * no parameters for the signature algorithm.
       * Parameters are encoded as ASN1Null.
       */
      d = JCA.getDigestOID(algorithm);
      if (d == null)
         throw new NoSuchAlgorithmException("Cannot resolve signature algorithm!");
      try {
         dAlg_ = new AlgorithmIdentifier(new ASN1ObjectIdentifier(d), new ASN1Null());
         cAlg_ = new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm), new ASN1Null());
      } catch (IOException e) {
         throw new IllegalStateException(e.getMessage());
      }
      /* Digest Algorithm Identifier */
      add(dAlg_);

      /* Authenticated Attributes */
      auth_ = new Attributes();
      add(new ASN1TaggedType(0, auth_, false, true));

      /* Digest Encryption Algorithm Identifier */
      add(cAlg_);

      /* Encrypted Digest */
      edig_ = new ASN1OctetString();
      add(edig_);

      /* Unauthenticated Attributes */
      attr_ = new Attributes();
      add(new ASN1TaggedType(1, attr_, false, true));
   }


   /**
    * This method calls initialises this structure with
    * the given arguments. This constructore creates
    * Version 1 SignerInfos. The given algorithm must be
    * a PKCS#1 Version 2.1 Draft 1 conformant signature algorithm.
    * The signature algorithm identifier is put into the place of
    * the digest algorithm identifier. The given parameters are
    * those of the signature algorithm (e. g. RSASSA-PSS). If the
    * parameters are <code>null</code> then they are encoded as
    * {@link ASN1Null ASN1Null}. The signature algorithm identifier
    * is also put into the place of the digest encryption algorithm
    * identifier (without parameters). PKCS#1 Version 2.1 Draft 1
    * does not specify how this case should be handled so we picked
    * our choice.
    *
    * @param cert The signer's certificate.
    * @param algorithm The JCA standard name of the PKCS#1
    *   Version 2.1 Draft 1 compliant signature algorithm.
    * @exception NoSuchAlgorithmException if the signature algorithm
    *   name cannot be resolved to the OIDs of the names of its raw
    *   cipher algorithm and its digest algorithm.
    * @exception BadNameException if the issuer name in the given
    *   certificate cannot be parsed.
    */
   public SignerInfo(X509Certificate cert, AlgorithmParameters params)
      throws BadNameException, NoSuchAlgorithmException
   {
      super(7);

      /* Global structure and Version */
      version_ = new ASN1Integer(1);
      add(version_);

      /* Issuer and serial number */
      issuer_ = new Name(cert.getIssuerDN().getName());
      serial_ = new ASN1Integer(cert.getSerialNumber());

      ASN1Sequence seq = new ASN1Sequence(2);
      seq.add(issuer_);
      seq.add(serial_);

      add(seq);

      /* We now initialise the algorithm identifiers.
       * The style is PKCS#1 Version 2.1 Draft 1 with
       * the signature algorithm identifier in the
       * place of the digest algorithm identifier.
       */
      if (params == null)
         throw new NoSuchAlgorithmException("Cannot resolve signature algorithm!");
      // TODO: Need to figure out how to get digest alg.
      dAlg_ = new AlgorithmIdentifier(params);
      cAlg_ = new AlgorithmIdentifier(params);

      /* Digest Algorithm Identifier */
      add(dAlg_);

      /* Authenticated Attributes */
      auth_ = new Attributes();
      add(new ASN1TaggedType(0, auth_, false, true));

      /* Digest Encryption Algorithm Identifier */
      add(cAlg_);

      /* Encrypted Digest */
      edig_ = new ASN1OctetString();
      add(edig_);

      /* Unauthenticated Attributes */
      attr_ = new Attributes();
      add(new ASN1TaggedType(1, attr_, false, true));

      params_ = params;

   }



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

      if (!auth_.isEmpty()) {

         try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DEREncoder enc = new DEREncoder(bos);

            /* Because the authenticated attributes are
             * tagged IMPLICIT in version 1.5 we have to
             * set tagging to EXPLICIT during encoding.
             * Otherwise the identifier and length octets
             * would be missing in the encoding.
             */
            auth_.setExplicit(true);
            auth_.encode(enc);

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
            auth_.setExplicit(false);
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
      edig_ = new ASN1OctetString(edig);
      set(5, edig_);
   }


   /**
    * This method returns the encrypted digest stored in
    * this structure. The EncryptedDigest is defined as
    * <pre>
    * EncryptedDigest ::= OCTET STRING
    * </pre>
    * This octet string contains the encrypted digest
    * info structure, which is reproduced below for
    * completeness:
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
      return edig_.getByteArray();
   }



   /**
    * Returns the authenticated attributes.
    *
    * @return The unmodifiable list of authenticated attributes.
    */
   public Attributes authenticatedAttributes()
   {
      return auth_;
   }


   /**
    * Adds the given {@link Attribute attribute} to the list of
    * authenticated attributes. This method should be used to
    * add attributes because it clears the attributes instance's
    * <code>OPTIONAL</code> flag. Alternatively, this can be done
    * manually.
    *
    * @param attr The attribute.
    */
   public void addAuthenticatedAttribute(Attribute attr)
   {
      if (attr == null)
         throw new NullPointerException("Need an attribute!");

      auth_.add(attr);
   }



   /**
    * Returns the unauthenticated attributes.
    *
    * @return The unmodifiable list of unauthenticated attributes.
    */
   public Attributes unauthenticatedAttributes()
   {
      return attr_;
   }


   /**
    * Adds the given {@link Attribute attribute} to the list of
    * unauthenticated attributes. This method should be used to
    * add attributes because it clears the attributes instance's
    * <code>OPTIONAL</code> flag. Alternatively, this can be done
    * manually.
    *
    * @param attr The attribute.
    */
   public void addUnauthenticatedAttribute(Attribute attr)
   {
      if (attr == null)
         throw new NullPointerException("Need an attribute!");

      attr_.add(attr);
   }


   /**
    * Returns the {@link X500Principal name} of the issuer of the certificate of this
    * signer.
    *
    * @return The issuer name.
    */
   public X500Principal getIssuerDN()
   {
      return issuer_;
   }


   /**
    *
    * @return The serial number.
    */
   public BigInteger getSerialNumber()
   {
      return serial_.getBigInteger();
   }


   /**
    * This method returns the DigestAlgorithmIdentifier.
    *
    * @return The DigestAlgorithmIdentifier.
    */
   public AlgorithmIdentifier getDigestAlgorithmIdentifier()
   {
      return dAlg_;
   }


   /**
    * Returns the name of the signature algorithm. This
    * method calls {@link #init init()} if the name is not
    * yet known in order to determine it by means of the {@link
    * JCA JCA} and the {@link AlgorithmIdentifier algorithm
    * identifiers} embedded in this structure.
    *
    * @return The algorithm name.
    * @exception NoSuchAlgorithmException if the OIDs in this
    *   structure cannot be mapped onto an algorithm name by
    *   means of the alias definitions of the installed providers.
    * @exception InvalidAlgorithmParameterException if the
    *   signature algorithm identifier contains parameters but
    *   the parameters cannot be decoded.
    */
   public String getAlgorithm()
      throws NoSuchAlgorithmException
   {
      if (algorithm_ == null) init();
      return algorithm_;
   }


   /**
    * Returns the algorithm parameter spec for the parameters
    * of the signature algorithm (PKCS#1 Version 2.1 Draft 1)
    * or <code>null</code> if there are none.
    *
    * @return The AlgorithmParameterSpec to use when initialising
    *   the signature engine.
    * @exception NoSuchAlgorithmException if the OIDs in this
    *   structure cannot be mapped onto an algorithm name by
    *   means of the alias definitions of the installed providers.
    * @exception InvalidAlgorithmParameterException if the
    *   signature algorithm identifier contains parameters but
    *   the parameters cannot be decoded.
    */
   public AlgorithmParameters getParameters()
   {
      if (params_ == null) init();
      return params_;
   }






   /**
    * This method determines the signature algorithm and
    * appropriate parameters for initialising the signature
    * algorithm from the algorithm identifiers in this
    * structure. PKCS#1 versions 1.5 and 2.1 Draft 1 are
    * supported.<p>
    *
    * We start by resolving the digest and cipher OIDs
    * against a signature algorithm name by means of the
    * {@link JCA JCA} class. This requires JSPs (Java Security
    * Providers) to support appropriate alias mappings. Both
    * OID mappings and slashed forms are required.<p>
    *
    * If this fails then we try to interpret the digest
    * algorithm identifier as the signature algorithm identifier.
    * If this still does not give us a valid signature engine
    * then we try the digest encryption algorithm identifier as
    * the signature algorithm identifier.<p>
    *
    * If the combined form led to the signature engine then
    * no parameters are set (apart from those in the public
    * key's {@link SubjectPublicKeyInfo SubjectPublicKeyInfo}.
    * If either the digest algorithm identifier or the digest
    * encryption algorithm identifier led to the signature
    * engine then the respective parameters are set for the
    * signature engine.<p>
    *
    * Parameters are set before the signature engine is
    * initialised with the public key. No hint is given in
    * the JDK documentation on which is to be done first.
    * So we picked our choice.<p>
    *
    * Parameter initialisation works only if the parameters
    * engine supports proper conversion of opaque parameter
    * representations into transparent representations
    * (AlgorithmParameterSpecs) by means of the
    * <code>getAlgorithmParameterSpec()</code> method. Hardly
    * any provider gets it right, at the time of writing not
    * even the Sun JSP does it correctly.
    *
    * TODO: Redo this whole method.
    *
    * @return The name of the signature algorithm that
    *   is required for verifying this structure.
    */
   protected void init()
      throws NoSuchAlgorithmException
   {

      String d = dAlg_.getAlgorithmOID().toString();
      String c = cAlg_.getAlgorithmOID().toString();
      String s = JCA.getSignatureName(d, c);


      if (s != null) {
         algorithm_ = s;
         return;
      }
      /* If we cannot resolve the combined digest/cipher
       * name to a signature alg name then we try the
       * digest algorithm identifier instead. This is
       * the recommended way as of PKCS#1 Version 2.1
       * Draft 1.
       */
      s = JCA.resolveAlias("Signature", d);

      if (s != null) {
         algorithm_ = s;
         params = dAlg_.getParameters();
      } else {
         /* If we cannot get an instance by ordinary
          * means then we try the cipher algorithm
          * identifier as a last resort. This is not
          * standard however.
          */
         s = JCA.resolveAlias("Signature", c);

         if (s != null) {
            algorithm_ = s;
            params_ = cAlg_.getParameters();
         } else {
            throw new NoSuchAlgorithmException("Cannot resolve OIDs!");
         }
      }
   }




   /**
    * Checks if this <code>SignerInfo</code> has an issuer
    * distinguished name and a serial number that are equivalent
    * to those in the given certificate.
    *
    * @param cert The certificate to compare to.
    * @return <code>true</code> if this <code>SignerInfo
    *   </code> matches the given certificate.
    */
   public boolean equivIssuerAndSerialNumber(X509Certificate cert)
   {
      if (cert == null)
         throw new NullPointerException("Need a cert!");
      if (!issuer_.equals(cert.getIssuerDN())) return false;
      return serial_.getBigInteger().equals(cert.getSerialNumber());
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
         alg = getAlgorithm();
      } catch (Exception e) {
         alg = "<unknown>";
      }
      StringBuffer buf = new StringBuffer();
      buf.append(
         "PKCS#7 SignerInfo {\n" +
         "Version   : " + version_.toString() + "\n" +
         "Issuer    : " + issuer_.getName() + "\n" +
         "Serial    : " + serial_.toString() + "\n" +
         "Algorithm : " + alg + "\n" +
         "Auth A    : " + auth_.size() + " elements\n" +
         "Unauth A  : " + attr_.size() + " elements\n" +
         "Signature : " + edig_.toString() + "\n");

      if (!auth_.isEmpty()) {
         buf.append("\n")
            .append(auth_);
      }
      buf.append("}\n");

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
      t.setOptional(auth_.isEmpty());

      t = get(6);
      t.setOptional(attr_.isEmpty());

      super.encode(encoder);
   }

}

