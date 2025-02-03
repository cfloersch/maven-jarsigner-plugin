/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/1/2025
 */
package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.ASN1Integer;
import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.ASN1OctetString;
import org.xpertss.crypto.asn1.ASN1RegisteredType;
import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.asn1.ASN1Type;
import org.xpertss.crypto.pkcs.AlgorithmId;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.security.NoSuchAlgorithmException;

/**
 * Each PKCS#7 content type is associated with a specific object identifier, derived from:
 * <pre>
 *  pkcs-7 OBJECT IDENTIFIER ::=
 *    { iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) 7 }
 * </pre>
 * The object identifier for the DigestedData content type is defined as:
 * <p/>
 * digestedData OBJECT IDENTIFIER ::= { pkcs-7 5 }
 * <p/>
 * which corresponds to the OID string "1.2.840.1.113549.1.7.5".
 * <p/>
 * The PKCS#7 Cryptographic Message Standard specifies the DigestedData content type for
 * providing a syntax for building message digests. The digested-data content type consists
 * of content of any type and a message digest of the content (Version 1.5):
 * <pre>
 *     DigestedData ::= SEQUENCE {
 *     version            Version,
 *     digestAlgorithm    DigestAlgorithmIdentifier,
 *     contentInfo        ContentInfo,
 *     digest             Digest }
 *
 *      Digest ::= OCTET STRING
 * </pre>
 * The digestAlgorithm field specifies the digest algorithm to be used for computing the message
 * digest of the content given in the contentInfo field. The result of the digest calculation
 * is stored in the digest field. Verifying a received message digest is done by comparing it
 * with an independently computed message digest.
 */
public class DigestedData extends ASN1Sequence implements ASN1RegisteredType {


   /**
    * The OID of this structure. PKCS#7 SignedData.
    */
    static final int[] OID = {1, 2, 840, 113549, 1, 7, 5};

   protected AlgorithmIdentifier digestAlg;

   /**
    * The {@link ContentInfo ContentInfo}.
    */
   protected ContentInfo content;

   /**
    * The encrypted digest.
    */
   protected ASN1OctetString digest;


   /**
    * The digested-data content type consists of content of any type and a message digest of
    * the content.
    */
   public DigestedData()
   {
      super(4);

      add(new ASN1Integer(0)); // version

      digestAlg = new AlgorithmIdentifier();
      add(digestAlg);

      content = new ContentInfo();
      add(content);

      digest = new ASN1OctetString();
      add(digest);
   }


   public DigestedData(String digestAlg, byte[] digest)
      throws NoSuchAlgorithmException
   {
      super(4);

      add(new ASN1Integer(0)); // version

      ASN1ObjectIdentifier oid = AlgorithmId.lookup(digestAlg);
      this.digestAlg = new AlgorithmIdentifier(oid);
      add(this.digestAlg);

      content = new ContentInfo();
      add(content);

      this.digest = new ASN1OctetString(digest);
      add(this.digest);
   }



   /**
    * Returns the OID of this structure. The returned OID is a copy, no side effects are
    * caused by modifying it.
    *
    * @return The OID.
    */
   public ASN1ObjectIdentifier getOID()
   {
      return new ASN1ObjectIdentifier(OID);
   }




   /**
    * This method retrieves the content of this structure, consisting of the ASN.1
    * type embedded in the {@link #content ContentInfo} structure. Beware, the
    * content type might be faked by adversaries, if it is not of type {@link Data}.
    * If it is not data then the authenticated content type must be given as an
    * authenticated attribute in all the {@link SignerInfo} structures.
    *
    * @return The contents octets.
    */
   public ASN1Type getContent()
   {
      return content.getContent();
   }


   /**
    * Sets the content type to the given OID. The content itself is set to {@code null}.
    * This method should be called if the content to be signed is external (not inserted
    * into this structure).
    *
    * @param oid The OID that identifies the content type of the digested data.
    * @exception NullPointerException if <code>oid</code> is <code>null</code>.
    */
   public void setContentType(ASN1ObjectIdentifier oid)
   {
      if (oid == null) throw new NullPointerException("OID");
      content.setContent(oid);
   }


   /**
    * Sets the content to be embedded into this instance's {@code ContentInfo}.
    *
    * @param t The actual content.
    */
   public void setContent(ASN1RegisteredType t)
   {
      if (t == null) throw new NullPointerException("Need content!");
      content.setContent(t);
   }


   /**
    * Sets the content to be embedded into this instance's {@code ContentInfo}.
    *
    * @param oid The object identifier of the content.
    * @param t The actual content.
    */
   public void setContent(ASN1ObjectIdentifier oid, ASN1Type t)
   {
      if (oid == null || t == null)
         throw new NullPointerException("Need an OID and content!");
      content.setContent(oid, t);
   }


   /**
    * Returns the content type of the content embedded in this structure. The
    * returned OID is a copy, no side effects are caused by modifying it.
    *
    * @return The content type of this structure's payload.
    */
   public ASN1ObjectIdentifier getContentType()
   {
      return (ASN1ObjectIdentifier) content.getContentType().copy();
   }




   /**
    * This method returns the digest stored in this structure. The Digest is defined as
    * <pre>
    * Digest ::= OCTET STRING
    * </pre>
    * This octet string contains the digest info structure, which is reproduced below for
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
   public byte[] getDigest()
   {
      return digest.getByteArray();
   }

}
