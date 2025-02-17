package org.xpertss.crypto.pkcs.pkcs7;


import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * The signatures generated by this class are compatible to Sun's <code>jarsigner</code>.
 * The actual bytes being signed are denoted <i>payload</i> in this documenatation, in
 * order to differentiate between the signing of arbitrary (opaque) data and the DER
 * encoding of registered ASN.1 structures such as EnvelopedData.
 * <p/>
 * Presently, only content of type {@link Data Data} is supported. Either detached
 * signatures may be generated (in which case the content consists of a {@link Data Data}
 * type with no content) or the payload may be embedded into the content info of this
 * structure (automatically wrapped into a {@link Data Data} type.
 * <p/>
 * Use {@link SignerInfo SignerInfo} instances for signing and verifying instances of
 * this class such as illustrated in the code example below. This example shows how to
 * verify a detached signature on a file. One PKCS#7 structure may contain multiple
 * signatures. In the example given below, all of them are verified.
 * <p/>
 * The definition of this structure is:
 * <blockquote><pre>
 * SignedData ::= SEQUENCE {
 *   version Version,
 *   digestAlgorithms DigestAlgorithmIdentifiers,
 *   contentInfo ContentInfo,
 *   certificates
 *     [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *   crls
 *     [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *   signerInfos SignerInfos
 * }
 *
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *
 * SignerInfos ::= SET OF SignerInfo
 * </pre></blockquote>
 * <p/>
 * Please note that <code>SignerInfo</code> structures only store the issuer and serial
 * number of the signing certificate but not the certificate itself. Neither are
 * certificates added automatically by this class when signing is done. If a certificate
 * shall be included with an instance of this class then it must be added explicitly by
 * calling <code>addCertificate(..)</code>.
 */
public class SignedData extends ASN1Sequence implements ASN1RegisteredType {
   /**
    * The OID of this structure. PKCS#7 SignedData.
    */
   static final int[] OID = {1, 2, 840, 113549, 1, 7, 2};


   /**
    * The DigestAlgorithmIdentifiers.
    */
   protected ASN1Set digestIDs;

   /**
    * The X.509 certificates.
    */
   protected Certificates certs;

   /**
    * The {@link SignerInfo SignerInfos}.
    */
   protected ASN1SetOf infos;

   /**
    * The revocation lists.
    */
   protected ASN1Set crls;

   /**
    * The {@link ContentInfo ContentInfo}.
    */
   protected ContentInfo content;



   /**
    * Creates an instance ready for decoding.
    */
   public SignedData()
   {
      super(6);

      add(new ASN1Integer(1)); // version

      digestIDs = new ASN1SetOf(AlgorithmIdentifier.class);
      add(digestIDs);

      content = new ContentInfo();
      add(content);

      certs = new Certificates();
      add(new ASN1TaggedType(0, certs, false, true));

      crls = new ASN1SetOf(ASN1Opaque.class);
      add(new ASN1TaggedType(1, crls, false, true));

      infos = new ASN1SetOf(SignerInfo.class);
      add(infos);
   }




   /**
    * Returns the OID of this structure. The returned OID is a copy, no side effects are caused
    * by modifying it.
    *
    * @return The OID.
    */
   public ASN1ObjectIdentifier getOID()
   {
      return new ASN1ObjectIdentifier(OID);
   }








   /**
    * This method retrieves the content of this structure, consisting of the ASN.1 type
    * embedded in the {@link ContentInfo} structure. Beware, the content type might be faked
    * by adversaries, if it is not of type {@link Data}. If it is not data then the
    * authenticated content type must be given as an authenticated attribute in all the
    * {@link SignerInfo} structures.
    *
    * @return The contents octets.
    */
   public ASN1Type getContent()
   {
      return content.getContent();
   }


   /**
    * Sets the content type to the given OID. The content itself is set to <code>null</code>.
    * This method should be called if the content to be signed is external (not inserted
    * into this structure).
    * <p/>
    * If this structure is signed with the {@link Signer} then the {@link SignerInfo} that is
    * passed to it must have either:
    * <ul>
    * <li> no authenticated content type attribute, or
    * <li> the authenticated content type attribute must match <code>oid</code>.
    * </ul>
    * In the first case, a new authenticated content type attribute with <code>oid</code> as
    * its value will be added to the <code>SignerInfo</code> automatically (if the content type
    * is not {@link Data} or at least one other authenticated attribute is already in that
    * <code>SignerInfo</code>.
    *
    * @param oid The OID that identifies the content type of the signed data.
    * @exception NullPointerException if <code>oid</code> is <code>null</code>.
    */
   public void setContentType(ASN1ObjectIdentifier oid)
   {
      if (oid == null) throw new NullPointerException("OID");
      content.setContent(oid);
   }


   /**
    * Sets the content to be embedded into this instance's <code>ContentInfo</code>.
    *
    * @param t The actual content.
    */
   public void setContent(ASN1RegisteredType t)
   {
      if (t == null) throw new NullPointerException("Need content!");
      content.setContent(t);
   }


   /**
    * Sets the content to be embedded into this instance's <code>ContentInfo</code>.
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
    * Returns the content type of the content embedded in this structure. The returned OID is a
    * copy, no side effects are caused by modifying it.
    *
    * @return The content type of this structure's payload.
    */
   public ASN1ObjectIdentifier getContentType()
   {
      return (ASN1ObjectIdentifier) content.getContentType().copy();
   }












   /**
    * Returns the certificate with the given issuer and serial number if one exists of {@code
    * null} if it does not exist.
    *
    * @param issuer The issuer of the certificate
    * @param serial The serial number of the desired certificate
    */
   public X509Certificate getCertificate(X500Principal issuer, BigInteger serial)
   {
      return certs.getCertificate(issuer, serial);
   }

   public X509Certificate getCertificate(SignerInfo signer)
   {
      return certs.getCertificate(signer.getIssuerDN(), signer.getSerialNumber());
   }

   /**
    * This will return the certificate chain with the signer cert first followed by the
    * remainder of the chain. This will return {@code null} if a certificate with the
    * given issuer and serial number is not found.
    *
    * @param issuer The issuer of the subject certificate
    * @param serial The serial number of the subject certificate
    */
   public List<X509Certificate> getCertificates(X500Principal issuer, BigInteger serial)
   {
      return certs.getCertificates(issuer, serial);
   }

   public List<X509Certificate> getCertificates(SignerInfo signer)
   {
      /*
        NOTE: Certificate Paths are Forward based (Subject -> Trust Anchor) or
            Reverse (Trust Anchor -> Subject).
        Since Sun's PKIX CertPath validation generally operates in the FORWARD direction
            I always return my chains in this ordering. But in PKCS7 they are stored in
            REVERSE ordering. PKIXCertPathChecker's MUST support reverse but forward is
            preferred
       */
      return certs.getCertificates(signer.getIssuerDN(), signer.getSerialNumber());
   }

   /**
    * Returns all certificates in this collection as an unmodifiable List. This returns
    * the certificates ordered from trust root to end-entity which is the ordering PKCS7
    * maintains them.
    */
   public List<X509Certificate> getCertificates()
   {
      return certs.getCertificates();
   }









   /**
    * This method returns the {@link SignerInfo} of the signers of this structure.
    *
    * @return The unmodifiable view of the list of SignerInfos.
    */
   public List<SignerInfo> getSignerInfos()
   {
      return (List<SignerInfo>) infos.getValue();
   }


   /**
    * Returns the <code>SignerInfo</code> that matches the given certificate.
    *
    * @param cert The certificate matching the <code>SignerInfo </code> to be retrieved.
    * @return The <code>SignerInfo</code> or <code>null</code> if no matching one is found.
    */
   public SignerInfo getSignerInfo(X509Certificate cert)
   {
      for (Iterator i = getSignerInfos().iterator(); i.hasNext();) {
         SignerInfo info = (SignerInfo) i.next();
         if (!info.getIssuerDN().equals(cert.getIssuerDN())) continue;
         if (info.getSerialNumber().equals(cert.getSerialNumber())) return info;
      }
      return null;
   }




   /**
    * Creates, adds, and returns a new {@link SignerInfo} initialized with the given X509
    * certificate chain and signature algorithm. It adds the certificate chain to this
    * SignedData utilizing the first element to initialize the SignerInfo that is added and
    * returned.
    * <p/>
    * A CertChain holds its chain in forward order where the signer cert is first and the most
    * trusted cert is last.
    *
    *
    * @param algorithm The signature algorithm being used to do the signing
    * @param certChain The certificate chain identifying the signer
    * @return The SignerInfo initialized by signer certificate and algorithm
    * @throws NoSuchAlgorithmException If the specified algorithm is not found in this system
    */
   public SignerInfo newSigner(String algorithm, X509Certificate ... certChain)
      throws NoSuchAlgorithmException
   {
      Optional<X509Certificate> first = Arrays.stream(certChain).findFirst();
      SignerInfo signerInfo = new SignerInfo(first.get(), algorithm);
      addSignerInfo(signerInfo);
      certs.addCertChain(certChain);
      get(3).setOptional(false);
      return signerInfo;
   }





   /**
    * Adds the given {@link SignerInfo} to this instance. This method should be used rarely. In
    * general, the signing methods take care of adding <code>SignerInfo</code> instances.
    * Explicit adding of a <code>SignerInfo</code> is provided only in those cases where fine
    * control of the creation of signatures is required.
    *
    * @param info The <code>SignerInfo</code> to add.
    * @exception NullPointerException if the <code>info</code> is <code>null</code>.
    */
   private void addSignerInfo(SignerInfo info)
   {
      Iterator i;

      if (info == null) throw new NullPointerException("Need a SignerInfo!");
      infos.add(info);

      /*
       * We also have to add the DigestAlgorithmIdentifier of the SignerInfo to the list of digest
       * algs if it is not yet in the list.
       */
      AlgorithmIdentifier idn = info.getDigestAlgorithmIdentifier();

      for (i = digestIDs.iterator(); i.hasNext();) {
         AlgorithmIdentifier idv = (AlgorithmIdentifier) i.next();
         if (idn.equals(idv)) return;
      }
      digestIDs.add(idn);
   }

   


   /**
    * Returns a string representation of this object.
    *
    * @return The string representation.
    */
   public String toString()
   {
      return "-- PKCS#7 SignedData --\n" + super.toString();
   }


}


