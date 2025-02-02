package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.pkcs9.Attribute;
import org.xpertss.crypto.pkcs.pkcs9.Attributes;
import org.xpertss.crypto.pkcs.pkcs9.NoSuchAttributeException;
import org.xpertss.crypto.pkcs.pkcs9.InvalidAttributeException;

import java.io.*;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

/**
 * Verifies a given <code>SignedData</code> object.
 */
public class Verifier extends Object {
   /**
    * The OID of PKCS#7 Data
    */
   private ASN1ObjectIdentifier DATA = new ASN1ObjectIdentifier(
               new int[]{1, 2, 840, 113549, 1, 7, 1});

   /**
    * The OID of PKCS#9 MessageDigest Attribute
    */
   private ASN1ObjectIdentifier MESSAGE_DIGEST = new ASN1ObjectIdentifier(
               new int[]{1, 2, 840, 113549, 1, 9, 4});

   /**
    * The OID of PKCS#9 ContentType Attribute
    */
   private ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier(
               new int[]{1, 2, 840, 113549, 1, 9, 3});

   /**
    * The size of the buffer allocated for reading and
    * verifying data in case this is a detached signature
    * file.
    */
   public static final int BUFFER_SIZE = 1024;

   /**
    * The <code>SignedData</code> that is verified.
    */
   protected Signable target_;

   /**
    * The signature engine that is used to verify
    * signatures.
    */
   private Signature sig_;

   /**
    * The message digest engine that is used while
    * verification is in progress. The digest engine is
    * used only in the presence of authenticated attributes.
    */
   protected MessageDigest digest_;

   /**
    * The certificate of the signer whose signature verification
    * is in progress.
    */
   protected X509Certificate cert_;

   /**
    * The {@link SignerInfo SignerInfo} of the signer whose
    * signature verification is in progress.
    */
   protected SignerInfo info_;

   /**
    * The PKCS#9 MessageDigest Attribute value when
    * verifying in two-step mode.
    */
   protected byte[] md_;

   /**
    * <code>true</code> if verification is done with authenticated
    * attributes.
    */
   protected boolean twostep_ = false;


   /**
    * Creates an instance ready for signature verification.
    * Either the <code>SignerInfo</code> or the certificate
    * must be given. If either one is <code>null</code> then
    * the missing part is retrieved from the given <code>
    * SignedData</code>. If not both values can be established
    * then an exception is raised.
    * <p>
    *
    * All declared exception are of type <code>
    * CryptoException</code> and can be catched
    * by declaring the latter. In case fine-grained control
    * is required, one of the exception described below can
    * be caught.
    *
    * @param sigdat The <code>Signable</code> instance that
    *   is verified.
    * @param info The <code>SignerInfo</code> whose signature
    *   shall be verified, or <code>null</code> if it shall be
    *   retrieved from <code>sigdat</code> automatically by
    *   means of the given certificate.
    * @param cert The certificate of the signer or <code>null
    *   </code> if it shall be retrieved from <code>sigdat
    *   </code> automatically by means of <code>info</code>.
    *
    * @exception NoSuchAlgorithmException if some required
    *   algorithm implementation cannot be found.
    * @exception InvalidAlgorithmParameterException if some
    *   parameters do not match the required algorithms.
    * @exception InvalidKeyException if the public key does
    *   not match the signature algorithm.
    * @exception NoSuchSignerException if no <code>SignerInfo
    *   </code> was given and no matching the given certificate
    *   was found in the corresponding <code>SignedData</code>.
    * @exception CertificateException if no certificate was
    *   given and no certificate matching the given <code>
    *   SignerInfo</code> was found in the corresponding <code>
    *   SignedData</code>.
    * @exception IllegalArgumentException if no certificate and
    *   no <code>SignerInfo</code> was given, or the given
    *   <code>SignerInfo</code> and certificate do not have
    *   equivalent issuer distinguished names and serial
    *   numbers.
    * @exception NoSuchAttributeException if a required PKCS#9
    *   attribute was not found in the given <code>SignerInfo
    *   </code>.
    * @exception InvalidAttributeException if the PKCS#9
    *   ContentType attribute in the given <code>SignerInfo
    *   </code> does not match the content type of the
    *   corresponding <code>SignedData</code>.
    */
   public Verifier(Signable sigdat, SignerInfo info, X509Certificate cert)
      throws NoSuchSignerException, CertificateException, NoSuchAttributeException, InvalidAttributeException, NoSuchAlgorithmException
   {
      AlgorithmParameterSpec spec;
      ASN1OctetString octets;
      Attribute attribute;
      Signature sig;
      String mdalg;

      /* Either a certificate or a SignerInfo is needed.
       * We might do without one of'em but not without
       * both. The SignedData is need in every case.
       */
      if (info == null && cert == null)
         throw new IllegalArgumentException("Need either a SignerInfo or a certificate!");
      if (sigdat == null)
         throw new NullPointerException("Need a SignedData!");
      target_ = sigdat;

      /* If the SignerInfo is null then we try to get
       * it from the SignedData.
       */
      if (info == null) {
         info = target_.getSignerInfo(cert);

         if (info == null) {
            throw new NoSuchSignerException(
               "No signer info found for: "
               + cert.getIssuerDN().getName()
               + ", "
               + cert.getSerialNumber()
            );
         }
      }
      /* If we have a SignerInfo but no certificate the
       * we try and see if we can get it from the
       * SignedData.
       */
      else if (cert == null) {
         cert = target_.getCertificate(info.getIssuerDN(), info.getSerialNumber());

         if (cert == null) {
            throw new CertificateException(
               "No certificate available for: "
               + info.getIssuerDN().getName()
               + ", "
               + info.getSerialNumber()
            );
         }
      }
      /* We have both a SignerInfo and a certificate, now
       * let's see if they have matching issuer and serial
       * number.
       */
      else {
         if (!info.equivIssuerAndSerialNumber(cert))
            throw new IllegalArgumentException("SignerInfo and certificate don't match!");
      }
      /* At this point we should have both a SignerInfo
       * and a matching certificate.
       */
      info_ = info;
      cert_ = cert;
      String sigalg = info_.getAlgorithm();

      /* We now check for a simple one-step verification or
       * a two-step verification. One-step occurs only in
       * the degenerate case that the content type of the
       * SignedData instance is DATA and there are no
       * authenticated attributes in it.
       *
       * Otherwise we have to check painfully for the various
       * details on required attributes.
       */
      Attributes attributes = info_.authenticatedAttributes();
      ASN1ObjectIdentifier oid = target_.getContentType();

      if (attributes.size() > 0 || !oid.equals(DATA)) {
         twostep_ = true;

         Attribute attribute = info_.authenticatedAttributes().getAttribute(CONTENT_TYPE);

         if (attribute == null) {
            throw new NoSuchAttributeException("ContentType attribute missing!");
         }
         if (attribute.valueCount() == 0) {
            throw new InvalidAttributeException("ContentType attribute has no OID!");
         }
         if (!oid.equals(attribute.valueAt(0))) {
            throw new InvalidAttributeException("ContentType attribute mismatch!");
         }
         attribute = info_.authenticatedAttributes().getAttribute(MESSAGE_DIGEST);

         if (attribute == null) {
            throw new NoSuchAttributeException("MessageDigest attribute missing!");
         }
         if (attribute.valueCount() == 0) {
            throw new InvalidAttributeException("MessageDigest attribute has no data!");
         }
         ASN1OctetString octets = (ASN1OctetString) attribute.valueAt(0);
         md_ = octets.getByteArray();
         mdalg = JCA.getName(JCA.getDigestOID(sigalg));

         if (mdalg == null)
            throw new NoSuchAlgorithmException("Cannot determine digest algorithm for " + sigalg);
         digest_ = MessageDigest.getInstance(mdalg);
      }

      sig_ = Signature.getInstance(sigalg);
      AlgorithmParameters params = info_.getParameters();
      sig_.initVerify(cert_.getPublicKey(), params);
   }


   /**
    * Update operation for signing or verification. The given
    * input stream is not closed after completition of this
    * method.
    *
    * @param in The input data to be signed or verified.
    * @exception IOException if an I/O error occurs while
    *   reading from the given stream.
    * @exception SignatureException if this instance is
    *   not properly initialised.
    * @exception IOException if an I/O exception occurs
    *  while reading from the input stream.
    */
   public void update(InputStream in)
      throws SignatureException, IOException
   {
      int n;
      byte[] buf = new byte[BUFFER_SIZE];
      try {
         while ((n = in.read(buf)) > 0) {
            update(buf, 0, n);
         }
      } catch (IOException e) {
         reset();
         throw e;
      }
   }


   /**
    * Update operation. Updates the message digest or
    * signature computation with the content of the
    * <code>SignedData</code> specified at creation
    * time. If the <code>SignedData</code> has no content
    * then no updating takes place.<p>
    *
    * <b>Note:</b> updating must be done on the contents
    * octets of the content only, no identifier and length
    * octets are hashed or signed (Verison 1.5). Because
    * the contents are already decoded by the <code>
    * ContentInfo</code> we have to re-encode them according
    * to DER. Unfortunately we cannot tell how many identifier
    * and length octets we have to skip without decoding them
    * first. There is a trick, though. We can briefly modify
    * the tagging of the contents to IMPLICIT tagging while
    * encoding them. That way, the identifier and length
    * octets won't be encoded.<p>
    *
    * <b>Note:</b> Remember, the tagging will be changed
    * for re-encoding purposes. Custom content type instances
    * must support this (it's supported by default in all
    * <code>codec.asn1.&ast;</code> types).<p>
    *
    * If the content type is <code>Data</code> then there is
    * no problem because we can simply grab the contents
    * octets from it.
    */
   public void update()
      throws SignatureException
   {
      ASN1Type t = target_.getContent();

      if (t == null) return;
      if (t instanceof Data) {
         update(((Data) t).getByteArray());
         return;
      }

      /* We know it must be EXPLICIT but hey... */
      boolean tagging = t.isExplicit();
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      DEREncoder enc = new DEREncoder(bos);

      try {
         t.setExplicit(false);
         enc.writeType(t);

         update(bos.toByteArray());
      } catch (Exception e) {
         throw new SignatureException("Exception while re-encoding!");
      } finally {
         t.setExplicit(tagging);

         try {
            enc.close();
         } catch (Exception e) { }
      }
   }


   /**
    * Update operation.
    *
    * @param b The input bytes.
    */
   public void update(byte[] b)
      throws SignatureException
   {
      update(b, 0, b.length);
   }


   /**
    * Update operation.
    *
    * @param b The input bytes.
    * @param offset The offset into <code>b</code> at which the
    *   data to be signed starts.
    * @param len The number of bytes starting with <code>offset
    *   </code> to be signed.
    */
   public void update(byte[] b, int offset, int len)
      throws SignatureException
   {
      try {
         if (twostep_) {
            digest_.update(b, offset, len);
         } else {
            sig_.update(b, offset, len);
         }
      } catch (SignatureException e) {
         reset();
         throw e;
      }
   }


   /**
    * Resets this instance to a state before initialisation
    * for signing or verifying.
    */
   private void reset()
   {
      sig_ = null;
      cert_ = null;
      info_ = null;
      digest_ = null;
      target_ = null;
   }


   /**
    * Completes the verification. If the verification is
    * successful then the signer's certificate is returned.
    * This certificate can be either the one passed to the
    * constructor, or one found in the corresponding <code>
    * SignedData</code> instance if no certificate was
    * given initially.
    *
    * @return The certificate of the signer or <code>null
    *   </code> if the signature is not valid.
    * @exception SignatureException if something's wrong
    *   with the signature engine or the ciphers involved in
    *   the verification process.
    */
   public X509Certificate verify()
      throws SignatureException
   {
      byte[] b;

      if (twostep_) {
         b = digest_.digest();

         if (!Arrays.equals(b, md_)) {
            return null;
         }
         info_.update(sig_);
      }
      /* SignedAndEnvelopedData is treated specially, the signature
       * must be decrypted with the bulk encryption key. Before
       * signature verification, its must be initialized properly.
       */
      if (target_ instanceof SignedAndEnvelopedData) {
         SignedAndEnvelopedData saed = (SignedAndEnvelopedData) target_;
         byte[] edig = info_.getEncryptedDigest();
         b = saed.decryptBulkData(edig);
      } else {
         b = info_.getEncryptedDigest();
      }
      if (sig_.verify(b)) return cert_;
      return null;
   }

}
