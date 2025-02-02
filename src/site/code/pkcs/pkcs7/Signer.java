package org.xpertss.crypto.pkcs.pkcs7;


import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.pkcs9.Attribute;
import org.xpertss.crypto.pkcs.pkcs9.Attributes;
import org.xpertss.crypto.pkcs.pkcs9.InvalidAttributeException;

import java.io.*;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Signs a given <code>Signable</code> object, e.g. a <code>
 * SignedData</code> or a <code>SignedAndEnvelopedData</code>.
 */
public class Signer extends Object {
   /**
    * The OID of PKCS#7 Data
    */
   private ASN1ObjectIdentifier DATA = new ASN1ObjectIdentifier(new int[]{1, 2, 840, 113549, 1, 7, 1});

   /**
    * The OID of PKCS#9 MessageDigest Attribute
    */
   private ASN1ObjectIdentifier MESSAGE_DIGEST = new ASN1ObjectIdentifier(new int[]{1, 2, 840, 113549, 1, 9, 4});

   /**
    * The OID of PKCS#9 ContentType Attribute
    */
   private ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier(new int[]{1, 2, 840, 113549, 1, 9, 3});

   /**
    * The size of the buffer allocated for reading and
    * signing data in case this is a detached signature
    * file.
    */
   public static final int BUFFER_SIZE = 1024;

   /**
    * The <code>Signable</code> that is signed.
    */
   protected Signable target_;

   /**
    * The signature engine that is used to compute
    * signatures.
    */
   private Signature sig_;

   /**
    * The {@link SignerInfo SignerInfo} of the signer whose
    * signature generation is in progress.
    */
   protected SignerInfo info_;

   /**
    * The message digest engine that is used while signing
    * is in progress. The digest engine is used only in the
    * presence of authenticated attributes.
    */
   protected MessageDigest digest_;

   /**
    * The content type to be signed.
    */
   protected ASN1ObjectIdentifier contentType_;

   /**
    * <code>true</code> if signing is done with authenticated
    * attributes.
    */
   protected boolean twostep_ = false;


   /**
    * Creates an instance ready for signing.
    *
    * @param sigdat The <code>Signable</code> to which <code>
    *   SignerInfo</code> instances are added.
    * @param info The <code>SignerInfo</code> with the
    *   attributes that are signed along with the data.
    *   This instance is later added to the <code>Signable
    *   </code>.
    * @param key The private key to use for signing.
    * @exception NoSuchAlgorithmException if some required
    *   algorithm implementation cannot be found.
    * @exception InvalidKeyException if the public key does
    *   not match the signature algorithm.
    * @exception InvalidAttributeException if the PKCS#9
    *   ContentType attribute in the given <code>SignerInfo
    *   </code> does not match the content type of the
    *   corresponding <code>SignedData</code>.
    */
   public Signer(Signable sigdat, SignerInfo info, PrivateKey key)
      throws InvalidAttributeException, NoSuchAlgorithmException, InvalidKeyException
   {
      /* We can't do without both a SignerInfo and a
       * private key. */
      if (sigdat == null || info == null || key == null)
         throw new NullPointerException("Need a Signable, SignerInfo and PrivateKey!");
      info_ = info;
      target_ = sigdat;
      String sigalg = info_.getAlgorithm();

      /* Here comes the tough part. We have to check the
       * authenticated attributes. In the degenerated case
       * of no authenticated attributes and a content type
       * of Data in the SignedData we do one-step signing.
       * In all other cases we have to use two steps and
       * we have to add and/or check attributes.
       */
      Attributes attributes = info_.authenticatedAttributes();
      ASN1ObjectIdentifier oid = target_.getContentType();

      if (attributes.size() > 0 || !oid.equals(DATA)) {
         twostep_ = true;

         Attribute attribute = info_.authenticatedAttributes().getAttribute(CONTENT_TYPE);

         /* If there is no content type attribute then
          * we have to add one. If there is one then we
          * have to make sure that there is no mismatch.
          *
          * The code could correct and replace attributes
          * with a wrong type, but I guess it's better to
          * throw an exception because something with the
          * application's code is probably wrong.
          */
         if (attribute == null) {
            attribute = new Attribute((ASN1ObjectIdentifier) CONTENT_TYPE.copy(), (ASN1ObjectIdentifier) oid.copy());

            attributes.add(attribute);
         } else if (attribute.valueCount() < 1) {
            throw new InvalidAttributeException("Content type attribute has no value!");
         } else if (!attribute.valueAt(0).equals(oid)) {
            throw new InvalidAttributeException("Content type attribute has wrong value!");
         }
         attribute = info_.authenticatedAttributes().getAttribute(MESSAGE_DIGEST);

         /* If there is already a MessageDigest attribute
          * in the SignerInfo then we also boil out the
          * hard way. Better use a fresh SignerInfo.
          */
         if (attribute != null)
            throw new IllegalArgumentException("Message digest attribute already exists!");
         String mdalg = JCA.getName(JCA.getDigestOID(sigalg));

         if (mdalg == null)
            throw new NoSuchAlgorithmException("Cannot determine digest algorithm for " + sigalg);
         digest_ = MessageDigest.getInstance(mdalg);
      }
      sig_ = Signature.getInstance(sigalg);
      AlgorithmParameters params = info_.getParameters();

      sig_.initSign(key);
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
    * Update operation. Updates the
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
         } catch (Exception e) {
            /* Ignore */
         }
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
      info_ = null;
      digest_ = null;
      target_ = null;
   }


   /**
    * Completes the signing. The <code>SignerInfo</code> is
    * added to the target <code>SignedData</code> automatically.
    * <p>
    *
    * <b>Note:</b> The signer's certificate is not added to the
    * target <code>SignedData</code>. This has to be done
    * separately. Application shall have full control over
    * the embedding of certificates, because certificates
    * are likely to be distributed by other means as well
    * (e.g. LDAP). So there might not be a need to distibute
    * them with <code>SignedData</code> objects.
    */
   public void sign()
      throws SignatureException
   {
      if (twostep_) {
         byte[] b = digest_.digest();

         Attribute attribute = new Attribute((ASN1ObjectIdentifier) MESSAGE_DIGEST.copy(), new ASN1OctetString(b));

         info_.addAuthenticatedAttribute(attribute);
         info_.update(sig_);
      }
      /* SignedAndEnvelopedData instances are treated specially.
       * The message digest is additionally encrypted with the
       * bulk encryption key in order to prevent deterministic
       * checks for known plain texts.
       */
      if (target_ instanceof SignedAndEnvelopedData) {
         SignedAndEnvelopedData saed = (SignedAndEnvelopedData) target_;
         byte[] edig = saed.encryptBulkData(sig_.sign());
         info_.setEncryptedDigest(edig);
      } else {
         info_.setEncryptedDigest(sig_.sign());
      }
      target_.addSignerInfo(info_);
   }


}
