package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.x509.BadNameException;

import java.io.*;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.crypto.*;

/**
 * This class represents a <code>EncryptedContentInfo</code>
 * as defined in
 * <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-7.html">
 * PKCS#7</a>. The ASN.1 definition of this structure is
 * <p>
 * <pre>
 * EncryptedContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
 * }
 * EncryptedContent ::= OCTET STRING
 *
 * ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * </pre>
 * <p>
 * <code>contentType</code> indicates the type of content embedded
 * in the EncryptedContent. The encryptedContent is optional; if
 * it is not included in this structure then it must be provided
 * by other means (such as a detached file).
 * <p>
 *
 * PKCS#7 specifies six content types: {@link Data data}, {@link
 * SignedData signedData}, {@link EnvelopedData envelopedData},
 * {@link SignedAndEnvelopedData signedAndEnvelopedData},
 * {@link DigestedData digestedData} and {@link EncryptedData
 * encryptedData}. All of these content types have registered OIDs.
 * <p>
 *
 */
public class EncryptedContentInfo extends ASN1Sequence {
   /**
    * The size of the buffer allocated for encrypting.
    */
   public static final int BUFFER_SIZE = 4096;

   /**
    * The OID of PKCS#7 Data
    */
   private static final int[] DATA_OID = {1, 2, 840, 113549, 1, 7, 1};

   /**
    * The OID defining the contents of this structure.
    */
   protected ASN1ObjectIdentifier contentType_;

   /**
    * The ContentEncryptionAlgorithmIdentifier
    */
   protected AlgorithmIdentifier cAlg_;

   /**
    * The encrypted content, if present in this structure.
    */
   protected ASN1TaggedType econtent_;

   /**
    * The bulk encryption key.
    */
   private SecretKey bek_;

   /**
    * The bulk encryption algorithm parameters.
    */
   private AlgorithmParameters params_;

   /**
    * The encryption algorithm name
    */
   private String bea_;


   /**
    * Creates an instance ready for parsing. After decoding of
    * this instance, it must be initialised with one of the
    * <code>init</code> methods, before encryption or decryption
    * operation can commence.
    */
   public EncryptedContentInfo()
   {
      super(3);

      contentType_ = new ASN1ObjectIdentifier();
      cAlg_ = new AlgorithmIdentifier();
      econtent_ = new ASN1TaggedType(0, new ASN1OctetString(), false, true);

      add(contentType_);
      add(cAlg_);
      add(econtent_);
   }


   /**
    * Initialises an instance with the given secret key, algorithm,
    * and parameters. The content type is set to {@link Data Data}.
    * Instances created with this constructor are ready for
    * encryption and decryption operations by means of the
    * <code>crypt</code> methods.
    *
    * @param bek The secret bulk encryption key.
    * @param params The bulk encryption algorithm parameters.
    */
   public EncryptedContentInfo(SecretKey bek, AlgorithmParameters params)
      throws InvalidAlgorithmParameterException
   {
      if (bek == null)
         throw new NullPointerException("Encryption key is null!");
      if(params == null)
         throw new NullPointerException("AlgorithmParameters are null!");
      contentType_ = new ASN1ObjectIdentifier(DATA_OID);
      cAlg_ = new AlgorithmIdentifier(params);
      econtent_ = new ASN1TaggedType(0, new ASN1OctetString(), false, true);

      add(contentType_);
      add(cAlg_);
      add(econtent_);

      bek_ = bek;
      params_ = params;
      bea_ = params.getAlgorithm();
   }

   /**
    * Initialises an instance with the given secret key, algorithm,
    * and parameters. The content type is set to {@link Data Data}.
    * Instances created with this constructor are ready for
    * encryption and decryption operations by means of the
    * <code>crypt</code> methods.
    *
    * @param bea The bulk encryption algorithm name.
    * @param bek The secret bulk encryption key.
    */
   public EncryptedContentInfo(String bea, SecretKey bek)
      throws InvalidAlgorithmParameterException
   {
      if (bek == null)
         throw new NullPointerException("Encryption key is null!");
      if (bea == null)
         throw new NullPointerException("Encryption algorithm is null!");
      contentType_ = new ASN1ObjectIdentifier(DATA_OID);
      cAlg_ = new AlgorithmIdentifier(bea);
      econtent_ = new ASN1TaggedType(0, new ASN1OctetString(), false, true);

      add(contentType_);
      add(cAlg_);
      add(econtent_);

      bek_ = bek;
      bea_ = bea;
   }






   /**
    * Returns the <code>contentType</code> of this structure.
    * This value is defined only if the structure has been
    * decoded successfully, or the content has been set
    * previously.
    *
    * @return The OID describing the <code>contentType</code>
    *   of this structure.
    */
   public ASN1ObjectIdentifier getContentType()
   {
      return contentType_;
   }


   /**
    * This method returns the actual <code>content</code> of
    * this structure.
    *
    * @return The <code>content</code> or <code>null</code>
    *   if no content is available.
    */
   public byte[] getEncryptedContent()
   {
      if (econtent_.isOptional()) return null;
      ASN1OctetString v = (ASN1OctetString) econtent_.getInnerType();
      return v.getByteArray();
   }


   /**
    * Returns the name of the bulk encryption algorithm name.
    *
    * @return The algorithm name.
    * @exception IllegalStateException if this instance is
    *   not yet initialised.
    */
   public String getAlgorithm()
   {
      if (bea_ == null)
         throw new IllegalStateException("Not initialized or algorithm unresolvable!");
      return bea_;
   }


   /**
    * Returns the algorithm parameters of the bulk encryption
    * algorithm identifier.
    *
    * @return The algorithm parameters.
    */
   public AlgorithmParameters getParameters()
   {
      if (params_ == null)
         throw new IllegalStateException("Not initialized or parameters unresolvable!");
      return params_;
   }


   /**
    * Returns the secret bulk encryption key.
    *
    * @return The BEK or <code>null</code>.
    * @exception IllegalStateException if this instance is
    *   not yet initialised.
    */
   public SecretKey getSecretKey()
   {
      if (bek_ == null)
         throw new IllegalStateException("Not initialised!");
      return bek_;
   }








   /**
    * Initialises this instance for encryption/decryption
    * with the BEK that is stored in the given {@link
    * RecipientInfo RecipientInfo}.
    * The BEK is decrypted with the given private key and
    * initialised according to the algorithm specified in
    * this instance's contentEncryptionAlgorithmIdentifier.
    *
    * @param kdk The private <i>Key Decryption Key</i>
    *   required to decrypt the BEK.
    * @param info The {@link RecipientInfo RecipientInfo}
    *   that holds the BEK.
    */
   public void init(PrivateKey kdk, RecipientInfo info)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
   {
      init();
      bek_ = info.getSecretKey(kdk, bea_);
   }


   /**
    * Initialises this instance for encryption/decryption
    * with the given secret key.
    *
    * @param key The secret key that is used to decrypt.
    *   The key must match the algorithm defined in the
    *   contentEncryptionAlgorithmIdentifier.
    */
   public void init(SecretKey key)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
   {
      if (key == null)
         throw new NullPointerException("Need a SecretKey!");
      init();
      bek_ = key;
   }


   /**
    * Basic initialization.
    */
   protected void init()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException

   {
      if (params_ == null)
         params_ = cAlg_.getParameters();
      if (bea_ == null)
         bea_ = cAlg_.getAlgorithmOID().toString();
      if (bea_ == null)
         throw new NoSuchAlgorithmException("Cannot resolve OID " + cAlg_.getAlgorithmOID());
   }





   /**
    * This method returns <code>true</code> if this
    * instance is ready for encryption/decryption
    * without further initialisation.
    *
    * @return <code>true</code> if it is ready.
    */
   public boolean isReady()
   {
      if (bek_ == null) return false;
      return true;
   }


   /**
    * This method initialises and returns a new {@link
    * RecipientInfo RecipientInfo} based on the given
    * certificate. The BEK must already be
    * initialsed, otherwise and exception is thrown.
    *
    * @exception IllegalStateException if the BEK is not
    *   yet initialised.
    * @exception NoSuchAlgorithmException if some required
    *   algorithm is not available.
    * @exception BadNameException if the issuer name in the
    *   given vertificate cannot be parsed.
    * @exception IllegalStateException if this instance is
    *   not initialised properly.
    */
   public RecipientInfo newRecipient(X509Certificate cert)
      throws BadNameException
   {
      if (bek_ == null)
         throw new IllegalStateException("Not initialised!");
      return new RecipientInfo(cert, bek_);
   }


   /**
    * Encrypts the given data and inserts it as {@link
    * Data Data} content. The input stream is not closed.
    *
    * @exception IllegalStateException if the DEK is not
    *   initialised.
    * @exception CryptoException if something nasty
    *   happens while encrypting such as algorithms not found,
    *   bad paddings et cetera.
    */
   public void setData(InputStream in)
      throws IOException, CryptoException
   {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      crypt(in, out, Cipher.ENCRYPT_MODE);

      byte[] b = out.toByteArray();
      out.close();

      contentType_ = new ASN1ObjectIdentifier(DATA_OID);
      econtent_ = new ASN1TaggedType(0, new ASN1OctetString(b), false, false);

      clear();
      add(contentType_);
      add(cAlg_);
      add(econtent_);
      trimToSize();
   }


   /**
    * This method decrypts and returns the decrypted data
    * contained in this instance or <code>null</code> if
    * there is no contained data.
    *
    * @exception InconsistentStateException in case of an
    *   unexpected internal exception. This should never
    *   happen.
    * @exception IllegalStateException if the DEK is not
    *   initialised.
    * @exception NoSuchElementException if the content
    *   type is not {@link Data Data}.
    * @exception CryptoException if a cipher
    *   operation fails.
    */
   public byte[] getData()
      throws CryptoException, NoSuchElementException
   {
      if (!Arrays.equals(contentType_.getOID(), DATA_OID)) {
         throw new NoSuchElementException("Content type is not Data!");
      }
      byte[] b = getEncryptedContent();

      if (b == null || b.length == 0) return null;
      try {
         ByteArrayOutputStream out = new ByteArrayOutputStream();
         crypt(b, out, Cipher.DECRYPT_MODE);
         b = out.toByteArray();
         out.close();

         return b;
      } catch (IOException e) {
         throw new IllegalStateException(e.getMessage());
      }
   }


   /**
    * @param opmode The operation mode of the cipher.
    * @return A <code>Cipher</code> instance readily initialized
    *   for the given operation mode.
    * @exception CryptoException if something is wrong
    *   with the cipher initialization, e.g. no bea_ algorithm
    *   was found.
    * @exception IllegalStateException if this instance is not
    *   initialized properly for cipher operations. This happens
    *   for instance if no secret key was set, yet.
    */
   private Cipher createCipher(int opmode)
      throws CryptoException
   {
      if (bek_ == null)
         throw new IllegalStateException("No secret key");
      Cipher cipher = Cipher.getInstance(params_.getAlgorithm().getOID());

      if (params_ == null) {
         cipher.init(opmode, bek_);
      } else {
         cipher.init(opmode, bek_, params_);
      }
      return cipher;
   }


   /**
    * Pipes the input to the output while encrypting or
    * decrypting the piped data with the BEK.
    * The output stream is not closed by this method but
    * the input stream is.
    *
    * @param in The stream from which data is read.
    * @param out The stream to which data is written.
    * @param opmode The operation mode of the cipher,
    *   either <code>Cipher.ENCRYPT_MODE</code> or
    *   <code>Cipher.DECRYPT_MODE</code>.
    * @exception CryptoException if the some cipher
    *   operation caused an exception.
    * @exception IllegalStateException if the BEK is not
    *   initialised.
    * @exception IOException if some I/O error is detected.
    */
   public void crypt(InputStream in, OutputStream out, int opmode)
      throws IOException, CryptoException
   {
      int n;

      Cipher cipher = createCipher(opmode);
      byte[] b = new byte[BUFFER_SIZE];

      while ((n = in.read(b)) > 0) {
         out.write(cipher.update(b, 0, n));
      }
      out.write(cipher.doFinal());
      out.flush();
      in.close();
   }


   /**
    * Crypts or decrypts the given input bytes and writes the
    * resulting cipher text or clear text tp the given output
    * stream. The output stream is flushed but not closed by
    * this method.
    *
    * @param b The byte array from which data is taken.
    * @param out The stream to which data is written.
    * @param opmode The operation mode of the cipher,
    *   either <code>Cipher.ENCRYPT_MODE</code> or
    *   <code>Cipher.DECRYPT_MODE</code>.
    * @exception CryptoException if the some cipher
    *   operation caused an exception.
    * @exception IllegalStateException if the BEK is not
    *   initialised.
    * @exception IOException if some I/O error is detected.
    */
   public void crypt(byte[] in, OutputStream out, int opmode)
      throws IOException, CryptoException
   {
      Cipher cipher = createCipher(opmode);

      out.write(cipher.doFinal(in));
      out.flush();
   }


   /**
    * Crypts or decrypts the given input bytes and returns the
    * resulting cipher text or clear text.
    *
    * @param b The byte array from which data is taken.
    * @param offset The offset in the byte array at which
    *   the data starts.
    * @param length The number of bytes to operate on starting
    *   at the given offset.
    * @param opmode The operation mode of the cipher,
    *   either <code>Cipher.ENCRYPT_MODE</code> or
    *   <code>Cipher.DECRYPT_MODE</code>.
    *
    * @return The resulting cipher text or clear text depending
    *   on the operation mode.
    *
    * @exception CryptoException if the some cipher
    *   operation caused an exception.
    * @exception IllegalStateException if the BEK is not
    *   initialised.
    */
   public byte[] crypt(byte[] in, int offset, int length, int opmode)
      throws CryptoException
   {
      Cipher cipher = createCipher(opmode);
      return cipher.doFinal(in, offset, length);
   }


   /**
    * Decodes this instance with the given decoder. After decoding,
    * an attempt is made to resolve the algorithm name and parameters.
    *
    * @param dec The decoder to use.
    */
   public void decode(Decoder dec)
      throws IOException, ASN1Exception
   {
      super.decode(dec);

      try {
         init();
      } catch (CryptoException e) {
         /* We ignore this exception at this point.
          * It will be thrown again when this structure
          * is initialized with a key, or algorithm names
          * or parameters are requested.
          */
      }
   }


   /**
    * Encrypts the given data and embeds it into this instance.
    * The content type is set to the specified OID.
    *
    * @param oid The OID that identifies the content type.
    * @param in The stream from which the data is read.
    *
    * @exception IllegalStateException if this instance is not
    *   properly initialized for encryption.
    * @exception CryptoException if something nasty
    *   happens while encrypting such as algorithms not found,
    *   bad paddings et cetera.
    */
   public void setEncryptedContent(ASN1ObjectIdentifier oid, InputStream in)
      throws IOException, CryptoException
   {
      if (oid == null || in == null)
         throw new NullPointerException("oid or input stream");
      /* Encrypt the data */
      ByteArrayOutputStream out = new ByteArrayOutputStream();

      crypt(in, out, Cipher.ENCRYPT_MODE);

      byte[] b = out.toByteArray();

      out.close();

      /* Set the content type */
      contentType_ = oid;

      /* Embed the content into this structure. */
      econtent_ = new ASN1TaggedType(0, new ASN1OctetString(b), false, false);

      /* Re-build the structure. */
      clear();
      add(contentType_);
      add(cAlg_);
      add(econtent_);
      trimToSize();
   }


   /**
    * Sets the content type to the given OID.
    * The OID is copied by reference. Modifying
    * it afterwards causes side effects.
    *
    * @param oid The OID that identifies the content type.
    */
   public void setContentType(ASN1ObjectIdentifier oid)
   {
      if (oid == null)
         throw new NullPointerException("oid");
      contentType_ = oid;
      set(0, contentType_);
   }


}
