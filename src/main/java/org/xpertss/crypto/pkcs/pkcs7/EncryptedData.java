package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;

import java.io.*;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.crypto.*;

/**
 * This class represents a <code>EncryptedContentInfo</code> as defined in
 * <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-7.html">PKCS#7</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * <pre>
 * EncryptedData ::= SEQUENCE{
 *  version  Version,
 *  encryptedContentInfo EncryptedContentInfo }
 *
 * version is the syntax version number, which shall be 0 for this version.
 */
public class EncryptedData extends ASN1Sequence implements ASN1RegisteredType {
   /**
    * The OID of this structure. PKCS#7 Data
    */
   static final int[] OID = {1, 2, 840, 113549, 1, 7, 6};

   /**
    * the verson of this syntax
    */
   protected static ASN1Integer version_;

   /**
    * the actual content of this structure.
    */
   protected EncryptedContentInfo info_;


   /**
    * Creates an instance ready for decoding.
    */
   public EncryptedData()
   {
      super(2);

      version_ = new ASN1Integer(0);
      info_ = new EncryptedContentInfo();

      add(version_);
      add(info_);
   }


   /**
    * Creates an instance and initialises it with the given key, algorithm, and parameters.
    * The parameters can be <code>null</code> if none should be used.
    *
    * @param bek The secret key to use.
    * @param params The algorithm parameters or <code>null</code> if none are present.
    * @exception InvalidAlgorithmParameterException if there is a problem with the parameters.
    * @exception NullPointerException if {@code bea} or {@code bek} are {@code null}.
    */
   public EncryptedData(SecretKey bek, AlgorithmParameters params)
      throws InvalidAlgorithmParameterException
   {
      super(2);

      if (bek == null)
         throw new NullPointerException("BEK is null!");
      if (params == null)
         throw new NullPointerException("Parameters are null!");
      version_ = new ASN1Integer(0);
      info_ = new EncryptedContentInfo(bek, params);

      add(version_);
      add(info_);
   }





   /**
    * Initialises the underlying {@link EncryptedContentInfo} with the given bulk encryption
    * key.
    *
    * @param key The BEK to use for encrypting or decrypting.
    */
   public void init(SecretKey key)
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
   {
      info_.init(key);
   }


   public ASN1ObjectIdentifier getOID()
   {
      return new ASN1ObjectIdentifier(OID);
   }


   /**
    * This method returns the actual <code>content</code> of this structure.
    *
    * @return The <code>content</code> or <code>null</code> if no content is available.
    */
   public byte[] getEncryptedContent()
   {
      return info_.getEncryptedContent();
   }


   /**
    * Returns the name of the bulk encryption algorithm name.
    *
    * @return The algorithm name.
    * @exception IllegalStateException if this instance is not yet initialised.
    */
   public String getAlgorithm()
   {
      return info_.getAlgorithm();
   }


   /**
    * This method returns the secret bulk encryption key if the underlying
    * {@link EncryptedContentInfo} structure is already initialised properly (by calling one
    * of this object's {@link #init} methods). If the key is not available (yet) then {@code
    * null} is returned.
    *
    * @return The BEK or <code>null</code>.
    * @exception IllegalStateException if this instance is not yet initialised.
    */
   public SecretKey getSecretKey()
   {
      return info_.getSecretKey();
   }


   public EncryptedContentInfo getContentInfo()
   {
      return info_;
   }


   /**
    * This method returns <code>true</code> if this instance is ready for encryption/decryption
    * without further initialisation.
    *
    * @return <code>true</code> if it is ready.
    */
   public boolean isReady()
   {
      return info_.isReady();
   }


   /**
    * Encrypts the given data and inserts it as {@link Data} content.
    *
    * @exception IllegalStateException if the DEK is not initialised.
    */
   public void setData(InputStream in)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
               NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      info_.setData(in);
   }


   /**
    * This method decrypts and returns the decrypted data contained in this instance or {@code
    * null} if there is no contained data.
    *
    * @exception IllegalStateException if the DEK is not initialised.
    * @exception NoSuchElementException if the content type is not {@link Data}.
    */
   public byte[] getData()
      throws NoSuchElementException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
               NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      return info_.getData();
   }


   /**
    * This method reads encrypted bulk data from the input stream, decrypts and writes the
    * decrypted data to the given output stream. This instance must be properly initialised
    * for this operation to work.
    *
    * @param in The input stream from which the data is read.
    * @param out The output stream to which the data is written.
    */
   public void decryptBulkData(InputStream in, OutputStream out)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
               BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      info_.crypt(in, out, Cipher.DECRYPT_MODE);
   }


   /**
    * This method reads plaintext bulk data from the input stream, encrypts it and writes the
    * encrypted data to the given output stream. This instance must be properly initialised for
    * this operation to work.
    *
    * @param in The input stream from which the data is read.
    * @param out The output stream to which the data is written.
    */
   public void encryptBulkData(InputStream in, OutputStream out)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
               BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      info_.crypt(in, out, Cipher.ENCRYPT_MODE);
   }

}
