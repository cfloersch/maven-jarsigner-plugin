package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;

import java.io.*;
import java.security.PrivateKey;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;

/**
 * This class represents the PKCS#7 EnvelopedData type, which is defined as follows:
 * <pre>
 * EnvelopedData ::= SEQUENCE {
 *   version Version,
 *   recipientInfos RecipientInfos,
 *   encryptedContentInfo EncryptedContentInfo
 * }
 *
 * RecipientInfos ::= SET OF RecipientInfo
 * </pre>
 * See class {@link RecipientInfo} for a description of the RecipientInfo structure.
 */
public class EnvelopedData extends ASN1Sequence implements ASN1RegisteredType {

   /**
    * The size of the buffer allocated for reading and verifying data in case this is a
    * detached signature file.
    */
   public static final int BUFFER_SIZE = 1024;

   /**
    * The OID of this structure. PKCS#7 EnvelopedData.
    */
   static final int[] OID = {1, 2, 840, 113549, 1, 7, 3};

   /**
    * The version of this structure.
    */
   protected ASN1Integer version;

   /**
    * The RecipientInfos.
    */
   protected ASN1SetOf recipients;

   /**
    * The {@link EncryptedContentInfo}.
    */
   protected EncryptedContentInfo info;

   /**
    * The {@link ContentInfo}.
    */
   protected ContentInfo content;


   /**
    * This method calls builds the tree of ASN.1 objects used for decoding this structure.
    */
   public EnvelopedData()
   {
      super(3);

      version = new ASN1Integer(0);
      recipients = new ASN1SetOf(RecipientInfo.class);
      info = new EncryptedContentInfo();

      add(version); // version
      add(recipients);
      add(info);
   }


   /**
    * Creates an instance that is initialised with the given secret key and algorithm
    * parameters. If this constructor is used then this instance need not be initialised
    * anymore with the {@link #init} method for adding recipients.
    *
    * @param bek The secret key to use for bulk encryption.
    * @param params The AlgorithmParameters of the bulk encryption algorithm.
    * @exception InvalidAlgorithmParameterException just what is says...
    */
   public EnvelopedData(SecretKey bek, AlgorithmParameters params)
      throws InvalidAlgorithmParameterException
   {
      super(3);

      version = new ASN1Integer(0);
      recipients = new ASN1SetOf(RecipientInfo.class);
      info = new EncryptedContentInfo(bek, params);

      add(version); // version
      add(recipients);
      add(info);
   }


   /**
    * Returns the OID of this structure.
    *
    * @return The OID.
    */
   public ASN1ObjectIdentifier getOID()
   {
      return new ASN1ObjectIdentifier(OID);
   }


   /**
    * Retrieves and returns the content type of the content
    * stored in the <code>encryptedContentInfo</code> of this
    * structure. This value is meaningful only if this instance
    * was decoded or initialised properly.
    */
   public ASN1ObjectIdentifier getContentType()
   {
      return info.getContentType();
   }


   /**
    * This method returns an unmodifiable list view on the {@link RecipientInfo} of
    * this structure.
    *
    * @return The list of recipient infos.
    */
   public List<RecipientInfo> getRecipientInfos()
   {
      return (List<RecipientInfo>) recipients.getValue();
   }


   /**
    * This method checks if the given certificate is listed as a recipient by comparing
    * the issuer and serial number of the given certificate with those listed in the
    * {@link RecipientInfo recipient infos} of this instance.
    *
    * @param cert The certificate that identifies the recipient.
    * @return <code>true</code> if a recipient who matches the given certificate is
    *    included in this structure.
    */
   public boolean hasRecipient(X509Certificate cert)
   {
      return getRecipientInfo(cert) != null;
   }


   /**
    * This method retrieves the {@link RecipientInfo} macthing the given certificate or
    * <code>null</code> if there is no such recipient.
    *
    * @param cert The certificate that identifies the recipient.
    * @return The RecipientInfo of the recipient or <code>null</code> if no matching
    *    recipient was found.
    */
   public RecipientInfo getRecipientInfo(X509Certificate cert)
   {
      Iterator i;
      for (i = recipients.iterator(); i.hasNext();) {
         RecipientInfo ri = (RecipientInfo) i.next();

         if (ri.getIssuerDN().equals(cert.getIssuerDN())
               && ri.getSerialNumber().equals(cert.getSerialNumber())) {
            return ri;
         }
      }
      return null;
   }


   /**
    * This method adds a recipient to the list of recipients. Please note that this works only
    * if the underlying {@link EncryptedContentInfo} is initialised properly. This is done by
    * either of two means:
    * <ul>
    * <li> creating an instance of this class with the non-default constructor that takes as
    *    arguments a secret key and algorithm parameters, or
    * <li> by calling {@link #init init} with a certificate that is listed as recipient and
    *    appropriate private key.
    * </ul>
    * This ensures that the bulk encryption key is available. This key is then encrypted for
    * the recipient specified in the given certificate (by encrypting with the public key
    * enclosed in it) and an appropriate {@link RecipientInfo} instance is created and added
    * to the list of recipient infos in this instance.
    *
    * @param cert The certificate of the recipient.
    */
   public void addRecipient(X509Certificate cert)
      throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException,
               NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException
   {
      if (!hasRecipient(cert)) {
         recipients.add(info.newRecipient(cert));
      }
   }


   /**
    * Initialises this instance for encryption/decryption. The given certificate must be
    * registered as recipient and the private key must match the certificate. This method
    * actually looks for a {@link RecipientInfo} matching the given certificate and calls
    * {@link EncryptedContentInfo#init init} of the {@link EncryptedContentInfo} contained
    * in this structure.
    * <p/>
    * This method need to be called only if this instance was not initialised with a secret
    * key for bulk encryption, but was initialised through parsing it from a DER stream. In
    * other words, this method is probably used only when reading EnvelopedData sent by
    * someone else but hardly ever if it is generated.
    * <p/>
    * Please note that, once this instance is properly initialised, additional recipients
    * might be added to it unless this structure is protected by integrity measures (such
    * as wrapping it in a {@link SignedData} structure.
    *
    * @param kdk The private <i>Key Decryption Key</i> required to decrypt the DEK.
    * @param cert The certificate matching the private key.
    * @exception NoSuchElementException if no matching {@link RecipientInfo} is found in
    *    this instance.
    */
   public void init(X509Certificate cert, PrivateKey kdk)
      throws NoSuchElementException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
               NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException
   {
      RecipientInfo ri = getRecipientInfo(cert);
      if (ri == null) throw new NoSuchElementException("No such recipient exists!");
      info.init(kdk, ri);
   }


   /**
    * This method returns <code>true</code> if this instance is ready for encryption/decryption
    * without further initialisation.
    *
    * @return <code>true</code> if it is ready.
    */
   public boolean isReady()
   {
      return info.isReady();
   }


   /**
    * Encrypts the given data and inserts it as {@link Data} content.
    *
    * @exception IllegalStateException if the DEK is not initialised.
    */
   public void setData(InputStream in)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
               BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      info.setData(in);
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
      return info.getData();
   }


   /**
    * This method returns the secret bulk encryption key if the underlying EncryptedContentInfo
    * structure is already initialised properly (by calling one of this object's {@link #init}
    * methods). If the key is not available (yet) then <code>null</code> is returned.
    *
    * @return The BEK or <code>null</code>.
    * @exception IllegalStateException if this instance is not yet initialised.
    */
   public SecretKey getSecretKey()
   {
      return info.getSecretKey();
   }


   /**
    * This method reads encrypted bulk data from the input stream, decrypts and writes the
    * decrypted data to the given output stream. This instance must be properly initialised for
    * this operation to work.
    *
    * @param in The input stream from which the data is read.
    * @param out The output stream to which the data is written.
    */
   public void decryptBulkData(InputStream in, OutputStream out)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      info.crypt(in, out, Cipher.DECRYPT_MODE);
   }


   /**
    * This method reads plaintext bulk data from the input stream, encrypts it and writes the
    * encrypted data to the given output stream. This instance must be properly initialised
    * for this operation to work.
    *
    * @param in The input stream from which the data is read.
    * @param out The output stream to which the data is written.
    */
   public void encryptBulkData(InputStream in, OutputStream out)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      info.crypt(in, out, Cipher.ENCRYPT_MODE);
   }

}

