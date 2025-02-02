package org.xpertss.crypto.pkcs.pkcs7;


import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.util.CertificateSource;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.x509.BadNameException;

import java.io.*;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.math.BigInteger;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

/**
 * The definition of this structure is:
 * <blockquote><pre>
 * SignedAndEnvelopedData ::= SEQUENCE {
 *   version Version,
 *   recipientInfos RecipientInfos,
 *   digestAlgorithms DigestAlgorithmIdentifiers,
 *   encryptedContentInfo EncryptedContentInfo,
 *   certificates
 *     [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *   crls
 *     [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *   signerInfos SignerInfos
 * }
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *
 * SignerInfos ::= SET OF SignerInfo
 * </pre></blockquote>
 *
 * Please note that <code>SignerInfo</code> structures only store
 * the issuer and serial number of the signing certificate but not
 * the certificate itself. Neither are certificates added
 * automatically by this class when signing is done. If a certificate
 * shall be included with an instance of this class then it must be
 * added explicitly by calling <code>addCertificate(..)</code>.<p>
 *
 * The encryption and decryption methods of this class do not
 * work like <code>update(...)</code> of a <code>Cipher</code>
 * class but encrypt and decrypt data with a freshly initialized
 * cipher instance.
 */
public class SignedAndEnvelopedData extends ASN1Sequence implements ASN1RegisteredType, CertificateSource, Signable, Serializable {

   /**
    * The OID of this structure. PKCS#7 SignedAndEnvelopedData.
    */
   private static final int[] THIS_OID = {1, 2, 840, 113549, 1, 7, 4};

   /**
    * The PKCS#7 Data OID.
    */
   private static final int[] DATA_OID = {1, 2, 840, 113549, 1, 7, 1};

   /**
    * The DigestAlgorithmIdentifiers.
    */
   protected ASN1Set digestID_;

   /**
    * The X.509 certificates.
    */
   protected Certificates certs_;

   /**
    * The {@link SignerInfo SignerInfos}.
    */
   protected ASN1SetOf sInfos_;

   /**
    * The revocation lists.
    */
   protected ASN1Set crls_;

   /**
    * The RecipientInfos.
    */
   protected ASN1SetOf recipients_;

   /**
    * The {@link EncryptedContentInfo EncryptedContentInfo}.
    */
   protected EncryptedContentInfo info_;

   /**
    * The cache encoded X.509 certificates. This cache is
    * filled with opaque versions on encoding this instance.
    */
   protected ASN1Set cache_;

   /**
    * The certificate factory that is used for decoding
    * certificates.
    */
   protected CertificateFactory factory_;


   /**
    * Creates an instance ready for decoding.
    */
   public SignedAndEnvelopedData()
   {
      super(6);

      add(new ASN1Integer(1)); // version

      recipients_ = new ASN1SetOf(RecipientInfo.class);
      add(recipients_);

      digestID_ = new ASN1SetOf(AlgorithmIdentifier.class);
      add(digestID_);

      info_ = new EncryptedContentInfo();
      add(info_);

      certs_ = new Certificates();
      add(new ASN1TaggedType(0, certs_, false, true));

      crls_ = new ASN1SetOf(ASN1Opaque.class);
      add(new ASN1TaggedType(1, crls_, false, true));

      sInfos_ = new ASN1SetOf(SignerInfo.class);
      add(sInfos_);
   }


   /**
    * Creates an instance that is initialised with the given
    * secret key and algorithm parameters. If this constructor
    * is used then this instance need not be initialised anymore
    * with the {@link #init init} method for adding recipients.
    *
    * @param bek The secret key to use for bulk encryption.
    * @param params The AlgorithmParameters of the bulk
    *   encryption algorithm.
    * @exception InvalidAlgorithmParameterException just what
    *   is says...
    */
   public SignedAndEnvelopedData(SecretKey bek, AlgorithmParameters params)
      throws InvalidAlgorithmParameterException
   {
      super(6);

      add(new ASN1Integer(1)); // version

      recipients_ = new ASN1SetOf(RecipientInfo.class);
      add(recipients_);

      digestID_ = new ASN1SetOf(AlgorithmIdentifier.class);
      add(digestID_);

      info_ = new EncryptedContentInfo(bek, params);
      add(info_);

      certs_ = new Certificates();
      add(new ASN1TaggedType(0, certs_, false, true));

      crls_ = new ASN1SetOf(ASN1Opaque.class);
      add(new ASN1TaggedType(1, crls_, false, true));

      sInfos_ = new ASN1SetOf(SignerInfo.class);
      add(sInfos_);
   }


   /**
    * Adds the given certificate to this structure if none
    * with the same issuer and serial number already exists.
    *
    * @param cert  The certificate to add.
    */
   public void addCertificate(X509Certificate cert)
   {
      if (certs_.addCertificate(cert)) {
         ((ASN1Type) get(4)).setOptional(false);
      }
   }


   /**
    * This method adds a recipient to the list of recipients.
    * Please note that this works only if the underlying
    * {@link EncryptedContentInfo EncryptedContentInfo} is
    * initialised properly. This is done by either of two
    * means:
    * <ul>
    * <li> creating an instance of this class with the
    *   non-default constructor that takes as arguments
    *   a secret key and algorithm parameters, or
    * <li> by calling {@link #init init} with a certificate
    *   that is listed as recipient and appropriate private
    *   key.
    * </ul>
    * This ensures that the bulk encryption key is
    * available. This key is then encrypted for the recipient
    * specified in the given certificate (by encrypting with
    * the public key enclosed in it) and an appropriate
    * {@link RecipientInfo RecipientInfo} instance is
    * created and added to the list of recipient infos
    * in this instance.
    *
    * @param cert The certificate of the recipient.
    * @exception BadNameException if the issuer name in
    *   the certificate cannot be parsed.
    */
   public void addRecipient(X509Certificate cert)
      throws BadNameException
   {
      if (!hasRecipient(cert)) {
         recipients_.add(info_.newRecipient(cert));
      }
   }


   /**
    * Adds the given {@link SignerInfo SignerInfo} to this
    * instance. This method should be used rarely. In general,
    * the signing methods take care of adding <code>SignerInfo
    * </code> instances. Explicit adding of a <code>SignerInfo
    * </code> is provided only in those cases where fine control
    * of the creation of signatures is required.
    *
    * @param info The <code>SignerInfo</code> to add.
    * @exception NullPointerException if the <code>info</code>
    *   is <code>null</code>.
    */
   public void addSignerInfo(SignerInfo info)
   {
      Iterator i;

      if (info == null)
         throw new NullPointerException("Need a SignerInfo!");
      sInfos_.add(info);

      /* We also have to add the DigestAlgorithmIdentifier
       * of the SignerInfo to the list of digest algs if it
       * is not yet in the list.
       */
      AlgorithmIdentifier idn = info.getDigestAlgorithmIdentifier();

      for (i = digestID_.iterator(); i.hasNext();) {
         AlgorithmIdentifier idv = (AlgorithmIdentifier) i.next();

         if (idn.equals(idv)) return;
      }
      digestID_.add(idn);
   }


   public Iterator certificates(X500Principal subject)
   {
      return certs_.certificates(subject);
   }


   public Iterator certificates(X500Principal subject, int keyUsage)
   {
      return certs_.certificates(subject, keyUsage);
   }


   /**
    * This method reads encrypted bulk data from the input
    * stream, decrypts and writes the decrypted data to the
    * given output stream. This instance must be properly
    * initialised for this operation to work.
    *
    * @param in The input stream from which the data is read.
    * @param out The output stream to which the data is
    *   written.
    */
   public void decryptBulkData(InputStream in, OutputStream out)
      throws IOException
   {
      info_.crypt(in, out, Cipher.DECRYPT_MODE);
   }


   public byte[] decryptBulkData(byte[] b)
   {
      return info_.crypt(b, 0, b.length, Cipher.DECRYPT_MODE);
   }


   /**
    * This method reads plaintext bulk data from the input
    * stream, encrypts it and writes the encrypted data to the
    * given output stream. This instance must be properly
    * initialised for this operation to work.
    *
    * @param in The input stream from which the data is read.
    * @param out The output stream to which the data is
    *   written.
    */
   public void encryptBulkData(InputStream in, OutputStream out)
      throws IOException
   {
      info_.crypt(in, out, Cipher.ENCRYPT_MODE);
   }


   public byte[] encryptBulkData(byte[] b)
   {
      return info_.crypt(b, 0, b.length, Cipher.ENCRYPT_MODE);
   }


   public X509Certificate getCertificate(X500Principal issuer, BigInteger serial)
   {
      return certs_.getCertificate(issuer, serial);
   }


   /**
    * This method returns the certificates
    * stored in this structure. Each certificate can be
    * casted to a <code>X509Certificate</code>.
    *
    * @return An unmodifiable list view of the certificates.
    */
   public List getCertificates()
   {
      return Collections.unmodifiableList(certs_);
   }


   /**
    * This method retrieves the content of this structure, consisting of the
    * ASN.1 type embedded in the {@link #content_ ContentInfo} structure. Beware,
    * the content type might be faked by adversaries, if it is not of type
    * {@link Data Data}. If it is not data then the authenticated content type
    * must be given as an authenticated attribute in all the {@link SignerInfo}
    * structures.
    *
    * @return The contents octets.
    */
   public ASN1Type getContent()
   {
      return new Data(getData());
   }


   /**
    * Returns the content type of the content embedded
    * in this structure. The returned OID is a copy, no side
    * effects are caused by modifying it.
    *
    * @return The content type of this structure's payload.
    */
   public ASN1ObjectIdentifier getContentType()
   {
      return (ASN1ObjectIdentifier) info_.getContentType().copy();
   }


   /**
    * This method decrypts and returns the decrypted data
    * contained in this instance or <code>null</code> if
    * there is no contained data.
    *
    * @exception IllegalStateException if the DEK is not
    *   initialised.
    * @exception NoSuchElementException if the content
    *   type is not {@link Data Data}.
    */
   public byte[] getData()
      throws NoSuchElementException
   {
      return info_.getData();
   }


   /**
    * Returns the OID of this structure. The returned OID is
    * a copy, no side effects are caused by modifying it.
    *
    * @return The OID.
    */
   public ASN1ObjectIdentifier getOID()
   {
      return new ASN1ObjectIdentifier(THIS_OID);
   }


   /**
    * This method retrieves the {@link RecipientInfo RecipientInfo}
    * macthing the given certificate or <code>null</code> if there
    * is no such recipient.
    *
    * @param cert The certificate that identifies the recipient.
    * @return The RecipientInfo of the recipient or <code>null
    *   </code> if no matching recipient was found.
    */
   public RecipientInfo getRecipientInfo(X509Certificate cert)
   {
      Iterator i;

      for (i = recipients_.iterator(); i.hasNext();) {
         RecipientInfo ri = (RecipientInfo) i.next();

         if (ri.getIssuerDN().equals(cert.getIssuerDN()) && ri.getSerialNumber().equals(cert.getSerialNumber())) {
            return ri;
         }
      }
      return null;
   }


   /**
    * This method returns an unmodifiable list view on
    * the {@link RecipientInfo RecipientInfos} of this
    * structure.
    *
    * @return The list of recipient infos.
    */
   public List getRecipientInfos()
   {
      return Collections.unmodifiableList(recipients_);
   }


   /**
    * This method returns the secret bulk encryption key
    * if the underlying EncryptedContentInfo structure
    * is already initialised properly (by calling one of
    * this object's {@link #init init} methods). If the
    * key is not available (yet) then <code>null</code>
    * is returned.
    *
    * @return The BEK or <code>null</code>.
    * @exception IllegalStateException if this instance is
    *   not yet initialised.
    */
   public SecretKey getSecretKey()
   {
      return info_.getSecretKey();
   }


   /**
    * Returns the <code>SignerInfo</code> that matches the
    * given certificate.
    *
    * @param cert The certificate matching the <code>SignerInfo
    *   </code> to be retrieved.
    * @return The <code>SignerInfo</code> or <code>null</code>
    *   if no matching one is found.
    */
   public SignerInfo getSignerInfo(X509Certificate cert)
   {
      Iterator i;

      for (i = getSignerInfos().iterator(); i.hasNext();) {
         SignerInfo info = (SignerInfo) i.next();

         if (!info.getIssuerDN().equals(cert.getIssuerDN())) {
            continue;
         }
         if (info.getSerialNumber().equals(cert.getSerialNumber())) {
            return info;
         }
      }
      return null;
   }


   /**
    * This method returns the {@link SignerInfo
    * SignerInfos} of the signers of this structure.
    *
    * @return The unmodifiable view of the list of SignerInfos.
    */
   public List getSignerInfos()
   {
      return Collections.unmodifiableList(sInfos_);
   }


   /**
    * This method checks if the given certificate is listed
    * as a recipient by comparing the issuer and serial number
    * of the given certificate with those listed in the
    * {@link RecipientInfo recipient infos} of this instance.
    *
    * @param cert The certificate that identifies the recipient.
    * @return <code>true</code> if a recipient who matches the
    *   given certificate is included in this structure.
    */
   public boolean hasRecipient(X509Certificate cert)
   {
      return (getRecipientInfo(cert) != null);
   }


   /**
    * Initialises this instance for encryption/decryption.
    * The given certificate must be registered as recipient
    * and the private key must match the certificate. This
    * method actually looks for a {@link RecipientInfo
    * RecipientInfo} matching the given certificate and
    * calls {@link EncryptedContentInfo#init init} of the
    * {@link EncryptedContentInfo EncryptedContentInfo}
    * contained in this structure.<p>
    *
    * This method need to be called only if this instance
    * was not initialised with a secret key for bulk
    * encryption, but was initialised through parsing it
    * from a DER stream. In other words, this method is
    * probably used only when reading EnvelopedData sent
    * by someone else but hardly ever if it is generated.
    * <p>
    *
    * Please note that, once this instance is properly
    * initialised, additional recipients might be added
    * to it unless this structure is protected by
    * integrity measures (such as wrapping it in a
    * {@link SignedData SignedData} structure.
    *
    * @param kdk The private <i>Key Decryption Key</i>
    *   required to decrypt the DEK.
    * @param cert The certificate matching the private key.
    *
    * @exception CryptoException if some cipher
    *   operation fails.
    * @exception NoSuchElementException if no matching
    *   {@link RecipientInfo RecipientInfo} is found in
    *   this instance.
    */
   public void init(X509Certificate cert, PrivateKey kdk)
      throws NoSuchElementException
   {
      RecipientInfo ri = getRecipientInfo(cert);

      if (ri == null)
         throw new NoSuchElementException("No such recipient exists!");
      info_.init(kdk, ri);
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
      return info_.isReady();
   }


   /**
    * Sets the certificate factory to use for decoding
    * certificates.
    *
    * @param factory The certificate factory or <code>null
    *   </code> if the default <code>X.509</code> factory
    *   shall be used.
    */
   public void setCertificateFactory(CertificateFactory factory)
   {
      certs_.setCertificateFactory(factory);
   }


   /**
    * Sets the content type to the given OID. The content
    * itself is set to <code>null</code>. This method should
    * be called if the content to be signed is external (not
    * inserted into this structure).<p>
    *
    * If this structure is signed with the {@link Signer
    * Signer} then the {@link SignerInfo SignerInfo} that
    * is passed to it must have either:
    * <ul>
    * <li> no authenticated content type attribute, or
    * <li> the authenticated content type attribute must
    *   match <code>oid</code>.
    * </ul>
    * In the first case, a new authenticated content type
    * attribute with <code>oid</code> as its value will be
    * added to the <code>SignerInfo</code> automatically
    * (if the content type is not {@link Data Data} or at
    * least one other authenticated attribute is already
    * in that <code>SignerInfo</code>.
    *
    * @param oid The OID that identifies the content
    *   type of the signed data.
    * @exception NullPointerException if <code>oid</code>
    *   is <code>null</code>.
    */
   public void setContentType(ASN1ObjectIdentifier oid)
   {
      if (oid == null)
         throw new NullPointerException("OID");
      info_.setContentType(oid);
   }


   /**
    * This method wraps the given bytes into a {@link Data
    * Data} type and sets it as the content.<p>
    *
    * Please note that the signing process implemented in this
    * class does not care about the content. Setting a content
    * before signing does <b>not</b> sign the content. The data
    * to be signed must always be passed to one of the <code>
    * update</code> methods.
    *
    * @param b The opaque contents to embed in this structure.
    * @exception IllegalStateException if the DEK is not
    *   initialised.
    * @exception CryptoException if something nasty
    *   happens while encrypting such as algorithms not found,
    *   bad paddings et cetera.
    */
   public void setData(byte[] b)
      throws IOException, CryptoException
   {
      ByteArrayInputStream bis = new ByteArrayInputStream(b);
      try {
         info_.setData(bis);
      } finally {
         bis.close();
      }
   }


   /**
    * Encrypts the given data and inserts it as {@link
    * Data Data} content. The stream is not closed.
    *
    * @exception IllegalStateException if the DEK is not
    *   initialised.
    * @exception CryptoException if something nasty
    *   happens while encrypting such as algorithms not found,
    *   bad paddings et cetera.
    */
   public void setData(InputStream in)
      throws CryptoException, IOException
   {
      info_.setData(in);
   }


   /**
    * Sets the content type to {@Link Data Data} and clears
    * the actual content. Call this method when external
    * data is signed, and no particular content type shall
    * be used. This method calls <code>
    * setContentType(new ASN1ObjectIdentifier(DATA_OID))
    * </code>.
    */
   public void setDataContentType()
   {
      setContentType(new ASN1ObjectIdentifier(DATA_OID));
   }


   /**
    * Returns a string representation of this object.
    *
    * @return The string representation.
    */
   public String toString()
   {
      return "-- PKCS#7 SignedAndEnvelopedData --\n" + super.toString();
   }
}
