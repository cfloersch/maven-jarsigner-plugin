package org.xpertss.crypto.pkcs.pkcs7;


import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.io.*;
import java.security.PrivateKey;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.*;
import java.math.BigInteger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

/**
 * This class represents a <code>SignedAndEnvelopedData</code> as defined in
 * <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-7.html">PKCS#7</a>.
 * The ASN.1 definition of this structure is
 * <blockquote><pre>
 * SignedAndEnvelopedData ::= SEQUENCE {
 *   version Version,
 *   recipientInfos RecipientInfos,
 *   digestAlgorithms DigestAlgorithmIdentifiers,
 *   encryptedContentInfo EncryptedContentInfo,
 *   certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *   crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *   signerInfos SignerInfos
 * }
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
 * <p/>
 * The encryption and decryption methods of this class do not work like @code update(...)}
 * of a <code>Cipher</code> class but encrypt and decrypt data with a freshly initialized
 * cipher instance.
 */
// TODO Used to impl CertificateSource, Signable
public class SignedAndEnvelopedData extends ASN1Sequence implements ASN1RegisteredType {

   /**
    * The OID of this structure. PKCS#7 SignedAndEnvelopedData.
    */
   static final int[] OID = {1, 2, 840, 113549, 1, 7, 4};



   /**
    * The DigestAlgorithmIdentifiers.
    */
   protected ASN1Set digestID;

   /**
    * The X.509 certificates.
    */
   protected Certificates certs;

   /**
    * The {@link SignerInfo SignerInfos}.
    */
   protected ASN1SetOf signers;

   /**
    * The revocation lists.
    */
   protected ASN1Set crls;

   /**
    * The RecipientInfos.
    */
   protected ASN1SetOf recipients;

   /**
    * The {@link EncryptedContentInfo EncryptedContentInfo}.
    */
   protected EncryptedContentInfo content;

   /**
    * The cache encoded X.509 certificates. This cache is filled with opaque versions on
    * encoding this instance.
    */
   protected ASN1Set cache_;




   
   /**
    * Creates an instance ready for decoding.
    */
   public SignedAndEnvelopedData()
   {
      super(6);

      add(new ASN1Integer(1)); // version

      recipients = new ASN1SetOf(RecipientInfo.class);
      add(recipients);

      digestID = new ASN1SetOf(AlgorithmIdentifier.class);
      add(digestID);

      content = new EncryptedContentInfo();
      add(content);

      certs = new Certificates();
      add(new ASN1TaggedType(0, certs, false, true));

      crls = new ASN1SetOf(ASN1Opaque.class);
      add(new ASN1TaggedType(1, crls, false, true));

      signers = new ASN1SetOf(SignerInfo.class);
      add(signers);
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
   public SignedAndEnvelopedData(SecretKey bek, AlgorithmParameters params)
      throws InvalidAlgorithmParameterException
   {
      super(6);

      add(new ASN1Integer(1)); // version

      recipients = new ASN1SetOf(RecipientInfo.class);
      add(recipients);

      digestID = new ASN1SetOf(AlgorithmIdentifier.class);
      add(digestID);

      content = new EncryptedContentInfo(bek, params);
      add(content);

      certs = new Certificates();
      add(new ASN1TaggedType(0, certs, false, true));

      crls = new ASN1SetOf(ASN1Opaque.class);
      add(new ASN1TaggedType(1, crls, false, true));

      signers = new ASN1SetOf(SignerInfo.class);
      add(signers);
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
    * This method returns the secret bulk encryption key if the underlying {@link
    * EncryptedContentInfo} structure is already initialised properly (by calling one of this
    * object's {@link #init} methods). If the key is not available (yet) then {@code null} is
    * returned.
    *
    * @return The BEK or <code>null</code>.
    * @exception IllegalStateException if this instance is not yet initialised.
    *
    * TODO Should this even be exposed?
    */
   public SecretKey getSecretKey()
   {
      return content.getSecretKey();
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

   /**
    * Returns all certificates in this collection as an unmodifiable List.
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
      return (List<SignerInfo>) signers.getValue();
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
    * certificate path and signature algorithm. It adds the certificate path to this SignedData
    * utilizing the last element to initialize the SignerInfo that is added and returned.
    * <p/>
    * A CertPath holds its chain in reverse order where the most trusted cert is first and the
    * signer cert is last.
    *
    *
    * @param algorithm The signature algorithm being used to do the signing
    * @param certPath The certificate path identifying the signer
    * @return The SignerInfo initialized by signer certificate and algorithm
    * @throws NoSuchAlgorithmException If the specified algorithm is not found in this system
    */
   public SignerInfo newSigner(String algorithm, CertPath certPath)
      throws NoSuchAlgorithmException
   {

      Optional<X509Certificate> last = certPath.getCertificates().stream()
         .map(certificate -> (X509Certificate) certificate)
         .reduce((first, second) -> second);


      SignerInfo signerInfo = new SignerInfo(last.get(), algorithm);
      addSignerInfo(signerInfo);
      certs.addCertPath(certPath);
      return signerInfo;
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
      // TODO Maybe Certs should extend from TaggedType and encapsulate this internally
      //  something like Certificates certs = new Certificates(); certs.setTag(0);

      certs.addCertChain(certChain);
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
      signers.add(info);

      /*
       * We also have to add the DigestAlgorithmIdentifier of the SignerInfo to the list of digest
       * algs if it is not yet in the list.
       */
      AlgorithmIdentifier idn = info.getDigestAlgorithmIdentifier();

      for (i = digestID.iterator(); i.hasNext();) {
         AlgorithmIdentifier idv = (AlgorithmIdentifier) i.next();
         if (idn.equals(idv)) return;
      }
      digestID.add(idn);
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
         recipients.add(content.newRecipient(cert));
      }
   }


   /**
    * This method retrieves the {@link RecipientInfo} matching the given certificate or {@code
    * null} if there is no such recipient.
    *
    * @param cert The certificate that identifies the recipient.
    * @return The RecipientInfo of the recipient or {@code null} if no matching recipient was
    *    found.
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
    * This method returns an unmodifiable list view on the {@link RecipientInfo} of this
    * structure.
    *
    * @return The list of recipient infos.
    */
   public List<RecipientInfo> getRecipientInfos()
   {
      return (List<RecipientInfo>) recipients.getValue();
   }

   /**
    * This method checks if the given certificate is listed as a recipient by comparing the
    * issuer and serial number of the given certificate with those listed in the {@link
    * RecipientInfo} of this instance.
    *
    * @param cert The certificate that identifies the recipient.
    * @return <code>true</code> if a recipient who matches the given certificate is included
    *    in this structure.
    */
   public boolean hasRecipient(X509Certificate cert)
   {
      return (getRecipientInfo(cert) != null);
   }














   /**
    * Returns the content type of the content embedded in this structure. The returned OID is
    * a copy, no side effects are caused by modifying it.
    *
    * @return The content type of this structure's payload.
    */
   public ASN1ObjectIdentifier getContentType()
   {
      return (ASN1ObjectIdentifier) content.getContentType().copy();
   }


   /**
    * Sets the content type to the given OID. The content itself is set to <code>null</code>.
    * This method should be called if the content to be signed is external (not inserted into
    * this structure).
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
      content.setContentType(oid);
   }


   /**
    * This method retrieves the content of this structure, consisting of the ASN.1 type
    * embedded in the {@link ContentInfo} structure. Beware, the content type might be
    * faked by adversaries, if it is not of type {@link Data}. If it is not data then the
    * authenticated content type must be given as an authenticated attribute in all the
    * {@link SignerInfo} structures.
    *
    * @return The contents octets.
    *
    * TODO Soo many exceptions.. Simplify please!!!
    */
   public ASN1Type getContent()
      throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
               BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      return new Data(getData());
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
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
      NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      content.crypt(in, out, Cipher.DECRYPT_MODE);
   }


   public byte[] decryptBulkData(byte[] b)
      throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
      BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      return content.crypt(b, 0, b.length, Cipher.DECRYPT_MODE);
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
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
      NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      content.crypt(in, out, Cipher.ENCRYPT_MODE);
   }


   public byte[] encryptBulkData(byte[] b)
      throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
      BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      return content.crypt(b, 0, b.length, Cipher.ENCRYPT_MODE);
   }



   // TODO Are all these getData/setData methods useful or just wasteful duplicates?



   /**
    * This method wraps the given bytes into a {@link Data} type and sets it as the content.
    * <p/>
    * Please note that the signing process implemented in this class does not care about the
    * content. Setting a content before signing does <b>not</b> sign the content. The data to
    * be signed must always be passed to one of the <code>update</code> methods.
    *
    * @param b The opaque contents to embed in this structure.
    * @exception IllegalStateException if the DEK is not initialised.
    */
   // TODO Evaluate catching all the crypto errors and encapsulating them in IOException
   public void setData(byte[] b)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
      BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      try(ByteArrayInputStream bis = new ByteArrayInputStream(b)) {
         content.setData(bis);
      }
   }


   /**
    * Encrypts the given data and inserts it as {@link Data} content. The stream is not closed.
    *
    * @exception IllegalStateException if the DEK is not initialised.
    */
   // TODO Evaluate catching all the crypto errors and encapsulating them in IOException
   public void setData(InputStream in)
      throws IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException,
      BadPaddingException, NoSuchAlgorithmException, InvalidKeyException
   {
      content.setData(in);
   }


   /**
    * Sets the content type to {@link Data} and clears the actual content. Call this method when
    * external data is signed, and no particular content type shall be used. This method calls
    * <code>setContentType(new ASN1ObjectIdentifier(DATA_OID))</code>.
    */
   public void setDataContentType()
   {
      setContentType(new ASN1ObjectIdentifier(Data.OID));
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
      return content.getData();
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
    * other words, this method is probably used only when reading EnvelopedData sent by someone
    * else but hardly ever if it is generated.
    * <p/>
    * Please note that, once this instance is properly initialised, additional recipients might
    * be added to it unless this structure is protected by integrity measures (such as wrapping
    * it in a {@link SignedData} structure.
    *
    * @param kdk The private <i>Key Decryption Key</i> required to decrypt the DEK.
    * @param cert The certificate matching the private key.
    *
    * @exception NoSuchElementException if no matching {@link RecipientInfo} is found in this
    *    instance.
    */
   public void init(X509Certificate cert, PrivateKey kdk)
      throws NoSuchElementException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
               NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException
   {
      RecipientInfo ri = getRecipientInfo(cert);
      if (ri == null) throw new NoSuchElementException("No such recipient exists!");
      content.init(kdk, ri);

      // TODO This is used by the recipient (that posses the PrivateKey) to gain access to the
      //  encrypted content. Rather than using an init method like this I would prefer some sort
      //  of decrypt method that returns an InputStream from which the decrypted content can be
      //  read.


   }


   /**
    * This method returns <code>true</code> if this instance is ready for encryption/decryption
    * without further initialisation.
    *
    * @return <code>true</code> if it is ready.
    */
   public boolean isReady()
   {
      return content.isReady();
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
