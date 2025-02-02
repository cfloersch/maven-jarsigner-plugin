package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmId;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;


/**
 * This class represents a PKCS#7 RecipientInfo structure. It is defined as follows:
 * <pre>
 * RecipientInfo ::= SEQUENCE {
 *   version Version, -- 0 for version 1.5 of PKCS#7
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey
 * }
 *
 * EncryptedKey ::= OCTET STRING
 *
 * KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * </pre>
 * For completeness, we also present the structures referenced
 * in the RecipientInfo structure.
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *   issuer Name,
 *   serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER
 * </pre>
 * This class provides methods to create a RecipientInfo structure from a certificate
 * and a BEK. BEK stands for <i>Bulk Encryption Key</i>. The BEK is in general a
 * symmetric key that is used to encrypt bulk data. The BEK is then encrypted with
 * the public key of the recipient of the bulk data. The public key is sometimes
 * called the <i>Key Encryption Key</i> (KEK).
 * <p/>
 * The BEK can be retrieved easily from instances of this structure as long as the
 * algorithm of the DEK is known. This information is not stored in this class but in
 * the {@link EncryptedContentInfo} structure, which contains RecipientInfo
 * structures for each intended recipient of the bulk data.
 */
public class RecipientInfo extends ASN1Sequence {
   /**
    * The version number of this RecipientInfo.
    */
   protected ASN1Integer version_;

   /**
    * The issuer name serial number.
    */
   protected IssuerAndSerialNumber identity;

   /**
    * The {@link AlgorithmIdentifier KeyEncryptionAlgorithmIdentifier}.
    */
   protected AlgorithmIdentifier cAlg_;

   /**
    * The encrypted key.
    */
   protected ASN1OctetString ekey_;


   /**
    * The default constructor.
    */
   public RecipientInfo()
   {
      super(4);

      ASN1Sequence seq;

      /* Global structure and Version */
      version_ = new ASN1Integer(0);
      add(version_);

      /* Issuer and serial number */
      identity = new IssuerAndSerialNumber();
      add(identity);

      /* Key Encryption Algorithm Identifier */
      cAlg_ = new AlgorithmIdentifier();
      add(cAlg_);

      /* Encrypted Key */
      ekey_ = new ASN1OctetString();
      add(ekey_);
   }


   /**
    * Create a RecipientInfo wrapping the given {@code bulk encryption key} using the recipients
    * public key. The public key's algorithm is used to determined the algorithm identifier.
    *
    * @param cert The certificate to use for encrypting the given <code>bek</code>.
    * @param bek The bulk encryption key.
    */
   public RecipientInfo(X509Certificate cert, Key bek)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
               NoSuchPaddingException, NoSuchAlgorithmException
   {
      super(4);

      if (cert == null || bek == null)
         throw new NullPointerException("cert or bulk encryption key");
      /* Global structure and Version */
      version_ = new ASN1Integer(0);
      add(version_);

      /* Issuer and serial number */
      identity = new IssuerAndSerialNumber();
      add(identity);

      /* Extract algorithm identifier from the public key */
      PublicKey pub = cert.getPublicKey();

      // TODO Is this the correct algId
      // Are there AlgorithmParameters???
      ASN1ObjectIdentifier algId = AlgorithmId.lookup(pub.getAlgorithm());
      AlgorithmIdentifier aid = new AlgorithmIdentifier(algId);
      // TODO check if public key is keyUsage encryption?


      /* Initialise the cipher instance */
      Cipher cipher = Cipher.getInstance(pub.getAlgorithm());
      cipher.init(Cipher.ENCRYPT_MODE, pub);

      /* Key Encryption Algorithm Identifier */
      cAlg_ = (AlgorithmIdentifier) aid.copy();
      add(cAlg_);

      /* Encrypt the bulk encryption key. Better safe than
       * sorry - we check for bad return values from both
       * the key and the cipher. This already happened and
       * finding errors like this takes ages!
       */
      byte[] b = bek.getEncoded();

      if (b == null || b.length == 0)
         throw new InvalidKeyException("Key returns no or zero length encoding!");
      b = cipher.doFinal(b);

      if (b == null || b.length == 0)
         throw new InvalidKeyException("Cipher returned no data!");
      ekey_ = new ASN1OctetString(b);

      add(ekey_);
   }


   /**
    * This method returns the encrypted bulk encryption key. The returned byte array is a copy.
    * Modifying it causes no side effects.
    *
    * @return The encrypted key.
    */
   public byte[] getEncryptedKey()
   {
      return (byte[]) ekey_.getByteArray().clone();
   }


   /**
    * This method returns the decrypted data encryption key stored in this structure.
    *
    * @param kdk The private key decryption key.
    * @param bekalg The name of the algorithm of the encrypted bulk encryption key.
    * @exception NoSuchAlgorithmException if the OID cannot be mapped onto a
    *    registered algorithm name.
    *
    *    TODO Make sure this actually works
    */
   public SecretKey getSecretKey(PrivateKey kdk, String bekalg)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException
   {
      AlgorithmParameters params = cAlg_.getParameters();
      String alg = cAlg_.getAlgorithmOID().toString();
      Cipher cipher = Cipher.getInstance(alg);

      if (params == null) {
         cipher.init(Cipher.DECRYPT_MODE, kdk);
      } else {
         cipher.init(Cipher.DECRYPT_MODE, kdk, params);
      }
      byte[] b = ekey_.getByteArray();
      if (b.length == 0)
         throw new InvalidKeyException("No encrypted key available!");
      b = cipher.doFinal(b);
      if (b == null || b.length == 0)
         throw new InvalidKeyException("Cipher returned no data!");
      return new SecretKeySpec(b, bekalg);
   }


   /**
    * Returns the issuer name. The returned instance is the
    * one used internally. Modifying it causes side effects.
    *
    * @return The issuer Name.
    */
   public X500Principal getIssuerDN()
   {
      return identity.getIssuerDN();
   }


   /**
    * Returns the serial number.
    *
    * @return The serial number.
    */
   public BigInteger getSerialNumber()
   {
      return identity.getSerialNumber();
   }


   /**
    * This method returns the KeyEncryptionAlgorithmIdentifier.
    * The returned instance is the one used internally. Modifying
    * it causes side effects.
    *
    * @return The KeyEncryptionAlgorithmIdentifier.
    */
   public AlgorithmIdentifier getAlgorithmIdentifier()
   {
      return cAlg_;
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
         alg = AlgorithmId.lookup(cAlg_.getAlgorithmOID());
      } catch (Exception e) {
         alg = "<unknown>";
      }

      StringBuffer buf = new StringBuffer();

      buf.append("PKCS#7 RecipientInfo {").append("\n")
         .append("Version   : ").append(version_.toString()).append("\n")
         .append("Issuer    : ").append(identity.getIssuerDN().getName()).append("\n")
         .append("Serial    : ").append(identity.getSerialNumber().toString()).append("\n")
         .append("Algorithm : ").append(alg).append("\n")
         .append("Enc. DEK  : ").append(ekey_.toString()).append("\n}");

      return buf.toString();
   }
}

