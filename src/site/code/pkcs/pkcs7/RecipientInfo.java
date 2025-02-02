package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.x509.BadNameException;
import org.xpertss.crypto.x509.Name;
import org.xpertss.crypto.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
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
 * This class provides methods to create a RecipientInfo structure from a
 * certificate and a BEK. BEK stands for <i>Bulk Encryption Key</i>. The
 * BEK is in general a symmetric key that is used to encrypt bulk data. The
 * BEK is then encrypted with the public key of the recipient of the bulk
 * data. The public key is sometimes called the
 * <i>Key Encryption Key</i> (KEK).<p>
 *
 * The BEK can be retrieved easily from instances of this structure as long
 * as the algorithm of the DEK is known. This information is not stored in
 * this class but in the {@link EncryptedContentInfo EncryptedContentInfo}
 * structure, which contains RecipientInfo structures for each intended
 * recipient of the bulk data.<p>
 *
 * This class is completely JCE integrated. It determines the instances to
 * use for encrypting and decrypting based on the OID contained in its
 * instances. The OID are mapped to algorithm names and vice versa by the
 * {@link Translator Translator}, which requires appropriate aliases to be
 * defined for algorithm implementations as described in the JCE
 * documentation. If your installed providers do not support the aliasing
 * scheme then request such support from your provider's supplier, or add a
 * provider that properly defines the aliases (aliases are global to all
 * providers).
 */
public class RecipientInfo extends ASN1Sequence {
   /**
    * The version number of this RecipientInfo.
    */
   protected ASN1Integer version_;

   /**
    * The issuer name.
    */
   protected X500Principal issuer_;

   /**
    * The serial number.
    */
   protected ASN1Integer serial_;

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
      issuer_ = new Name();
      serial_ = new ASN1Integer();

      seq = new ASN1Sequence(2);
      seq.add(issuer_);
      seq.add(serial_);
      add(seq);

      /* Key Encryption Algorithm Identifier */
      cAlg_ = new AlgorithmIdentifier();
      add(cAlg_);

      /* Encrypted Key */
      ekey_ = new ASN1OctetString();
      add(ekey_);
   }


   /**
    * This method calls initialises this structure with
    * the given arguments. The given <code>bek</code> is
    * encrypted with the given public key. The algorithm
    * to use is determined by means of the OID in the
    * {@link AlgorithmIdentifier AlgorithmIdentifier}
    * that is embedded in the public key's encoding.
    * Decoding is done using a {@link SubjectPublicKeyInfo
    * SubjectPublicKeyInfo} instance.
    *
    * @param cert The certificate to use for encrypting
    *   the given <code>bek</code>.
    * @param bek The bulk encryption key.
    */
   public RecipientInfo(X509Certificate cert, Key bek)
      throws BadNameException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchPaddingException, NoSuchAlgorithmException
   {
      super(4);

      if (cert == null || bek == null)
         throw new NullPointerException("cert or bulk encryption key");
      /* Global structure and Version */
      version_ = new ASN1Integer(0);
      add(version_);

      /* Issuer and serial number */
      issuer_ = new Name(cert.getIssuerDN().getName());
      serial_ = new ASN1Integer(cert.getSerialNumber());

      ASN1Sequence seq = new ASN1Sequence(2);
      seq.add(issuer_);
      seq.add(serial_);
      add(seq);

      /* Extract algorithm identifier from the public key */
      PublicKey pub = cert.getPublicKey();
      SubjectPublicKeyInfo pki = new SubjectPublicKeyInfo(pub);
      AlgorithmIdentifier aid = pki.getAlgorithmIdentifier();

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
    * This method returns the encrypted bulk encryption
    * key. The returned byte array is a copy. Modifying
    * it causes no side effects.
    *
    * @return The encrypted key.
    */
   public byte[] getEncryptedKey()
   {
      return (byte[]) ekey_.getByteArray().clone();
   }


   /**
    * This method returns the decrypted data encryption
    * key stored in this structure.
    *
    * @param kdk The private key decryption key.
    * @param bekalg The name of the algorithm of the
    *   encrypted bulk encryption key.
    * @exception NoSuchAlgorithmException if the OID cannot
    *   be mapped onto a registered algorithm name.
    */
   public SecretKey getSecretKey(PrivateKey kdk, String bekalg)
      throws CryptoException
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
      return issuer_;
   }


   /**
    * Returns the serial number.
    *
    * @return The serial number.
    */
   public BigInteger getSerialNumber()
   {
      return serial_.getBigInteger();
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
    * This method returns the resolved key encryption
    * algorithm name that can be used for requesting
    * JCE Cipher implementations. This method uses
    * {@link JCA JCA}. If the name consists of an
    * OID then either the appropriate algorithms are not
    * supported by the installed JCE Providers or the
    * aliases defined by those Providers are incomplete.
    *
    * @return The name of the key encryption algorithm
    *   that is required for decrypting the DEK this
    *   structure.
    */
   public String getAlgorithm()
   {
      String c,t;

      c = cAlg_.getAlgorithmOID().toString();
      t = JCA.getName(c);

      if (t != null) {
         return t;
      }
      return c;
   }


   /**
    * Returns a string representation of this object.
    *
    * @return The string representation.
    */
   public String toString()
   {
      StringBuffer buf = new StringBuffer();

      buf.append(
         "PKCS#7 RecipientInfo {\n" +
         "Version   : " + version_.toString() + "\n" +
         "Issuer    : " + issuer_.getName() + "\n" +
         "Serial    : " + serial_.toString() + "\n" +
         "Algorithm : " + getAlgorithm() + "\n" +
         "Enc. DEK  : " + ekey_.toString() + "\n}"
      );

      return buf.toString();
   }
}

