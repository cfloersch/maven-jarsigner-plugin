package org.xpertss.crypto.pkcs;

import org.xpertss.crypto.asn1.*;

import java.io.*;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * This class represents the ASN.1/DER value of the AlgorithmIdentifier defined in
 * Annex D to Recommendation X.509. This structure is extensively used for instance
 * in the PKCS standards of RSA Inc. The ASN.1 definition of this structure is as
 * given below:
 * <p>
 * <pre>
 * AlgorithmIdentifier  ::= SEQUENCE {
 *   algorithm  OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 * </pre>
 * <p>
 * The alias definitions are used by this class in order to find an AlgorithmParameters
 * implementation for the OID embedded in the ASN.1 AlgorithmIdentifier structure, and
 * to create the OID for a given AlgorithmParameters instances.
 */
public class AlgorithmIdentifier extends ASN1Sequence {

   /**
    * The algorithm parameters of the algorithm
    * specified by this algorithm identifier.
    */
   protected ASN1Opaque parameters_;

   /**
    * The OID of the algorithm.
    */
   protected ASN1ObjectIdentifier algorithm_;


   /**
    * This method  builds the tree of
    * ASN.1 objects used for decoding this structure.
    */
   public AlgorithmIdentifier()
   {
      super(2);
      algorithm_ = new ASN1ObjectIdentifier();
      parameters_ = new ASN1Opaque();
      parameters_.setOptional(true);
      add(algorithm_);
      add(parameters_);
   }


   public AlgorithmIdentifier(ASN1ObjectIdentifier oid)
   {
      super(2);
      if (oid == null) throw new NullPointerException("Need an OID!");
      algorithm_ = (ASN1ObjectIdentifier) oid.copy();
      parameters_ = new ASN1Opaque(ASN1.TAG_NULL, ASN1.CLASS_UNIVERSAL, new byte[0]);
      add(algorithm_);
      add(parameters_);
   }


   /**
    * Creates an instance with the given OID and opaque
    * algorithm parameter representation. Both the given
    * OID and the parameter encoding is cloned or copied.
    * No side effects occur if these arguments are modified
    * after completition of this constructor.
    *
    * @param oid The algorithm object identifier.
    * @param b The opaque DER encoding of the parameters for
    *   the algorithm known under the given OID. If no
    *   parameters are required then <code>null</code> might
    *   be passed. In that case {@link ASN1Null ASN.1 NULL}
    *   is encoded.
    * @exception IOException if the opaque representation does
    *   not contain a valid DER header and contents octets.
    */
   public AlgorithmIdentifier(ASN1ObjectIdentifier oid, byte[] b)
      throws IOException
   {
      super(2);
      if (oid == null) throw new NullPointerException("Need an OID!");
      algorithm_ = (ASN1ObjectIdentifier) oid.copy();
      if (b == null) {
         /* Usually, we'd define the following type as OPTIONAl. However, in case no
          * parameters are given a NULL is set instead.
          */
         parameters_ = new ASN1Opaque(ASN1.TAG_NULL, ASN1.CLASS_UNIVERSAL, new byte[0]);
      } else {
         parameters_ = new ASN1Opaque(b);
      }
      add(algorithm_);
      add(parameters_);
   }



   /**
    * Creates an instance that is initialised from the given AlgorithmParameters
    * instance. This method attempts to map the algorithm name to an ASN.1 OID
    * by calling {@link AlgorithmId#lookup(String)}.
    *
    * @param params The AlgorithmParameters.
    * @exception NullPointerException if <code>alg</code>
    *   is <code>null</code>.
    * @exception InvalidAlgorithmParameterException if the
    *   given parameters have a bad encoding, or the OID
    *   of the algorithm cannot be determined.
    */
   public AlgorithmIdentifier(AlgorithmParameters params)
      throws InvalidAlgorithmParameterException
   {
      super(2);
      try {
         // TODO This may be something that needs the Digest removed
         algorithm_ = AlgorithmId.lookup(params.getAlgorithm());
         parameters_ = new ASN1Opaque(params.getEncoded());
         add(algorithm_);
         add(parameters_);
      } catch (NoSuchAlgorithmException e) {
         throw new InvalidAlgorithmParameterException("Cannot determine OID for algorithm " + params.getAlgorithm());
      } catch (ASN1Exception e) {
         throw new InvalidAlgorithmParameterException("Parameter encoding is not ASN.1/DER!");
      } catch (IllegalArgumentException e) {
         throw new InvalidAlgorithmParameterException("Bad OID alias for algorithm " + params.getAlgorithm());
      } catch (IOException e) {
         throw new InvalidAlgorithmParameterException("Error during parameter encoding!");
      }
   }


   /**
    * Creates an instance with the given OID and parameters.
    * The parameters are encoded according to DER and stored
    * by means of an opaque type. If the given parameters
    * are <code>null</code> then an ASN.1 NULL is encoded.
    *
    * @param oid The OID to use.
    * @param params The ASN.1 type of which the parameters
    *   consist.
    * @exception IOException if the given parameters
    *   cannot be encoded. This should rarely happen.
    */
   public AlgorithmIdentifier(ASN1ObjectIdentifier oid, ASN1Type params)
      throws IOException
   {
      super(2);
      if (oid == null) throw new NullPointerException("OID required!");
      algorithm_ = (ASN1ObjectIdentifier) oid.copy();
      if (params == null || (params instanceof ASN1Null)) {
         parameters_ = new ASN1Opaque(ASN1.TAG_NULL, ASN1.CLASS_UNIVERSAL, new byte[0]);
      } else {
         parameters_ = new ASN1Opaque(AsnUtil.encode(params));
      }
      add(algorithm_);
      add(parameters_);
   }


   /**
    * This method locates a suitable {@link
    * AlgorithmParameters AlgorithmParameters}
    * implementation if it is available from the JCE
    * compliant security providers that are installed
    * locally.<p>
    *
    * Such providers need to specify the following aliases
    * for this to work:
    * <ul>
    * <li> AlgorithmParameters.MyAlg = <i>class</i>
    * <li> Alg.Alias.AlgorithmParameters.1.2.3.4 = MyAlg
    * </ul>
    * If you ever want to test a provider for compliance
    * with the JCE and <i>cleverness</i>, test it against
    * the FhG-IGD PKCS package. If it doesn't work then
    * better demand fixes from the provider's vendor.<p>
    *
    * This method may be called only if this instance is
    * initialised properly either by specifying
    * AlgorithmParameters in a constructor or by parsing
    * a valid ASN.1/DER encoding.
    *
    * @exception NoSuchAlgorithmException if no matching
    *   AlgorithmParameters engine is found.
    * @exception InvalidAlgorithmParameterException if
    *   the parameters cannot be decoded properly.
    * @return The AlgorithmParameters or <code>null</code> if
    *   none are enclosed in this structure.
    */
   public AlgorithmParameters getParameters()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
   {
      // TODO: this may be a problem.
      if (parameters_.isOptional()) return null;
      if (parameters_.getTag() == ASN1.TAG_NULL && parameters_.getTagClass() == ASN1.CLASS_UNIVERSAL)
         return null;

      String algorithmName = AlgorithmId.lookup(algorithm_);
      AlgorithmParameters params = AlgorithmParameters.getInstance(algorithmName);
      try {
         params.init(parameters_.getEncoded());
      } catch (IOException e) {
         throw new InvalidAlgorithmParameterException(e);
      }
      return params;
   }


   public ASN1Type getASNParameters()
   {
      return (ASN1Type) get(1);
   }


   /**
    * This method returns the OID of the algorithm represented
    * by this AlgorithmIdentifier. The OID returned is the
    * one used internally. Do not modify the returned OID!
    * Otherwise, side effects occur.
    *
    * @return The algorithm OID.
    */
   public ASN1ObjectIdentifier getAlgorithmOID()
   {
      return algorithm_;
   }


   /**
    * Returns a string representation of this object.
    *
    * @return The string representation.
    */
   public String toString()
   {
      return algorithm_.toString();
   }


   /**
    * This method returns <code>true</code> if the given
    * object is an instance of this class or a subclass
    * thereof and the algorithm OID of the given object
    * equals this object's algorithm OID.
    *
    * @return <code>true</code> if the given object equals
    *   this one.
    */
   public boolean equals(Object o)
   {
      if (!(o instanceof AlgorithmIdentifier)) return false;
      return algorithm_.equals(((AlgorithmIdentifier) o).getAlgorithmOID());
   }


   public int hashCode()
   {
      return algorithm_.hashCode();
   }


   /**
    * Returns a clone. The clone is a deep copy of this instance
    * except from the constraints. Constraints are copied by
    * reference.
    *
    * @return The clone.
    */
   public ASN1Type copy()
   {
      AlgorithmIdentifier aid = (AlgorithmIdentifier) super.copy();
      aid.clear();
      aid.algorithm_ = (ASN1ObjectIdentifier) algorithm_.copy();
      aid.parameters_ = (ASN1Opaque) parameters_.copy();
      aid.add(algorithm_);
      aid.add(parameters_);
      return aid;
   }


}

