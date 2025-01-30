package org.xpertss.crypto.asn1;

import java.io.IOException;
import java.math.BigInteger;


/**
 * Represents an ASN.1 ENUMERATED type. The corresponding 
 * Java type is java.math.BigInteger.
 * <p>
 * Note that at the moment there is no value checking
 * <p>
 * TODO Apparently, I should impl this kinda like Choice in
 * that it can have any number of values that are allowed.
 * When the value is set or decoded we need to check to
 * make sure that the value being set is one of the allowed
 * values. Allowed values are all integers but the value must
 * be a single integer value. (Some seem to suggest it must
 * be a positive integer). The value options are NOT encoded
 * with the object, only the value. NOTE in some cases the
 * numeric value options are named and thus a toString out
 * puts the value as a string rather than a numeric.
 */
public class ASN1Enumerated extends ASN1Integer {

   private BigInteger[] allowed;


   /**
    * Creates a new instance ready for parsing. The value of
    * this instance is set to 0.
    */
   public ASN1Enumerated()
   {
      super();
   }

   public ASN1Enumerated(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given int value.
    *
    * @param n The integer to initialise with.
    */
   public ASN1Enumerated(int n)
   {
      super(n);
   }


   /**
    * Creates a new instance with the given BigInteger as its
    * initial value.
    *
    * @param val The value.
    */
   public ASN1Enumerated(BigInteger val)
   {
      super(val);
   }



   /**
    * Creates an instance with the given allowed values.
    * TODO Replace with Map<BigInteger,String> where
    * key is allowed value and value is the name for
    * that entry.
    *
    * @param allowed The allowed values.
    */
   public ASN1Enumerated(int[] allowed)
   {
      this.allowed = new BigInteger[allowed.length];
      for(int i = 0; i < allowed.length; i++) {
         this.allowed[i] = BigInteger.valueOf(allowed[i]);
      }
   }


   /**
    * Creates a new instance with the given allowed
    * values.
    *
    * @param allowed The allowed values.
    */
   public ASN1Enumerated(BigInteger[] allowed)
   {
      this.allowed = allowed;
   }
   



   public void decode(Decoder dec)
      throws IOException
   {
      dec.readInteger(this);
      if(allowed != null) {
         BigInteger decoded = (BigInteger) getValue();
         for(int i = 0; i < allowed.length; i++) {
            if(decoded.equals(allowed[i])) {
               decoded = null;
               break;
            }
         }
         if(decoded != null) throw new ASN1Exception("Invalid value");
      }
      checkConstraints();
   }


   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeInteger(this);
   }


   public int getTag()
   {
      return ASN1.TAG_ENUMERATED;
   }


   public String toString()
   {
      // TODO Do we want to have named value show up here?
      // Of course it will only work when decoded
      return "Enumerated " + super.getValue().toString();
   }


}
