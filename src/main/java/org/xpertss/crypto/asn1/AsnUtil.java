package org.xpertss.crypto.asn1;

import java.io.*;

/**
 * Utility methods for encoding, decoding, and object 
 * tree printing.
 */
public class AsnUtil {


   /**
    * Encode a ASN Object into a byte array for transmittion or storage.
    */
   public static final byte[] encode(ASN1Type ansObj)
      throws IOException
   {
      DEREncoder enc = null;
      try {
         ByteArrayOutputStream bos = new ByteArrayOutputStream();
         enc = new DEREncoder(bos);
         ansObj.encode(enc);
         return bos.toByteArray();
      } finally {
         if(enc != null) enc.close();
      }
   }



   /**
    * Decode an encoded ASN Object from a byte array read from a transmittion
    * or storage. This is useful for ASN Types that are not defined in the
    * base ASN package. AKA if you have made your own constructed types.
    */
   public static final ASN1Type decode(ASN1Type ansObj, byte[] encoded)
      throws IOException
   {
      DERDecoder dec = null;
      try {
         ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
         dec = new DERDecoder(bis);
         ansObj.decode(dec);
         return ansObj;
      } finally {
         if(dec != null) dec.close();
      }
   }



   /**
    * Decode an encoded ASN Object from a byte array read from a transmittion
    * or storage. This will not decode proprietary constructed types but only
    * the basic ASN objects.
    */
   public static final ASN1Type decode(byte[] encoded)
      throws IOException
   {
      DERDecoder dec = null;
      try {
         ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
         dec = new DERDecoder(bis);
         return dec.readType();
      } finally {
         if(dec != null) dec.close();
      }
   }



   public static final void dump(ASN1Type ansObj)
   {
      System.out.println(ansObj);
   }

   public static final void dump(ASN1Type ansObj, PrintStream out)
   {
      out.println(ansObj);
   }



   public static final String fixDecimal(String str)
   {
      return str.trim().replace(',','.');
   }

}


