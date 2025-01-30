package org.xpertss.crypto.asn1;

/**
 * Defines various constants used with ASN.1 such as the tag and type class
 * identifiers. The classes in this package are modelled along the lines of
 * ITU-T Recommendations X.680, X.681, X.682, X.690, and X.691. From now on
 * we assume the reader is familiar with ASN.1, BER, and DER.<p>
 *
 * This package defines a number of primitive types as specified by the basic
 * syntax in X.680. Based on these primitive types more complex types can be
 * created. We refer to these types as <i>compound types</i> or <i>
 * structures</i>. Below, we discuss how such types are constructed, encoded
 * and decoded using the classes in this package.
 */
public class ASN1 extends Object {

   public static final int TAG_EOC = 0;
   public static final int TAG_BOOLEAN = 1;
   public static final int TAG_INTEGER = 2;
   public static final int TAG_BITSTRING = 3;
   public static final int TAG_OCTETSTRING = 4;
   public static final int TAG_NULL = 5;
   public static final int TAG_OID = 6;
   public static final int TAG_REAL = 9;
   public static final int TAG_ENUMERATED = 10;
   public static final int TAG_UTF8STRING = 12;
   public static final int TAG_SEQUENCE = 16;
   public static final int TAG_SET = 17;
   public static final int TAG_NUMERICSTRING = 18;
   public static final int TAG_PRINTABLESTRING = 19;
   public static final int TAG_T61STRING = 20;
   public static final int TAG_VIDEOTEXTSTRING = 21;
   public static final int TAG_IA5STRING = 22;
   public static final int TAG_UTCTIME = 23;
   public static final int TAG_GENERALIZEDTIME = 24;
   public static final int TAG_GRAPHICSTRING = 25;
   public static final int TAG_VISIBLESTRING = 26;
   public static final int TAG_GENERALSTRING = 27;
   public static final int TAG_UNIVERSALSTRING = 28;
   public static final int TAG_BMPSTRING = 30;
   public static final int TAG_MASK = 0x1f;
   public static final int TAG_LONGFORM = 0x1f;

   public static final int CLASS_UNIVERSAL = 0x00;
   public static final int CLASS_APPLICATION = 0x40;
   public static final int CLASS_CONTEXT = 0x80;
   public static final int CLASS_PRIVATE = 0xc0;
   public static final int CLASS_MASK = 0xc0;

   public static final int PRIMITIVE = 0x00;
   public static final int CONSTRUCTED = 0x20;

   public static final int LENGTH_LONGFORM = 0x80;
   public static final int LENGTH_MASK = 0x7f;


   /**
    * No-one can instantiate this class.
    */
   private ASN1()
   {
   }

}
