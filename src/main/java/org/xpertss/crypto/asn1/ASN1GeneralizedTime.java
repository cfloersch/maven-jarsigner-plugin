package org.xpertss.crypto.asn1;

import java.util.Calendar;
import java.util.Date;


/**
 * This is the Generalized Time class. In principle, the known time 
 * types are all of type <code>VisibleString</code>. GeneralizedTime 
 * is defined as <code> [{@link ASN1#TAG_GENERALIZEDTIME UNIVERSAL 24}] 
 * IMPLICIT VisibleString</code>. This class automatically represents 
 * dates internally in a DER compliant format, and parses dates 
 * according to BER. The internal representation is not changed from 
 * BER to DER on decoding. This is to ensure that decoding and encoding 
 * restore bitwise identical encodings.
 */
public class ASN1GeneralizedTime extends ASN1Time {

   /**
    * The <code>Calendar</code> fields used upon encoding
    * date values.
    */
   private static final int[] FIELDS = {
      Calendar.YEAR, Calendar.MONTH, Calendar.DATE,
      Calendar.HOUR_OF_DAY, Calendar.MINUTE, Calendar.SECOND,
      Calendar.MILLISECOND
   };

   /**
    * The lengths of the encoded fields in characters.
    */
   private static final int[] LENGTHS = {
      4, 2, 2, 2, 2, -2, 0
   };

   /**
    * Corrections to be applied to the fields of a <code>
    * Calendar</code>. Corrections are substracted from
    * <code>Calendar</code> fields on encoding, and are
    * added on decoding.
    */
   private static final int[] CORRECT = {
      0, -1, 0, 0, 0, 0, 0
   };


   /**
    * Creates an instance. The value of this instance
    * is set to the current date.
    */
   public ASN1GeneralizedTime()
   {
      setDate(new Date());
   }

   public ASN1GeneralizedTime(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }



   /**
    * Creates an instance with the given date string. The date string must be
    * well-formed according to the BER.
    *
    * @param time - The string representation of the date.
    * @exception IllegalArgumentException if the given string has a bad format.
    * @exception StringIndexOutOfBoundsException if the string
    *   is not well-formed.
    */
   public ASN1GeneralizedTime(String time)
   {
      setDate(time);
   }


   /**
    * Creates an instance with the given date.
    *
    * @param cal The <code>Calendar</code>.
    */
   public ASN1GeneralizedTime(Calendar cal)
   {
      setDate(cal);
   }


   /**
    * Creates an instance with the given date.
    *
    * @param date The date.
    */
   public ASN1GeneralizedTime(Date date)
   {
      setDate(date);
   }


   /**
    * Creates an instance with the given number of milliseconds
    * since January 1, 1970, 00:00:00 GMT.
    *
    * @param time - The time as a long.
    */
   public ASN1GeneralizedTime(long time)
   {
      setDate(time);
   }






   protected int[] getFields()
   {
      return (int[]) FIELDS.clone();
   }


   protected int[] getFieldLengths()
   {
      return (int[]) LENGTHS.clone();
   }


   protected int[] getFieldCorrections()
   {
      return (int[]) CORRECT.clone();
   }


   public int getTag()
   {
      return ASN1.TAG_GENERALIZEDTIME;
   }

}
