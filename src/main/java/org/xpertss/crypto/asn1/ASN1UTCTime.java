package org.xpertss.crypto.asn1;

import java.util.Calendar;
import java.util.Date;


/**
 * This is the root class of all ASN.1 time types. In principle, 
 * the known time types are all of type VisibleString. UTCTime 
 * is defined as
 * <tt>[{@link ASN1#TAG_UTCTIME UNIVESAL 23}] IMPLICIT VisibleString</tt>.
 */
public class ASN1UTCTime extends ASN1Time {
   /**
    * The <code>Calendar</code> fields used upon encoding
    * date values.
    */
   private static final int[] FIELDS = {
      Calendar.YEAR, Calendar.MONTH, Calendar.DATE,
      Calendar.HOUR_OF_DAY, Calendar.MINUTE, Calendar.SECOND
   };

   /**
    * The lengths of the encoded fields in characters.
    */
   private static final int[] LENGTHS = {
      2, 2, 2, 2, 2, -2
   };

   /**
    * Corrections to be applied to the fields of a <code>
    * Calendar</code>. Corrections are substracted from
    * <code>Calendar</code> fields on encoding, and are
    * added on decoding.
    */
   private static final int[] CORRECT = {
      0, -1, 0, 0, 0, 0
   };


   /**
    * Creates an instance. The value of this instance is set 
    * to the current date.
    */
   public ASN1UTCTime()
   {
      setDate(new Date());
   }


   /**
    * Creates an instance with the given date string. The date 
    * string must be well-formed according to the DER encoding 
    * of UTCTime.
    *
    * @param date The string representation of the date.
    * @exception IllegalArgumentException if the given string is not a valid date accoridng to X.680.
    * @exception StringIndexOutOfBoundsException if the string is not well-formed.
    */
   public ASN1UTCTime(String date)
   {
      setDate(date);
   }


   /**
    * Creates an instance with the given date.
    *
    * @param cal - The date.
    */
   public ASN1UTCTime(Calendar cal)
   {
      setDate(cal);
   }


   /**
    * Creates an instance with the given date.
    *
    * @param date The date.
    */
   public ASN1UTCTime(Date date)
   {
      setDate(date);
   }


   /**
    * Method declaration.
    */
   public int getTag()
   {
      return ASN1.TAG_UTCTIME;
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


}
