package org.xpertss.crypto.asn1;

import java.io.*;
import java.util.*;

/**
 * This is the root class of all ASN.1 time types. In principle, 
 * the known time types are all of type VisibleString.
 */
public abstract class ASN1Time extends ASN1PrintableString {
   /**
    * The <code>TimeZone</code> representing universal coordinated
    * time (UTC).
    */
   private static final TimeZone TZ = TimeZone.getTimeZone("GMT");

   /**
    * Used to fill with zeroes.
    */
   protected static final String ZEROES = "0000";

   /**
    * The internal storage of the date.
    */
   private Date date;



   public ASN1Time()
   {
      super();
   }

   public ASN1Time(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   
   public Object getValue()
   {
      return getDate();
   }
   
   
   
   /**
    * Returns a Java Date instance representing the time
    * in this ASN.1 time type.
    *
    * @return The time as a Java Date instance.
    */
   public Date getDate()
   {
      return (Date) date.clone();
   }


   /**
    * Returns a Java long representing the time in milliseconds
    * since January 1, 1970, 00:00:00 GMT in this ASN.1 time type.
    *
    * @return The number of milliseconds since January 1, 1970,
    *   00:00:00 GMT.
    */
   public long getTime()
   {
      return date.getTime();
   }


   /**
    * Sets the time from the given <code>Calendar</code>.
    *
    * @param calendar The <code>Calendar</code> with the date that
    *   shall be set.
    */
   public void setDate(Calendar calendar)
   {
      if (calendar == null) throw new NullPointerException("calendar");
      date = calendar.getTime();
      setString0(toString(date));
   }


   /**
    * Sets the time from the given Date instance.
    *
    * @param date The Date.
    */
   public void setDate(Date date)
   {
      if (date == null)  throw new NullPointerException("date");
      this.date = (Date) date.clone();
      setString0(toString(this.date));
   }


   /**
    * Sets the time from the given time in milliseconds
    * since January 1, 1970, 00:00:00 GMT.
    *
    * @param time The number of milliseconds
    *   since January 1, 1970, 00:00:00 GMT.
    */
   public void setDate(long time)
   {
      date = new Date(time);
      setString0(toString(date));
   }


   /**
    * Sets the date to the one represented by the given string.
    * The internal string representation is normalized and
    * complies to DER. The date string is thus converted to
    * GMT.
    *
    * @param date The date as a X.680 date string.
    * @exception IllegalArgumentException if the string is
    *   not well-formed.
    * @exception StringIndexOutOfBoundsException if the string
    *   is not well-formed.
    */
   public void setDate(String date)
   {
      if (date == null)  throw new NullPointerException("date string");
      this.date = toDate(date);
      setString0(toString(this.date));
   }


   /**
    * Sets the string value.
    *
    * @param s The string value.
    */
   public void setString(String s)
   {
      date = toDate(s);

      /* The value must be set literally because this
       * method is called by the decoders. This ensures
       * that the encoding is bitwise identical to the
       * decoding.
       */
      setString0(s);
   }


   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeTime(this);
   }


   public void decode(Decoder enc)
      throws IOException
   {
      enc.readTime(this);
   }

   
   
   
   
   public ASN1Type copy()
   {
      try { 
         ASN1Time v = (ASN1Time) super.clone();
         if(date != null) v.date = (Date) date.clone();
         return v;
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }
   
   
   public boolean equals(Object obj)
   {
      if(obj instanceof ASN1Time && obj.getClass() == getClass()) {
         ASN1Time o = (ASN1Time) obj;
         return o.getString().equals(getString());
      }
      return false;
   }
   
   

   protected abstract int[] getFields();


   protected abstract int[] getFieldLengths();


   protected abstract int[] getFieldCorrections();


   /**
    * Converts the given <code>Date</code> into a string
    * representation according to DER as described in
    * X.690.
    *
    * @param date The <code>Date</code> that is converted.
    * @return The string with the date.
    */
   protected String toString(Date date)
   {
      if (date == null) throw new NullPointerException("date");
      Calendar cal = new GregorianCalendar(TZ);
      int[] fields = getFields();
      int[] correct = getFieldCorrections();
      int[] lengths = getFieldLengths();
      StringBuffer buf = new StringBuffer(20);

      /* Date is UTC time (most of the time ;-) and we
       * set Calendar to UTC.
       */
      cal.setTime(date);

      for (int n = 0; n < fields.length; n++) {
         int v = cal.get(fields[n]) - correct[n];
         String s = String.valueOf(v);
         int len = s.length();

         /* If the target length is zero then we truncate
          * to the left, and take only the hundreds if they
          * are greater than zero. Hence, only one digit is
          * printed. In summary, we handle the case of
          * milliseconds.
          */
         int w = lengths[n];

         if (w == 0) {
            if (v > 99) {
               buf.append(".");
               buf.append(s.charAt(0));
            }
            continue;
         }
         /* If we have to fill up then we fill zeroes to
          * the left. This accounts for days as well as
          * hours and minutes.
          */
         if (w < 0) w = -w;
         if (len < w) {
            buf.append(ZEROES.substring(0, w - len));
            buf.append(s);
         } else if (len > w) {
            /* If we must truncate then we take the rightmost
             * characters. This accounts for truncated years
             * e.g. "98" instead of "1998".
             */
            buf.append(s.substring(len - w));
         } else {
            /* Everything is fine, we got the length we need.
             */
            buf.append(s);
         }
      }
      buf.append('Z');

      return buf.toString();
   }


   /**
    * Converts the given string to a <code>Date</code> object.
    *
    * @param code The string encoding of the date to be converted.
    * @return The <code>Date</code> object.
    * @exception IllegalArgumentException if the given
    *   string is not a valid BER encoding of a date.
    */
   protected Date toDate(String code)
   {
      Calendar res;
      TimeZone tz;
      String s;
      int pos;
      int n;
      int v;
      int c;

      if (code == null) throw new NullPointerException("code");
      Calendar cal = new GregorianCalendar(TZ);
      int[] fields = getFields();
      int[] correct = getFieldCorrections();
      int[] lengths = getFieldLengths();
      int len = code.length();

      for (pos = 0, n = 0; n < fields.length; n++) {
         /* If the field length is zero then we handle
          * milliseconds. In particular, we test whether
          * the milliseconds are present.
          */
         int w = lengths[n];

         if (w == 0) {
            /* No character, no period or comma, therefor
             * no milliseconds either.
             */
            if (pos >= len) continue;
            c = code.charAt(pos);

            /* No period or comma but another character
             * presumably means that there are no millis
             * but a time zone offset - or a bad code.
             */
            if (c != '.' && c != ',') continue;
            pos++;

            /* We have millis, and now we're gonna read
             * them!
             */
            for (v = 0; (v < 3 && pos < len); v++) {
               if (!Character.isDigit(code.charAt(pos))) break;
               pos++;
            }
            /* If we did not consume at least one digit
             * then we have a bad encoding.
             */
            if (v == 0)
               throw new IllegalArgumentException("Milliseconds format error!");
            s = code.substring(pos - v, pos);

            if (v < 3) {
               s = s + ZEROES.substring(0, 3 - v);
            }
            v = Integer.parseInt(s);
            v = v + correct[n];

            cal.set(fields[n], v);

            continue;
         }
         /* Here we deal with optional digit fields such
          * as seconds in BER.
          */
         if (w < 0) {
            w = -w;
            if (pos >= len || !Character.isDigit(code.charAt(pos))) continue;
         }
         /* We fetch the required number of characters
          * and try to decode them.
          */
         s = code.substring(pos, pos + w);
         v = Integer.parseInt(s);
         v = v + correct[n];
         pos = pos + w;

         /* Special case for UTCTime: we have to correct
          * for years before 1970.
          */
         if (fields[n] == Calendar.YEAR && lengths[n] == 2) {
            v = v + ((v < 70) ? 2000 : 1900);
         }
         cal.set(fields[n], v);
      }
      /* We still have to deal with time zone offsets and
       * time zone specifications - nasty stuff.
       */
      if (pos < len) {
         c = code.charAt(pos);

         /* If there is a '+' or '-' then we have a time
          * differential to GMT and no trailing 'Z'.
          */
         if (c == '+' || c == '-') {
            s = code.substring(pos, pos + 5);
            tz = TimeZone.getTimeZone("GMT" + s);
            pos = pos + 5;
         } else if (code.charAt(pos) != 'Z') {
            /* No time differential means we either have a 'Z' or a bad encoding. */
            throw new IllegalArgumentException("Illegal char in place of 'Z' (" + pos + ")");
         } else {
            /* We got the 'Z', thus we have GMT. */
            tz = TimeZone.getTimeZone("GMT");
            pos++;
         }
      } else {
         /* We reached the end of the string without encountering
          * a time differential or a 'Z', therefor we use the
          * local time zone. This should rarely happen unless
          * someone screws up. Nevertheless, it's a valid code.
          */
         tz = TimeZone.getDefault();
      }
      if (pos != len)
         throw new IllegalArgumentException("Trailing characters after encoding! (" + pos + ")");

      /* we now have a Calendar calibrated to GMT and a
       * time zone in tz. Now we merge both together in
       * order to get the correct time according to GMT.
       */
      res = Calendar.getInstance(tz);

      for (n = 0; n < fields.length; n++) {
         res.set(fields[n], cal.get(fields[n]));
      }
      return res.getTime();
   }

}
