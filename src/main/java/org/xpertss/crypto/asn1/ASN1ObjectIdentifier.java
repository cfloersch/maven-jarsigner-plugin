package org.xpertss.crypto.asn1;

import java.util.StringTokenizer;
import java.io.IOException;


/**
 * Represents an ASN.1 OBJECT IDENTIFIER type. The corresponding Java
 * type is <code>int[]</code>. Constraints are checked for this type
 * only at the end of method {@link #decode decode}.
 */
public class ASN1ObjectIdentifier extends ASN1AbstractType implements Cloneable, Comparable {

   private int[] value = new int[2];


   public ASN1ObjectIdentifier()
   {
      super();
   }

   public ASN1ObjectIdentifier(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given array of integers
    * as elements. No constraints are checked by this
    * constructor.
    *
    * @param oid The array of consecutive integers of the
    *   OID.
    * @exception NullPointerException if the given <code>oid
    *   </code> is <code>null</code>.
    * @exception IllegalArgumentException if the given <code>
    *   oid</code> is not well-formed. For instance, a bad
    *   <code>oid</code> might have a value greater than 2
    *   as its first element.
    */
   public ASN1ObjectIdentifier(int[] oid)
   {
      set0(oid);
   }


   /**
    * Creates an ASN.1 OBJECT IDENTIFIER instance initialised from 
    * the given OID string representation. The format must be 
    * 1.2.3.4 for the initiliser to work properly. Trailing dots 
    * are ignored.
    *
    * @exception NumberFormatException if some element
    *   of the OID string is not an integer number.
    * @exception IllegalArgumentException if the string
    *   is not a well-formed OID.
    */
   public ASN1ObjectIdentifier(String s)
   {
      if(s == null) throw new NullPointerException("OID is undefined");
      int[] oid = new int[16];
      StringTokenizer tok = new StringTokenizer(s, ".");

      int n = 0;
      while (tok.hasMoreTokens()) {
         if (n >= oid.length)
            throw new IllegalArgumentException("OID has too many elements!");
         oid[n++] = Integer.parseInt(tok.nextToken());
      }
      value = new int[n];
      System.arraycopy(oid, 0, value, 0, n);
   }


   public Object getValue()
   {
      return getOID();
   }

   public int[] getOID()
   {
      return (int[]) value.clone();
   }


   public void setOID(int[] oid)
      throws ConstraintException
   {
      set0(oid);
      checkConstraints();
   }


   private void set0(int[] oid)
   {
      if (oid == null)
         throw new NullPointerException("Need an OID!");

      if (oid.length < 2)
         throw new IllegalArgumentException("OID must have at least 2 elements!");

      if (oid[0] < 0 || oid[0] > 2)
         throw new IllegalArgumentException("OID[0] must be 0, 1, or 2!");

      if (oid[1] < 0 || oid[1] > 39)
         throw new IllegalArgumentException("OID[1] must be in the range 0,..,39!");

      value = new int[oid.length];
      System.arraycopy(oid, 0, value, 0, oid.length);
   }


   public int elementCount()
   {
      return value.length;
   }

   public int getTag()
   {
      return ASN1.TAG_OID;
   }

   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeObjectIdentifier(this);
   }

   public void decode(Decoder dec)
      throws IOException
   {
      dec.readObjectIdentifier(this);
      checkConstraints();
   }


   /**
    * Returns the string representation of this OID. The string
    * consists of the numerical elements of the OID separated
    * by periods.
    *
    * @return The string representation of the OID.
    */
   public String toString()
   {
      StringBuffer buf = new StringBuffer();
      for (int i = 0; i < value.length; i++)
         buf.append(value[i] + ".");
      if (value.length > 0)
         buf.setLength(buf.length() - 1);
      return buf.toString();
   }


   /**
    * Compares two OIDs for equality. Two OIDs are
    * equal if the have the same number of elements
    * and all corresponding elements are equal.
    *
    * @param o The object to compare to.
    * @return <code>true</code> iff the given object
    *   is an ASN1ObjectIdentifier and iff it equals
    *   this one.
    */
   public boolean equals(Object o)
   {
      if (!(o instanceof ASN1ObjectIdentifier)) return false;

      ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) o;
      if (oid.value.length != value.length) return false;

      for (int i = 0; i < value.length; i++)
         if (value[i] != oid.value[i]) return false;

      return true;
   }

   /**
    * This method computes the hash code of this instance.
    * The hash code of this instance is defined as a hash
    * function of the underlying integer array.
    *
    * @return the hash code of this instance.
    */
   public int hashCode()
   {
      int h = 23;
      for (int i = 0; i < value.length; i++)
         h = h * 7 + value[i];
      return h;
   }


   /**
    * This method compares two OID and returns -1, 0, 1 if
    * this OID is less than, equal or greater than the given
    * one. OID are interpreted as strings of numbers. An OID
    * that is a prefix of another is always smaller than the
    * other.
    *
    * @param o The OID to compare to.
    * @return -1, 0, 1 if this OID is smaller than, equal to,
    *    or greater than the given OID.
    * @exception ClassCastException iff <code>o</code> is not
    *   an ASN1ObjectIdentifier.
    */
   public int compareTo(Object o)
   {
      int[] oid = ((ASN1ObjectIdentifier) o).value;

      int n = Math.min(value.length, oid.length);
      for (int i = 0; i < n; i++) {
         if (value[i] < oid[i]) return -1;
         else if (value[i] > oid[i]) return 1;
      }
      if (value.length > n) return 1;
      if (oid.length > n) return -1;
      return 0;
   }


   /**
    * This method determines whether the given OID is part
    * of the OID family defined by this OID prefix. In
    * other words, this method returns <code>true</code>
    * if this OID is a prefix of the given one.
    *
    */
   public boolean isPrefixOf(ASN1ObjectIdentifier o)
   {
      int i = value.length;
      if (o.value.length < i) return false;

      while (i > 0) {
         i--;
         if (value[i] != o.value[i]) return false;
      }
      return true;
   }


   /**
    * Returns a clone of this instance. This method is not
    * thread safe. The constraints are copied by reference.
    *
    * @return The clone.
    */
   public ASN1Type copy()
   {
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier();
      oid.value = new int[value.length];
      System.arraycopy(value, 0, oid.value, 0, value.length);
      oid.setConstraint(getConstraint());
      return oid;
   }
}





