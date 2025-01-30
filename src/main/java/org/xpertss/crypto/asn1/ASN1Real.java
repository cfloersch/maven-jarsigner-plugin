package org.xpertss.crypto.asn1;

import java.io.IOException;

/**
 * Represents an ASN.1 REAL. The corresponding Java 
 * type is java.lang.Double.
 */
public class ASN1Real extends ASN1AbstractType {

   /**
    * The value of this ASN.1 Real.
    */
   private Double value;


   public ASN1Real()
   {
      value = new Double(0);
   }

   public ASN1Real(boolean optional, boolean explicit)
   {
      super(optional, explicit);
      value = new Double(0);
   }

   public ASN1Real(double d)
   {
      value = new Double(d);
   }

   public ASN1Real(String d)
      throws NumberFormatException
   {
      value = new Double(d);
   }

   public ASN1Real(Double d)
   {
      if (d == null)
         throw new NullPointerException("Need a number!");
      value = d;
   }





   public Double getDouble()
   {
      return value;
   }

   public void setDouble(Double n)
      throws ConstraintException
   {
      value = n;
      checkConstraints();
   }


   public Object getValue()
   {
      return value;
   }



   public int getTag()
   {
      return ASN1.TAG_REAL;
   }


   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeReal(this);
   }

   public void decode(Decoder dec)
      throws IOException
   {
      dec.readReal(this);
      checkConstraints();
   }


   public String toString()
   {
      return "Real " + value.toString();
   }



   public ASN1Type copy()
   {
      try { 
         return (ASN1Real) super.clone();
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }


   int encodedLength()
   {
      if (isOptional()) return 0;
      long longBits = Double.doubleToLongBits(getDouble().doubleValue());
      long exp = (longBits & 0x7ff0000000000000L) >> 52;
      long mantissa = longBits &   0xfffffffffffffL;

      if(exp > 0L) {
          mantissa |= 0x10000000000000L;
          exp = exp - 1023L - 52L;
      } else {
          exp = exp - 1022L - 52L;
      }

      // Strip trailing zeros from mantissa
      while((mantissa & 1L) == 0L) {
          mantissa >>= 1;
          exp++;
      }

      long tmp = (exp >= 0L ? exp : ~exp) >> 7;
      byte expLen;
      for(expLen = 1; tmp != 0L; expLen++) tmp >>= 8;

      tmp = mantissa;
      byte mantissaLen;
      for(mantissaLen = 0; tmp != 0L; mantissaLen++) tmp >>= 8;

      return mantissaLen + expLen + 1;
   }



   /* default */ Double decodeBinary(DERDecoder dec, byte octet, int length)
      throws IOException
   {
      int sign;
      int base;
      int exponent;

      if ((octet & 0x40) > 0) sign = -1;
      else sign = 1;

      int bv = ((octet >> 4) & 0x03);
      if (bv == 2) base = 16;
      else if (bv == 1) base = 8;
      else if (bv == 0) base = 2;
      else throw new ASN1Exception("Unknown base encoded. Supports Base 2, 8, & 16 only!");


      int f = ((octet >> 2) & 0x03);


      int neo = 0;
      if ((octet & 0x02) > 0) {
         if ((octet & 0x01) > 0) {
            /* bits 2+1 = 11 */
            /* Following octet encodes the number of octets used to
             * encode the exponent.
             */
            neo = dec.read();
            exponent = dec.readTwosComplement(neo);
         } else {
            /* bits 2+1 = 10 */
            neo = 3;
            exponent = dec.readTwosComplement(neo);
         }
      } else if ((octet & 0x01) > 0) {
         /* bits 2+1 = 01 */
         neo = 2;
         exponent = dec.readTwosComplement(neo);
      } else {
         /* bits 2+1 = 00 */
         neo = 1;
         exponent = dec.readTwosComplement(neo);
      }

      int offset = (neo <= 3) ? 1 + neo : 2 + neo;
      long number = dec.readInt(length - offset);

      long mantissa = (long) (sign * number * Math.pow(2, f));
      return new Double((double) mantissa * Math.pow((double)base,(double)exponent));

   }



   /* default */ Double decodeDecimal(DERDecoder dec, byte octet, int length)
      throws IOException
   {
      // This is fairly loose compared to the real standards.
      byte[] buf = new byte[length - 1];
      if(dec.read(buf) < buf.length)
         throw new ASN1Exception("Unexpected end of file");
      try {
         return new Double(AsnUtil.fixDecimal(new String(buf, "ASCII")));
      } catch(NumberFormatException nfe) {
         throw new ASN1Exception("Unknown ASN Real Encoding!");
      }
   }


   /* default */ void encodeBinary(DEREncoder enc)
      throws IOException
   {

      long longBits = Double.doubleToLongBits(value.doubleValue());
      long exp = (longBits & 0x7ff0000000000000L) >> 52;
      long mantissa = longBits &   0xfffffffffffffL;

      if(exp > 0L) {
          mantissa |= 0x10000000000000L;
          exp = exp - 1023L - 52L;
      } else {
          exp = exp - 1022L - 52L;
      }

      // Strip trailing zeros from mantissa
      while((mantissa & 1L) == 0L) {
          mantissa >>= 1;
          exp++;
      }

      long tmp = (exp >= 0L ? exp : ~exp) >> 7;
      byte expLen;
      for(expLen = 1; tmp != 0L; expLen++) tmp >>= 8;

      tmp = mantissa;
      byte mantissaLen;
      for(mantissaLen = 0; tmp != 0L; mantissaLen++) tmp >>= 8;

      // Write out our header including length
      enc.writeHeader(this, true);


      // Write out first content octet (describes encoding)
      enc.write(((longBits <= 0L ? 192 : 128) + expLen) - 1);

      // Write the exponent
      enc.writeInt(expLen, exp);

      // Write the mantissa
      enc.writeInt(mantissaLen, mantissa);

   }



}


/**

NUM
Integer types are defined by NR1 from ISO 6093:1985 standard.

NR1 ::= unsigned-NR1 | signed-NR1 .
unsigned-NR1 ::= {space} figure {figure}.
signed-NR1 ::= {space} [sign] figure {figure}.
space ::= SPACE .
figure ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9".
sign ::= "+" | "-".



REAL
Decimal figure types are defined by NR2 ISO 6093:1985 standard.

REAL ::=  NR2 .
NR2 ::= unsigned-NR2 | signed-NR2 .
Unsigned-NR2 ::= {space} figure {figure} decimal separator {figure} | {space}{figure}decimal separator figure {figure}.
Signed-NR2 ::=  {space} [sign] figure {figure}decimal separator{figure} | {space} [sign] {figure} decimal separator figure {figure}.
space ::=  SPACE .
figure ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9".
decimal separator ::= "," | "." .
sign ::= "+" | "-".



EXP
Decimal figure types are defined by NR3 from the standard for exponential notation ISO 6093:1985.

EXP ::=  NR3 .
NR3 ::= unsigned-NR3 | signed-NR3 .
unsigned-NR3 ::= {space} mantisse exponent marking characterestics .
signed-NR3 ::= {space}[sign] mantisse exponent marking characterestics .
mantisse ::= (figure {figure} decimalcharacter {figure}) | ({figure}decimalcharacter figure {figure}) .
characteristics ::= [space] figure {figure} .
space ::= SPACE .
figure ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9".
sign ::= "+" | "-".
decimalcharacter ::= "," | "." .
exponent marking ::= "E" | "e".









III.1 A sender will normally examine his own hardware floating point representation to determine
the (value-independent) algorithms to be used to transfer values between this floating-point
representation and the length and contents octets of the encoding of an ASN.1 real value. This
Appendix illustrates the steps which would be taken in such a process by using the (artificial)
hardware floating point representation of the mantissa shown in Figure III-1/X.209.

It is assumed that the exponent can easily be obtained from the floating point hardware as an
integer value E.

III.2 The contents octets which need to be generated for sending a non-zero value (as specified in
the body of this Recommendation) are:

1 S bb ff ee Octets for E Octets for N

where S (the mantissa sign) is dependent on the value to be converted, bb is a fixed value (say 10)
to represent the base (in this case let us assume base 16), ff is the fixed F value calculated as
described in � III.3, and ee is a fixed length of exponent value calculated as described in �
III.4 (this Appendix does not treat the case where E needs to exceed three octets).

III.3 The algorithm will transmit octets 1 to 5 of the hardware representation as the value of N,
after forcing bits 8 to 3 of octet 1 and bits 4 to 1 of octet 5 to zero. The implied decimal point
is assumed to be positioned between bits 2 and 1 of octet in the hardware representation which
delivers the value of E. Its implied position can be shifted to the nearest point after the end of
octet 6 by reducing the value of E before transmission. In our example system we can shift by four
bits for every exponent decrement (because we are assuming base 16), so a decrement of 9 will
position the implied point between bits 6 and 5 of octet 6. Thus the value of M is N multiplied by
23 to position the point correctly in M. (The implied position N, the octets transferred, is after
bit 1 of octet 5.) Thus we have the crucial parameters:

F = 3 (so ff is 11)
exponent decrement = 9

III.4 The length needed for the exponent is now calculated by working out the maximum number of
octets needed to represent the values

Emin � excess � exponent decrement
Emax � excess � exponent decrement

where Emin and Emax are minimum and maximum integer values of the exponent representation, excess is
any value which needs subtracting to produce the true exponent value, and the exponent decrement is
as calculated in � III.3. Let us assume this gives a length of 3 octets. Then ee is 10. Let us also
assume excess is zero.

III.5 The transmission algorithm is now:

a) test for zero, and if so, transmit an ASN.1 length of zero (no contents octets) and end the algorithm;

b) test and remember the mantissa sign, and negate the mantissa if negative;

c) transmit an ASN.1 length of 9, then

1 1 10 11 10 if negative

or

1 0 10 11 10 if positive

d) produce and transmit the 3 octet exponent with value

E � 9

e) zero bits 8 to 3 of octet 1 and bits 4 to 1 of octet 5, then transmit the 5 octet mantissa.

III.6 The receiving algorithm has to be prepared to handle any ASN.1 format, but here the floating point
unit can be directly used. We proceed as follows:

a) check octet 1 of the contents; if it is 1x101110 we have a transmission compatible with ours, and can
simply reverse the sending algorithm;

b) otherwise, for character encoding invoke standard character decimal to floating point conversion
software, and deal with a "SpecialRealValue" according to the application semantics (perhaps setting
the largest and smallest number the hardware floating point can handle);

c) for a binary transmission, put N into the floating point unit, losing octets at the least significant
end if necessary, multiply by 2F, and by BE, then negate if necessary. Implementors may find optimisation
possible in special cases, but may find (apart from the optimisation relating to transmissions from a
compatable machine) that testing for them loses more than they gain.

III.7 The above algorithms are illustrative only. Implementors will, of course, determine their own best
strategies.




 */