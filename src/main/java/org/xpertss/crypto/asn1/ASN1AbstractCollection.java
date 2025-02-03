package org.xpertss.crypto.asn1;

import java.util.Arrays;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.io.IOException;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * Represents an abstract collection of ASN.1 types such as 
 * a SEQUENCE or a SET. Since this class inherits from the 
 * Collection framework class ArrayList, ASN.1 types may be 
 * added conveniently just as object instances are added to 
 * a list.
 * <p>
 * Please note that constraints of collections are validated 
 * before encoding and after decoding. Invalid modification 
 * of a collection type can be detected on importing and 
 * exporting abstract collections. On DER encoding a collection
 * its constraint is validated twice since the DER encoding is 
 * a two-pass process.
 */
public abstract class ASN1AbstractCollection extends ASN1AbstractType implements ASN1Collection, Cloneable {


   /**
    * The array buffer into which the elements of the collection 
    * are stored. The capacity of the collection is the length of 
    * this array buffer.
    */
   private ASN1Type[] elementData;

   /**
    * The number of times this list has been <i>structurally modified</i>.
    */
   private int modCount = 0;

   /**
    * The size of the collection (the number of elements it contains).
    */
   private int size;

   
   
   
   public ASN1AbstractCollection()
   {
      this(10);
   }

   public ASN1AbstractCollection(int initialCapacity)
   {
      this(initialCapacity, false, true);
   }

   public ASN1AbstractCollection(boolean optional, boolean explicit)
   {
      this(10, optional, explicit);
   }

   public ASN1AbstractCollection(int initialCapacity, boolean optional, boolean explicit)
   {
      super(optional, explicit);
      if (initialCapacity < 0)
         throw new IllegalArgumentException("Illegal Capacity: " + initialCapacity);
      elementData = new ASN1Type[initialCapacity];
   }
   
   
   
   
   
// ASNCollection impl   
   
   /**
    * Returns the number of elements in this collection.
    *
    * @return  the number of elements in this collection.
    */
   public int size() 
   {
      return size;
   }

   /**
    * Tests if this collection has no elements.
    *
    * @return  <tt>true</tt> if this collection has no elements;
    *          <tt>false</tt> otherwise.
    */
   public boolean isEmpty() 
   {
      return size == 0;
   }
   
   /**
    * Returns <tt>true</tt> if this collection contains the specified 
    * element.
    *
    * @param elem element whose presence in this collection is to be tested.
    * @return  <code>true</code> if the specified element is present;
    *    <code>false</code> otherwise.
    */
   public boolean contains(ASN1Type elem) 
   {
      if (elem == null) {
         for (int i = 0; i < size; i++) {
            if (elementData[i] == null) return true;
         }
      } else {
         for (int i = 0; i < size; i++) {
            if (elem.equals(elementData[i])) return true;
         }
      }
      return false;
   }


   
   /**
    * Appends the specified element to the end of this collection.
    *
    * @param o element to be appended to this collection.
    * @return <tt>true</tt> (as per the general contract of Collection.add).
    */
   public boolean add(ASN1Type o) 
   {
      ensureCapacity(size + 1);  // Increments modCount!!
      elementData[size++] = o;
      return true;
   }

   public boolean addAll(ASN1Type ... o)
   {
      ensureCapacity(size + o.length);  // Increments modCount!!
      System.arraycopy(o, 0, elementData, size, o.length);
      size += o.length;
      return true;
   }


   
   /**
    * Replaces the element at the specified position in this collection 
    * with the specified element.
    *
    * @param index    The index of the element to replace.
    * @param element  The element to be stored at the specified position.
    * @return the element previously at the specified position.
    * @throws    IndexOutOfBoundsException if index out of range
    *      <tt>(index &lt; 0 || index &gt;= size())</tt>.
    */
   public ASN1Type set(int index, ASN1Type element) 
   {
      if (index >= size) 
         throw new IndexOutOfBoundsException("Index: " + index + ", Size: " + size);
      ASN1Type oldValue = elementData[index];
      elementData[index] = element;
      return oldValue;
   }
   
   
   /**
    * Returns the element at the specified position in this collection.
    *
    * @param  index  The index of element to return.
    * @return the element at the specified position in this collection.
    * @throws IndexOutOfBoundsException if index is out of range <tt>(index
    *         &lt; 0 || index &gt;= size())</tt>.
    */
   public ASN1Type get(int index) 
   {
      if (index >= size) 
         throw new IndexOutOfBoundsException("Index: " + index + ", Size: " + size);
      return elementData[index];
   }
   
   
   /**
    * Removes a single instance of the specified element from this
    * collection, if it is present (optional operation).  More formally,
    * removes an element <tt>e</tt> such that <tt>(o==null ? e==null :
    * o.equals(e))</tt>, if the collection contains one or more such
    * elements.  Returns <tt>true</tt> if the collection contained the
    * specified element (or equivalently, if the collection changed as a
    * result of the call).<p>
    *
    * This implementation iterates over the collection looking for the
    * specified element.  If it finds the element, it removes the element
    * from the collection using the iterator's remove method.<p>
    *
    * Note that this implementation throws an
    * <tt>UnsupportedOperationException</tt> if the iterator returned by this
    * collection's iterator method does not implement the <tt>remove</tt>
    * method and this collection contains the specified object.
    *
    * @param o element to be removed from this collection, if present.
    * @return <tt>true</tt> if the collection contained the specified
    *         element.
    * @throws UnsupportedOperationException if the <tt>remove</tt> method is
    *         not supported by this collection.
    */
   public boolean remove(ASN1Type o) 
   {
      for(Iterator<ASN1Type> it = iterator(); it.hasNext(); ) {
         if((o == null && it.next() == null) || (it.next().equals(o))) {
            it.remove();
            return true;
         }
      }
      return false;
   }
   
   
   /**
    * Removes the element at the specified position in this collection.
    * Shifts any subsequent elements to the left (subtracts one from 
    * their indices).
    *
    * @param index The index of the element to remove.
    * @return the element that was removed from the collection.
    * @throws    IndexOutOfBoundsException if index out of range <tt>(index
    *         &lt; 0 || index &gt;= size())</tt>.
    */
   public ASN1Type remove(int index) 
   {
      if (index >= size) 
         throw new IndexOutOfBoundsException("Index: " + index + ", Size: " + size);

      modCount++;
      ASN1Type oldValue = elementData[index];

      int numMoved = size - index - 1;
      if (numMoved > 0)
         System.arraycopy(elementData, index+1, elementData, index, numMoved);
      elementData[--size] = null;
      return oldValue;
   }
   
   
   /**
    * Removes all of the elements from this collection. The 
    * collection will be empty after this call returns. All
    * references are cleared for garbage collection.
    */
   public void clear() 
   {
      modCount++;
      for (int i = 0; i < size; i++) elementData[i] = null;
      size = 0;
   }
   
   
   
   
   
   /**
    * Returns an iterator over the elements in this collection in proper
    * sequence. 
    * 
    * @return an iterator over the elements in this collection in proper sequence.
    */
   public Iterator<ASN1Type> iterator()
   {
      return new Itr();
   }
   
   
   
   
   
   
   
   /**
    * Compares the specified object with this collection for equality.  
    * Returns <tt>true</tt> if and only if the specified object is also 
    * an ASN1Collection, both collections have the same size, and all 
    * corresponding pairs of elements in the two collections are 
    * <i>equal</i>.  (Two elements <tt>e1</tt> and <tt>e2</tt> are 
    * <i>equal</i> if <tt>(e1==null ? e2==null : e1.equals(e2))</tt>.)  
    * In other words, two collections are defined to be equal if they 
    * contain the same elements in the same order.
    *
    * @param o the object to be compared for equality with this collection.
    * 
    * @return <tt>true</tt> if the specified object is equal to this collection.
    */
   public boolean equals(Object o) 
   {
      if (o == this) return true;

      if(o instanceof ASN1Collection) {
         Iterator<ASN1Type> e1 = iterator();
         Iterator<ASN1Type> e2 = ((ASN1Collection) o).iterator();
         while(e1.hasNext() && e2.hasNext()) {
            Object o1 = e1.next();
            Object o2 = e2.next();
            if (!(Objects.equals(o1, o2))) return false;
         }
         return !(e1.hasNext() || e2.hasNext());
      }
      return false;
   }

   /**
    * Returns the hash code value for this collection. 
    *
    * @return the hash code value for this collection.
    */
   public int hashCode() 
   {
      int hashCode = 1;
      for(Iterator<ASN1Type> it = iterator(); it.hasNext(); ) {
         Object obj = it.next();
         hashCode = 31 * hashCode + (obj == null ? 0 : obj.hashCode());
      }
      return hashCode;
   }
   
   
   
   
   
   
   
   /**
    * Returns the Java type that corresponds to this ASN.1 type. The default implementation
    * returns a java.util.List.
    *
    * @return The collection used internally for storing the elements in this constructed ASN.1
    *    type.
    */
   public Object getValue()
   {
      return Stream.of(Arrays.copyOf(elementData, size))
                     .collect(Collectors.toList());
   }


   
   /**
    * Writes this collection to the given {@link Encoder encoder}.
    *
    * @param enc The encoder to write this type to.
    */
   public void encode(Encoder enc)
      throws IOException
   {
      checkConstraints();
      enc.writeCollection(this);
   }


   /**
    * Reads this collection from the given {@link Decoder decoder}. This type is initialised
    * with the decoded data. The components of the decoded collection must match the components
    * of this collection. If they do then the components are also initialised with the decoded
    * values. Otherwise, an exception is thrown.
    *
    * @param dec - The decoder to read from.
    */
   public void decode(Decoder dec)
      throws IOException
   {
      dec.readCollection(this);
      checkConstraints();
   }

   
   
   
   public ASN1Type copy()
   {
      try { 
         ASN1AbstractCollection v = (ASN1AbstractCollection) super.clone();
         v.elementData = new ASN1Type[size];
         for(int i = 0; i < size; i++) {
            if(elementData[i] != null) {
               v.elementData[i] = elementData[i].copy();
            } else {
               v.elementData[i] = null;
            }
         }
         v.modCount = 0;
         return v;
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }

   

   /**
    * Prints this collection. This default implementation derives a 
    * descriptive name from the name of the fully qualified name of 
    * this class (or that of the respective subclass). The last 
    * component of the class name is extracted and a prefix of 
    * &quot;ASN1&quot; is removed from it. Then the elements contained 
    * in this collection are printed.
    *
    * @return The string representation of this ASN.1 collection.
    */
   public String toString()
   {

      String s = getClass().getName();
      int n = s.lastIndexOf('.');

      if (n < 0) n = -1;

      s = s.substring(n + 1);
      if (s.startsWith("ASN1")) s = s.substring(4);

      StringBuffer buf = new StringBuffer(s);

      if (isOptional()) buf.append(" OPTIONAL");

      if (this instanceof ASN1CollectionOf)
         buf.append(" ").append( ((ASN1CollectionOf) this).getElementType().getName() );
      buf.append(" {\n");

      Iterator<ASN1Type> it = iterator();
      while (it.hasNext())
         buf.append(it.next()).append("\n");
      buf.append("}");
      return buf.toString();
   }
   
   
   
   /**
    * Increases the capacity of this <tt>ArrayList</tt> instance, if
    * necessary, to ensure  that it can hold at least the number of elements
    * specified by the minimum capacity argument. 
    *
    * @param   minCapacity   the desired minimum capacity.
    */
   private void ensureCapacity(int minCapacity) 
   {
      modCount++;
      int oldCapacity = elementData.length;
      if (minCapacity > oldCapacity) {
         ASN1Type[] oldData = elementData;
         int newCapacity = (oldCapacity * 3)/2 + 1;
         if (newCapacity < minCapacity) newCapacity = minCapacity;
         elementData = new ASN1Type[newCapacity];
         System.arraycopy(oldData, 0, elementData, 0, size);
      }
   }

   
   
   
   
   
   
   
   private class Itr implements Iterator<ASN1Type> {
      /**
       * Index of element to be returned by subsequent call to next.
       */
      int cursor = 0;

      /**
       * Index of element returned by most recent call to next or
       * previous.  Reset to -1 if this element is deleted by a call
       * to remove.
       */
      int lastRet = -1;

      /**
       * The modCount value that the iterator believes that the backing
       * List should have.  If this expectation is violated, the iterator
       * has detected concurrent modification.
       */
      int expectedModCount = modCount;

      public boolean hasNext() 
      {
         return cursor != size();
      }

      public ASN1Type next()
      {
         checkForComodification();
         try {
            ASN1Type next = ASN1AbstractCollection.this.get(cursor);
            lastRet = cursor++;
            return next;
         } catch(IndexOutOfBoundsException e) {
            checkForComodification();
            throw new NoSuchElementException();
         }
      }

      public void remove() 
      {
         if (lastRet == -1)
            throw new IllegalStateException();
         checkForComodification();

         try {
            ASN1AbstractCollection.this.remove(lastRet);
            if (lastRet < cursor) cursor--;
            lastRet = -1;
            expectedModCount = modCount;
         } catch(IndexOutOfBoundsException e) {
            throw new ConcurrentModificationException();
         }
      }

      final void checkForComodification() 
      {
         if (modCount != expectedModCount)
            throw new ConcurrentModificationException();
      }
   }
   
   
}
