package org.xpertss.crypto.asn1;

import java.util.Iterator;

/**
 * The basic interface for Java objects representing a constructed 
 * ASN.1 type such as a SEQUENCE or SET as specified in ITU-T 
 * Recommendation X.680.
 */
public interface ASN1Collection extends ASN1Type {

   
   /**
    * Returns the number of elements in this collection.  If this collection
    * contains more than <tt>Integer.MAX_VALUE</tt> elements, returns
    * <tt>Integer.MAX_VALUE</tt>.
    * 
    * @return the number of elements in this collection
    */
   int size();

   
   /**
    * Returns <tt>true</tt> if this collection contains no elements.
    *
    * @return <tt>true</tt> if this collection contains no elements
    */
   boolean isEmpty();

   
   /**
    * Returns <tt>true</tt> if this collection contains the specified
    * element.  More formally, returns <tt>true</tt> if and only if this
    * collection contains at least one element <tt>e</tt> such that
    * <tt>(o==null ? e==null : o.equals(e))</tt>.
    *
    * @param o element whose presence in this collection is to be tested.
    * @return <tt>true</tt> if this collection contains the specified
    *         element
    * @throws ClassCastException if the type of the specified element
    *           is incompatible with this collection (optional).
    * @throws NullPointerException if the specified element is null and this
    *         collection does not support null elements (optional).
    */
   boolean contains(ASN1Type o);

   
   /**
    * Returns an iterator over the elements in this collection.  There are 
    * no guarantees concerning the order in which the elements are returned
    * (unless this collection is an instance of some class that provides a
    * guarantee).
    * 
    * @return an <tt>Iterator</tt> over the elements in this collection
    */
   Iterator<ASN1Type> iterator();
   
   
   /**
    * Ensures that this collection contains the specified element. Returns 
    * <tt>true</tt> if this collection changed as a result of the call.  
    * (Returns <tt>false</tt> if this collection does not permit duplicates 
    * and already contains the specified element.)
    *
    * @param o element whose presence in this collection is to be ensured.
    * @return <tt>true</tt> if this collection changed as a result of the
    *         call
    * 
    * @throws UnsupportedOperationException <tt>add</tt> is not supported by
    *         this collection.
    * @throws ClassCastException class of the specified element prevents it
    *         from being added to this collection.
    * @throws NullPointerException if the specified element is null and this
    *         collection does not support null elements.
    * @throws IllegalArgumentException some aspect of this element prevents
    *         it from being added to this collection.
    */
   boolean add(ASN1Type o);


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
   ASN1Type set(int index, ASN1Type element);
   
   
   /**
    * Returns the element at the specified position in this collection.
    *
    * @param index the index of the element to return.
    * @return the element at the specified position in this collection.
    * 
    * @throws IndexOutOfBoundsException if the index is out of range (index
    *         &lt; 0 || index &gt;= size()).
    */
   ASN1Type get(int index);
   
   
   /**
    * Removes a single instance of the specified element from this
    * collection, if it is present (optional operation).  More formally,
    * removes an element <tt>e</tt> such that <tt>(o==null ?  e==null :
    * o.equals(e))</tt>, if this collection contains one or more such
    * elements.  Returns true if this collection contained the specified
    * element (or equivalently, if this collection changed as a result of 
    * the call).
    *
    * @param o element to be removed from this collection, if present.
    * @return <tt>true</tt> if this collection changed as a result of the
    *         call
    * 
    * @throws ClassCastException if the type of the specified element
    *           is incompatible with this collection (optional).
    * @throws NullPointerException if the specified element is null and this
    *         collection does not support null elements (optional).
    * @throws UnsupportedOperationException remove is not supported by this
    *         collection.
    */
   boolean remove(ASN1Type o);
   
   
   /**
    * Removes the element at the specified position in this collection. 
    * Shifts any subsequent elements to the left (subtracts one from 
    * their indices).  Returns the element that was removed from the
    * collection.
    *
    * @param index The index of the element to remove.
    * @return the element previously at the specified position.
    * @throws IndexOutOfBoundsException if the index is out of range (index
    *            &lt; 0 || index &gt;= size()).
    */
   ASN1Type remove(int index);
   
   
   /**
    * Removes all of the elements from this collection (optional operation).
    * This collection will be empty after this method returns unless it
    * throws an exception.
    *
    * @throws UnsupportedOperationException if the <tt>clear</tt> method is
    *         not supported by this collection.
    */
   void clear();
   
   
   /**
    * Compares the specified object with this collection for equality. 
    *
    * @param o Object to be compared for equality with this collection.
    * @return <tt>true</tt> if the specified object is equal to this
    * collection
    */
   boolean equals(Object o);

   
   /**
    * Returns the hash code value for this collection.  While the
    * <tt>Collection</tt> interface adds no stipulations to the general
    * contract for the <tt>Object.hashCode</tt> method, programmers should
    * take note that any class that overrides the <tt>Object.equals</tt>
    * method must also override the <tt>Object.hashCode</tt> method in order
    * to satisfy the general contract for the <tt>Object.hashCode</tt>method.
    * In particular, <tt>c1.equals(c2)</tt> implies that
    * <tt>c1.hashCode()==c2.hashCode()</tt>.
    *
    * @return the hash code value for this collection
    */
   int hashCode();
   
   
   
}
