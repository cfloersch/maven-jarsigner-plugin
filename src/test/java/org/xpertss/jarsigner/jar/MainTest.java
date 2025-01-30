package org.xpertss.jarsigner.jar;

import org.junit.jupiter.api.Test;


import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {


    @Test
    public void testOrdering()
    {
        Map<String,String> attributes = new LinkedHashMap<>();
        attributes.put("1", "one");
        attributes.put("2", "two");
        attributes.put("3", "three");
        attributes.put("4", "four");
        attributes.put("5", "five");
        attributes.put("6", "six");
        attributes.put("7", "seven");
        attributes.put("8", "eight");
        attributes.put("9", "nine");
        Map<String,String> copy = Collections.unmodifiableMap(attributes);
        assertEquals("[1, 2, 3, 4, 5, 6, 7, 8, 9]", copy.keySet().toString());
    }


}