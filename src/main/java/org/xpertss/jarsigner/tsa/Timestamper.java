package org.xpertss.jarsigner.tsa;

import org.xpertss.crypto.pkcs.tsp.TimeStampRequest;
import org.xpertss.crypto.pkcs.tsp.TimeStampResponse;

import java.io.IOException;

public interface Timestamper {


    /*
     * Connects to the TSA and requests a timestamp.
     *
     * @param tsQuery The timestamp query.
     * @return The result of the timestamp query.
     * @throws IOException The exception is thrown if a problem occurs while
     *         communicating with the TSA.
     */
    //public TimeStampResponse generateTimestamp(TimeStampRequest tsQuery) throws IOException;
    public TimeStampResponse generateTimestamp(TimeStampRequest tsQuery) throws IOException;

}
