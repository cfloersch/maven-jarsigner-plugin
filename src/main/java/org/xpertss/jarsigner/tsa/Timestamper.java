package org.xpertss.jarsigner.tsa;

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
    public TSResponse generateTimestamp(TSRequest tsQuery) throws IOException;

}
