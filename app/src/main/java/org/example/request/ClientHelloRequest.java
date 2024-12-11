package org.example.request;

import java.nio.ByteBuffer;

public record ClientHelloRequest(
        short smpversion
) {
    public byte[] getBytes() {
        ByteBuffer b = ByteBuffer.allocate(2);
        b.putShort(smpversion);
        return b.array();
    }
}
