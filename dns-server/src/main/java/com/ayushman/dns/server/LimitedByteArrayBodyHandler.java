package com.ayushman.dns.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/** Collects an HTTP body while enforcing a hard in-memory byte limit. */
final class LimitedByteArrayBodyHandler
        implements HttpResponse.BodyHandler<byte[]> {

    private final int maximumBytes;

    LimitedByteArrayBodyHandler(int maximumBytes) {
        if (maximumBytes <= 0) {
            throw new IllegalArgumentException(
                    "maximumBytes must be positive"
            );
        }
        this.maximumBytes = maximumBytes;
    }

    @Override
    public HttpResponse.BodySubscriber<byte[]> apply(
            HttpResponse.ResponseInfo responseInfo
    ) {
        return new LimitedSubscriber(maximumBytes);
    }

    private static final class LimitedSubscriber
            implements HttpResponse.BodySubscriber<byte[]> {

        private final int maximumBytes;
        private final ByteArrayOutputStream output;
        private final CompletableFuture<byte[]> body =
                new CompletableFuture<>();

        private Flow.Subscription subscription;
        private int receivedBytes;

        private LimitedSubscriber(int maximumBytes) {
            this.maximumBytes = maximumBytes;
            output = new ByteArrayOutputStream(
                    Math.min(maximumBytes, 8_192)
            );
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription newSubscription) {
            if (subscription != null) {
                newSubscription.cancel();
                return;
            }
            subscription = newSubscription;
            subscription.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            if (body.isDone()) {
                return;
            }
            try {
                for (ByteBuffer buffer : buffers) {
                    int length = buffer.remaining();
                    if (length > maximumBytes - receivedBytes) {
                        throw new IOException(
                                "policy snapshot response exceeds the byte limit"
                        );
                    }
                    byte[] chunk = new byte[length];
                    buffer.get(chunk);
                    output.writeBytes(chunk);
                    receivedBytes += length;
                }
                subscription.request(1);
            } catch (Exception failure) {
                subscription.cancel();
                body.completeExceptionally(failure);
            }
        }

        @Override
        public void onError(Throwable failure) {
            body.completeExceptionally(failure);
        }

        @Override
        public void onComplete() {
            body.complete(output.toByteArray());
        }
    }
}
