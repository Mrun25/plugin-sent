package io.kestra.plugin.sent.triggers;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

import io.kestra.core.http.HttpRequest;
import io.kestra.core.http.HttpResponse;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.executions.Execution;
import io.kestra.core.models.flows.Flow;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.services.WebhookService;
import io.kestra.core.utils.IdUtils;
import io.kestra.plugin.core.trigger.WebhookContext;

import jakarta.inject.Inject;

import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.*;

@KestraTest
class EventTriggerTest {
    private static final String SECRET = "whsec_abcdef1234567890";
    private static final String BODY = "{\"field\":\"message\",\"event\":\"message.received\",\"timestamp\":\"2026-10-01T12:00:00Z\",\"payload\":{\"message_id\":\"test-message\",\"text\":\"Test café\"}}";

    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private WebhookService webhookService;

    private EventTrigger trigger;
    private Flow flow;
    private WebhookService recording;
    private List<Execution> started;
    private EventTrigger.Output output;

    @BeforeEach
    void setup() {
        trigger = EventTrigger.builder().id(IdUtils.create()).type(EventTrigger.class.getName())
            .key("test-url-key").signingSecret(Property.ofValue(SECRET)).build();
        flow = Flow.builder().id("sent_" + IdUtils.create()).namespace("qa.sent").revision(1)
            .tasks(List.of()).triggers(List.of(trigger)).build();
        started = new ArrayList<>();
        output = null;
        recording = recordingWebhookService(false, null);
    }

    // WebhookService.startExecution returns void on Kestra 1.3 and a Mono on Kestra 2.x, so a
    // hand-written subclass can only compile against one of them. A Mockito answer adapts to
    // the runtime signature, which keeps this suite runnable against both versions.
    private WebhookService recordingWebhookService(boolean trackSubscription, AtomicBoolean subscribed) {
        return Mockito.mock(WebhookService.class, (Answer<Object>) invocation -> {
            var method = invocation.getMethod();
            return switch (method.getName()) {
                case "runContext" -> runContextFactory.of(Map.of());
                case "newExecution" -> {
                    output = (EventTrigger.Output) invocation.getArgument(3);
                    yield webhookService.newExecution(
                        invocation.getArgument(0),
                        invocation.getArgument(1),
                        invocation.getArgument(2),
                        invocation.getArgument(3)
                    );
                }
                case "startExecution" -> {
                    started.add(invocation.getArgument(0));
                    if (method.getReturnType().equals(void.class)) {
                        yield null;
                    }
                    // Kestra 2.x: the returned Mono is lazy, so record subscription.
                    yield trackSubscription ? Mono.fromRunnable(() -> subscribed.set(true)) : Mono.empty();
                }
                default -> throw new UnsupportedOperationException(method.getName());
            };
        });
    }

    @Test
    void rejectsToleranceAboveOneHour() throws Exception {
        trigger = EventTrigger.builder().id(trigger.getId()).type(EventTrigger.class.getName())
            .key("test-url-key").signingSecret(Property.ofValue(SECRET))
            .tolerance(Property.ofValue(Duration.ofHours(1).plusMillis(1))).build();
        assertEquals(HttpResponse.Status.BAD_REQUEST, evaluate(BODY, BODY, Instant.now().getEpochSecond(), false).getStatus());
        assertTrue(started.isEmpty());
    }

    @Test
    void acceptsToleranceAtOneHour() throws Exception {
        trigger = EventTrigger.builder().id(trigger.getId()).type(EventTrigger.class.getName())
            .key("test-url-key").signingSecret(Property.ofValue(SECRET))
            .tolerance(Property.ofValue(Duration.ofHours(1))).build();
        assertEquals(HttpResponse.Status.OK, evaluate(BODY, BODY, Instant.now().getEpochSecond(), false).getStatus());
        assertEquals(1, started.size());
    }

    @Test
    void rejectsReplacementCharactersAfterHttpDecoding() throws Exception {
        var body = BODY.replace("café", "�");
        assertEquals(HttpResponse.Status.BAD_REQUEST, evaluate(body, body, Instant.now().getEpochSecond(), false).getStatus());
        assertTrue(started.isEmpty());
    }

    @Test
    void validSignatureCreatesExecutionWithVerifiedOutput() throws Exception {
        var response = evaluate(BODY, BODY, Instant.now().getEpochSecond(), false);
        assertEquals(HttpResponse.Status.OK, response.getStatus());
        assertEquals(1, started.size());
        var execution = started.getFirst();
        assertEquals(flow.getId(), execution.getFlowId());
        assertEquals(trigger.getId(), execution.getTrigger().getId());
        assertEquals("message.received", output.getEvent());
        assertEquals("Test café", output.getPayload().get("text"));
        assertTrue(output.getDedupeKey().startsWith("event:message.received:"));
    }

    @Test
    void byteArrayBodyPreservesSignedUtf8() throws Exception {
        assertEquals(HttpResponse.Status.OK, evaluate(BODY, BODY, Instant.now().getEpochSecond(), true).getStatus());
        assertEquals(1, started.size());
        assertEquals("Test café", output.getPayload().get("text"));
    }

    @Test
    void tamperingCannotCreateAnExecution() throws Exception {
        assertEquals(HttpResponse.Status.UNAUTHORIZED, evaluate(BODY + " ", BODY, Instant.now().getEpochSecond(), false).getStatus());
        assertTrue(started.isEmpty());
        assertNull(output);
    }

    @Test
    void staleSignatureCannotCreateAnExecution() throws Exception {
        assertEquals(HttpResponse.Status.UNAUTHORIZED, evaluate(BODY, BODY, Instant.now().getEpochSecond() - 600, false).getStatus());
        assertTrue(started.isEmpty());
    }

    @Test
    void validButFilteredEventDoesNotCreateAnExecution() throws Exception {
        var delivered = BODY.replace("message.received", "message.delivered");
        assertEquals(HttpResponse.Status.NO_CONTENT, evaluate(delivered, delivered, Instant.now().getEpochSecond(), false).getStatus());
        assertTrue(started.isEmpty());
    }

    @Test
    void signedNullJsonIsRejectedWithoutAnExecution() throws Exception {
        assertEquals(HttpResponse.Status.BAD_REQUEST, evaluate("null", "null", Instant.now().getEpochSecond(), false).getStatus());
        assertTrue(started.isEmpty());
    }

    @Test
    void missingSignatureIsRejectedWithoutAnExecution() throws Exception {
        var request = HttpRequest.builder().method("POST").uri(URI.create("https://localhost/webhook/test"))
            .body(HttpRequest.StringRequestBody.of(BODY)).build();
        var context = WebhookContext.builder().request(request).flow(flow).trigger(trigger).webhookService(recording).build();
        assertEquals(HttpResponse.Status.BAD_REQUEST, trigger.evaluate(context).block().getStatus());
        assertTrue(started.isEmpty());
    }

    @Test
    void subscribesToMonoReturnedOnKestra2x() throws Exception {
        var subscribed = new AtomicBoolean(false);
        recording = recordingWebhookService(true, subscribed);
        assertEquals(HttpResponse.Status.OK, evaluate(BODY, BODY, Instant.now().getEpochSecond(), false).getStatus());
        assertEquals(1, started.size());
        var returnsVoid = WebhookService.class.getMethod("startExecution", Execution.class).getReturnType().equals(void.class);
        // On Kestra 1.3 the method returns void, so there is nothing to subscribe to; on 2.x the
        // trigger must subscribe, because a lazy Mono would otherwise never start the execution.
        assertEquals(!returnsVoid, subscribed.get());
    }

    private HttpResponse<?> evaluate(String body, String signedBody, long timestamp, boolean bytes) throws Exception {
        var time = Long.toString(timestamp);
        var signature = SentWebhookVerifier.computeSignature(SECRET, "test-endpoint", time, signedBody.getBytes(StandardCharsets.UTF_8));
        var request = HttpRequest.builder().method("POST").uri(URI.create("https://localhost/webhook/test"))
            .addHeader("X-Webhook-ID", "test-endpoint")
            .addHeader("X-Webhook-Timestamp", time)
            .addHeader("X-Webhook-Signature", signature)
            .body(bytes ? HttpRequest.ByteArrayRequestBody.of(body.getBytes(StandardCharsets.UTF_8)) : HttpRequest.StringRequestBody.of(body))
            .build();
        var context = WebhookContext.builder().request(request).flow(flow).trigger(trigger).webhookService(recording).build();
        return trigger.evaluate(context).block();
    }
}
