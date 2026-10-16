package io.kestra.plugin.sent.triggers;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.kestra.core.http.HttpRequest;
import io.kestra.core.http.HttpResponse;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.executions.Execution;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.queues.QueueException;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.core.services.WebhookService;
import io.kestra.plugin.core.trigger.AbstractWebhookTrigger;
import io.kestra.plugin.core.trigger.WebhookContext;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import reactor.core.publisher.Mono;

@SuperBuilder
@ToString
@EqualsAndHashCode(callSuper = true)
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow from a signed Sent webhook",
    description = "Receives Sent events at Kestra's native webhook URL. It requires `X-Webhook-ID`, `X-Webhook-Timestamp`, and `X-Webhook-Signature`; verifies HMAC-SHA256 in constant time before parsing and filtering the event. Kestra 1.3 supplies the body as a string: UTF-8 bytes are reconstructed without JSON reserialization. Non-UTF-8 charset declarations and U+FFFD replacement characters are rejected to prevent lossy decoding from changing signed bytes. Register the generated HTTPS URL manually in Sent."
)
@Plugin(examples = @Example(title = "Handle signed inbound-message events", full = true, code = """
    id: sent_inbound_events
    namespace: company.messaging

    tasks:
      - id: log_event_identifiers
        type: io.kestra.plugin.core.log.Log
        message: "Sent event {{ trigger.event }} with dedupe key {{ trigger.dedupeKey }}"

    triggers:
      - id: sent_webhook
        type: io.kestra.plugin.sent.triggers.EventTrigger
        key: "{{ secret('SENT_WEBHOOK_URL_KEY') }}"
        signingSecret: "{{ secret('SENT_WEBHOOK_SIGNING_SECRET') }}"
        events:
          - message.received
    """))
public class EventTrigger extends AbstractWebhookTrigger implements TriggerOutput<EventTrigger.Output> {
    private static final ObjectMapper MAPPER = JacksonMapper.ofJson();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    @Schema(title = "Sent signing secret", description = "Webhook secret returned by Sent, including the `whsec_` prefix. Store it as a Kestra secret.")
    @NotNull
    @PluginProperty(group = "connection", secret = true)
    @ToString.Exclude
    private Property<String> signingSecret;

    @Schema(title = "Events", description = "Event names or parent fields to accept. Use `*` to accept every verified event.")
    @Builder.Default
    @PluginProperty(group = "processing")
    private Property<List<String>> events = Property.ofValue(List.of("message.received"));

    @Schema(title = "Replay tolerance", description = "Maximum absolute difference from `X-Webhook-Timestamp`. Must be positive and at most one hour; Sent recommends five minutes.")
    @Builder.Default
    @PluginProperty(group = "reliability")
    private Property<Duration> tolerance = Property.ofValue(Duration.ofMinutes(5));

    @Override
    public Mono<HttpResponse<?>> evaluate(WebhookContext context) throws Exception {
        if (context.path() != null || context.request().getUri().getPath().endsWith("/")) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.NOT_FOUND));
        }

        if (!usesUtf8(context.request().getHeaders())) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.BAD_REQUEST));
        }
        var rawBody = rawBody(context.request().getBody());
        if (rawBody == null) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.BAD_REQUEST));
        }

        var runContext = context.webhookService().runContext(context.flow(), this);
        var rSigningSecret = runContext.render(signingSecret).as(String.class).orElse(null);
        var rTolerance = runContext.render(tolerance).as(Duration.class).orElse(Duration.ofMinutes(5));
        if (rTolerance.isNegative() || rTolerance.isZero() || rTolerance.compareTo(Duration.ofHours(1)) > 0) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.BAD_REQUEST));
        }

        var headers = context.request().getHeaders();
        var webhookId = header(headers, "X-Webhook-ID");
        var timestamp = header(headers, "X-Webhook-Timestamp");
        var signature = header(headers, "X-Webhook-Signature");
        var verification = SentWebhookVerifier.verify(
            rSigningSecret,
            webhookId,
            timestamp,
            signature,
            rawBody.bytes(),
            rTolerance,
            Clock.systemUTC()
        );
        if (verification == SentWebhookVerifier.Result.MISSING_HEADERS) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.BAD_REQUEST));
        }
        if (verification != SentWebhookVerifier.Result.VALID) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.UNAUTHORIZED));
        }

        Map<String, Object> event;
        try {
            event = MAPPER.readValue(rawBody.text(), MAP_TYPE);
        } catch (Exception e) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.BAD_REQUEST));
        }
        if (event == null) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.BAD_REQUEST));
        }
        var field = string(event.get("field"));
        var eventName = string(event.get("event"));
        var eventTimestamp = string(event.get("timestamp"));
        if (field == null || eventName == null || eventTimestamp == null || !(event.get("payload") instanceof Map<?, ?> rawPayload)) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.BAD_REQUEST));
        }

        var selected = runContext.render(events).asList(String.class);
        if (!accepts(selected, field, eventName)) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.NO_CONTENT));
        }

        @SuppressWarnings("unchecked")
        var payload = (Map<String, Object>) rawPayload;
        var output = Output.builder()
            .field(field)
            .event(eventName)
            .timestamp(eventTimestamp)
            .payload(payload)
            .webhookId(webhookId)
            .dedupeKey(dedupeKey(eventName, payload, rawBody.bytes()))
            .build();

        var maybeExecution = context.webhookService().newExecution(context, context.flow(), this, output);
        if (maybeExecution.isEmpty()) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.NO_CONTENT));
        }
        try {
            return toResponse(startExecution(context.webhookService(), maybeExecution.get()));
        } catch (QueueException e) {
            return Mono.just(HttpResponse.of(HttpResponse.Status.INTERNAL_SERVER_ERROR));
        }
    }

    // Any Mono error (QueueException, 2.x start TimeoutException) maps to 500 so nothing escapes evaluate (issue #9).
    static Mono<HttpResponse<?>> toResponse(Mono<Void> started) {
        return started
            .<HttpResponse<?>> thenReturn(HttpResponse.of(HttpResponse.Status.OK))
            .onErrorReturn(HttpResponse.of(HttpResponse.Status.INTERNAL_SERVER_ERROR));
    }

    // 1.3 returns void, 2.x a Mono: resolved reflectively so one JAR runs on both (issue #9)
    private static final Method START_EXECUTION_METHOD = findStartExecutionMethod();

    private static Method findStartExecutionMethod() {
        try {
            return WebhookService.class.getMethod("startExecution", Execution.class);
        } catch (NoSuchMethodException e) {
            throw new ExceptionInInitializerError(
                "WebhookService.startExecution is unavailable on this Kestra version: " + e
            );
        }
    }

    private static Mono<Void> startExecution(WebhookService service, Execution execution) throws QueueException {
        try {
            var result = START_EXECUTION_METHOD.invoke(service, execution);
            if (result instanceof Mono<?> mono) {
                return mono.then();
            }
            return Mono.empty();
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof QueueException queueException) {
                throw queueException;
            }
            throw new IllegalStateException("WebhookService.startExecution failed.", e.getCause());
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("WebhookService.startExecution is unavailable on this Kestra version.", e);
        }
    }

    static boolean accepts(List<String> selected, String field, String event) {
        return selected != null && selected.stream().filter(value -> value != null).map(String::trim)
            .anyMatch(value -> value.equals("*") || value.equals(field) || value.equals(event));
    }

    private static RawBody rawBody(HttpRequest.RequestBody body) {
        if (body instanceof HttpRequest.StringRequestBody text) {
            var charset = text.getCharset() == null ? StandardCharsets.UTF_8 : text.getCharset();
            // Kestra 1.3 decodes HTTP bodies before invoking plugins. Reject lossy
            // decoding so replacement characters cannot hide modified wire bytes.
            if (!StandardCharsets.UTF_8.equals(charset) || text.getContent().indexOf('\uFFFD') >= 0) {
                return null;
            }
            return new RawBody(text.getContent().getBytes(charset), text.getContent());
        }
        if (body instanceof HttpRequest.ByteArrayRequestBody bytes) {
            var charset = bytes.getCharset() == null ? StandardCharsets.UTF_8 : bytes.getCharset();
            return new RawBody(bytes.getContent(), new String(bytes.getContent(), charset));
        }
        return null;
    }

    private static boolean usesUtf8(HttpHeaders headers) {
        var contentType = header(headers, "Content-Type");
        if (contentType == null) {
            return true;
        }
        for (var parameter : contentType.split(";")) {
            var pair = parameter.trim().split("=", 2);
            if (pair.length == 2 && pair[0].trim().equalsIgnoreCase("charset")) {
                var charset = pair[1].trim().replace("\"", "");
                if (!charset.equalsIgnoreCase("utf-8") && !charset.equalsIgnoreCase("utf8")) {
                    return false;
                }
            }
        }
        return true;
    }

    private static String header(HttpHeaders headers, String name) {
        return headers == null ? null : headers.firstValue(name).orElse(null);
    }

    private static String string(Object value) {
        return value instanceof String text && !text.isBlank() ? text : null;
    }

    private static String dedupeKey(String eventName, Map<String, Object> payload, byte[] rawBody) {
        var messageId = string(payload.get("message_id"));
        var status = string(payload.get("message_status"));
        if (messageId != null && status != null) {
            return "message:" + messageId + ":" + status;
        }
        return "event:" + eventName + ":" + sha256(rawBody);
    }

    private static String sha256(byte[] value) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable.", e);
        }
    }

    private record RawBody(byte[] bytes, String text) {
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Event field", description = "Parent Sent event family, such as message or templates.")
        private final String field;

        @Schema(title = "Event name", description = "Granular Sent event name, such as message.delivered.")
        private final String event;

        @Schema(title = "Event timestamp", description = "ISO 8601 event-creation timestamp from the signed body.")
        private final String timestamp;

        @Schema(title = "Event payload", description = "Event-specific payload from the verified request. It may contain phone numbers or message content; avoid logging it wholesale.")
        private final Map<String, Object> payload;

        @Schema(title = "Webhook ID", description = "Sent webhook configuration UUID. This is not a unique delivery ID.")
        private final String webhookId;

        @Schema(title = "Dedupe key", description = "Payload-derived candidate key. Persist it atomically in a shared store if the flow needs cross-execution deduplication.")
        private final String dedupeKey;
    }
}
