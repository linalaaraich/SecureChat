package security;

import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimiter {
    private final Map<String, Queue<Long>> clientRequests = new ConcurrentHashMap<>();
    private final int MAX_REQUESTS = 100;
    private final long TIME_WINDOW = 60000; // 1 minute

    public boolean allowRequest(String clientId) {
        Queue<Long> timestamps = clientRequests.computeIfAbsent(
                clientId, k -> new LinkedList<>());

        long now = System.currentTimeMillis();

        // Remove old timestamps
        while (!timestamps.isEmpty() &&
                timestamps.peek() < now - TIME_WINDOW) {
            timestamps.poll();
        }

        if (timestamps.size() >= MAX_REQUESTS) {
            return false; // Rate limit exceeded
        }

        timestamps.offer(now);
        return true;
    }
}
