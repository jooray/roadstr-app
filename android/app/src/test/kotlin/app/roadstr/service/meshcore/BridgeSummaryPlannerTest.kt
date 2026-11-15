package app.roadstr.service.meshcore

import app.roadstr.core.geo.GeoPoint
import app.roadstr.core.protocol.interop.BridgeSummaryCodec
import app.roadstr.core.protocol.nostr.BoundedJsonParser
import app.roadstr.core.protocol.nostr.NostrJson
import app.roadstr.service.nostr.NativeNostrWire
import app.roadstr.service.nostr.NativeRelayConnector
import app.roadstr.service.nostr.NativeRelayEvents
import app.roadstr.service.nostr.NativeRelaySocket
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BridgeSummaryPlannerTest {
    private val bridge = GeoPoint(48.15, 17.11)
    private val now = 1_800_000_000L

    private fun candidate(n: Int, createdAt: Long = now - 60, lat: Int = 48_150_000 + n * 1_000, category: Int = 0) =
        SummaryCandidate("id$n", category, lat, 17_110_000, createdAt, now + 3_600, 0, 0)

    @Test
    fun `at most five entries, newest first`() {
        val planner = BridgeSummaryPlanner()
        val demand = planner.noteSignedFrame(bridge, 0, bridge, now)!!
        val selection = planner.select(demand, (1..8).map { candidate(it, createdAt = now - 100 * it) }, now)!!
        assertEquals(listOf("id1", "id2", "id3", "id4", "id5"), selection.ids)
    }

    @Test
    fun `nothing short-lived, nothing out of range`() {
        val planner = BridgeSummaryPlanner()
        val demand = planner.noteSignedFrame(bridge, 0, bridge, now)!!
        val ending = candidate(1).copy(shownUntil = now + 200)
        val far = candidate(2, lat = 48_150_000 + 400_000) // 44 km
        assertNull(planner.select(demand, listOf(ending, far), now))
    }

    @Test
    fun `the airtime budget and the hourly count are hard`() {
        val planner = BridgeSummaryPlanner()
        val demand = planner.noteSignedFrame(bridge, 0, bridge, now)!!
        val selection = planner.select(demand, listOf(candidate(1)), now)!!
        // 682 ms per 45-byte region-scoped summary at SF11/250 kHz: five fit into 3.6 s, a sixth does not.
        repeat(5) {
            assertTrue(planner.budgetAllows(682.0, now + it))
            planner.recordSent(selection, 682.0, now + it)
        }
        assertFalse(planner.budgetAllows(682.0, now + 10))
        assertTrue("an hour later the budget is back", planner.budgetAllows(682.0, now + 3_600))
        val small = BridgeSummaryPlanner()
        repeat(6) { small.recordSent(selection, 1.0, now) }
        assertFalse("six summaries per hour at most", small.budgetAllows(1.0, now))
    }

    @Test
    fun `demand counts for two hours and a request for its area only`() {
        val planner = BridgeSummaryPlanner()
        val demand = planner.noteSignedFrame(bridge, 1, bridge, now)!!
        assertNotNull(planner.due(demand.area, now + 7_000))
        assertNull(planner.due(demand.area, now + 7_201))
        assertNull("too far from the bridge", planner.noteSignedFrame(GeoPoint(48.5, 17.11), 0, bridge, now))
    }

    // ── claims over Nostr ──────────────────────────────────────────────────────────────────────

    /** A relay that delivers live: what one socket publishes reaches every open subscription. */
    private class LiveRelay : NativeRelayConnector {
        private val subscribers = mutableListOf<Triple<NativeRelayEvents, String, Map<*, *>>>()

        override fun connect(url: String, events: NativeRelayEvents): NativeRelaySocket {
            events.onOpen()
            return object : NativeRelaySocket {
                override fun send(text: String): Boolean {
                    val frame = BoundedJsonParser(text).parse() as List<*>
                    when (frame[0]) {
                        "REQ" -> synchronized(subscribers) { subscribers += Triple(events, frame[1] as String, frame[2] as Map<*, *>) }
                        "EVENT" -> {
                            @Suppress("UNCHECKED_CAST")
                            val event = frame[1] as Map<String, Any?>
                            events.onMessage(NostrJson.encode(listOf("OK", event["id"], true, "")))
                            val targets = synchronized(subscribers) { subscribers.toList() }
                            for ((listener, sub, filter) in targets) {
                                val area = (filter["#g"] as List<*>).single()
                                if (NativeNostrWire.tagValue(event, "g") == area) listener.onMessage(NostrJson.encode(listOf("EVENT", sub, event)))
                            }
                        }
                    }
                    return true
                }

                override fun close() {
                    synchronized(subscribers) { subscribers.removeAll { it.first === events } }
                }
            }
        }
    }

    @Test
    fun `of two bridges claiming the same area, fewer hops wins, and both agree`() = runBlocking {
        val relay = LiveRelay()
        val a = NostrBridgeClaims(relay, listOf("wss://r.example"), { now }, listenMillis = 300, random = SecureRandom())
        val b = NostrBridgeClaims(relay, listOf("wss://r.example"), { now }, listenMillis = 300, random = SecureRandom())
        val first = async(Dispatchers.Default) { a.contest("u2s1", 2) }
        val second = async(Dispatchers.Default) { b.contest("u2s1", 0) }
        assertEquals(false, first.await())
        assertEquals(true, second.await())
    }

    @Test
    fun `a tie is broken by the claim hash, the same way the vectors do`() = runBlocking {
        val relay = LiveRelay()
        val a = NostrBridgeClaims(relay, listOf("wss://r.example"), { now }, listenMillis = 300)
        val b = NostrBridgeClaims(relay, listOf("wss://r.example"), { now }, listenMillis = 300)
        val first = async(Dispatchers.Default) { a.contest("u2s1", 1) }
        val second = async(Dispatchers.Default) { b.contest("u2s1", 1) }
        val winner = BridgeSummaryCodec.claimWinner("u2s1", listOf(a.publicKey to 1, b.publicKey to 1))
        assertEquals(winner == 0, first.await())
        assertEquals(winner == 1, second.await())
    }

    @Test
    fun `alone on the relay a bridge wins, and without relays it never claims`() = runBlocking {
        val alone = NostrBridgeClaims(LiveRelay(), listOf("wss://r.example"), { now }, listenMillis = 50)
        assertEquals(true, alone.contest("u2s1", 255))
        val offline = NostrBridgeClaims({ _, _ -> error("no network") }, listOf("wss://r.example"), { now }, listenMillis = 50, connectTimeoutMillis = 100)
        assertNull(offline.contest("u2s1", 0))
        assertNull(NostrBridgeClaims(LiveRelay(), emptyList(), { now }).contest("u2s1", 0))
    }
}
