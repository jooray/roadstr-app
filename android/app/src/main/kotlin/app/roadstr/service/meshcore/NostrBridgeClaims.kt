package app.roadstr.service.meshcore

import app.roadstr.core.protocol.interop.BridgeSummaryCodec
import app.roadstr.core.protocol.nostr.NostrEventDraft
import app.roadstr.core.protocol.nostr.NostrRelayEventMessage
import app.roadstr.core.protocol.nostr.NostrRelayMessageDecoder
import app.roadstr.core.protocol.nostr.NostrRelayOkMessage
import app.roadstr.core.protocol.nostr.NostrRelayWire
import app.roadstr.core.protocol.nostr.NostrSchnorr
import app.roadstr.service.nostr.NativeNostrWire
import app.roadstr.service.nostr.NativeRelayConnector
import app.roadstr.service.nostr.NativeRelayEvents
import app.roadstr.service.nostr.NativeRelaySocket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The claim of SPECIFICATION.md 4.3 rule 7: an ephemeral kind-21315 event, "I take area X now",
 * published on the relays while listening for the claims of other bridges for 1.5 s. Fewest hops
 * wins, then the lowest SHA-256(pubkey ‖ area).
 *
 * Ephemeral events are not stored, so the subscription must be open before the claims arrive: it
 * is sent first on each socket, then the claim. The claim is signed by a random key made when this
 * object is (once per bridge start) and never reused, so no stable identity is tied to a place.
 */
class NostrBridgeClaims(
    private val connector: NativeRelayConnector,
    private val relays: List<String>,
    private val nowSeconds: () -> Long,
    private val listenMillis: Long = 1_500,
    private val connectTimeoutMillis: Long = 5_000,
    random: SecureRandom = SecureRandom(),
) : BridgeClaims {
    private val secretKey: String = ByteArray(32).also(random::nextBytes).joinToString("") { "%02x".format(it) }
    val publicKey: String = NostrSchnorr.publicKey(secretKey)

    override suspend fun contest(area: String, hops: Int): Boolean? {
        if (relays.isEmpty()) return null
        val now = nowSeconds()
        fun claimAt(createdAt: Long) = NostrSchnorr.signEvent(
            NostrEventDraft(
                pubkey = publicKey,
                createdAt = createdAt,
                kind = KIND_CLAIM,
                tags = listOf(listOf("g", area), listOf("hops", hops.coerceIn(0, 255).toString()), listOf("expiration", (now + EXPIRATION_SECONDS).toString())),
                content = "",
            ),
            secretKey,
        )
        val claim = claimAt(now)
        // Relays do not keep ephemeral events: a bridge that subscribes after this claim went out
        // would never see it. So the claim is said once more at the end of the wait (a second
        // event, one second later), and every bridge that is still listening hears it.
        val again = NostrRelayWire.encode(NostrRelayWire.publish(claimAt(now + 1)))
        val claimId = claim["id"] as String
        val subscriptionId = "claim" + claimId.take(8)
        val heard = LinkedHashMap<String, Int>()
        val opened = AtomicBoolean(false)
        val accepted = AtomicBoolean(false)
        val sockets = ArrayList<NativeRelaySocket>()
        val request = NostrRelayWire.encode(
            listOf("REQ", subscriptionId, linkedMapOf("kinds" to listOf(KIND_CLAIM), "#g" to listOf(area), "since" to now - WINDOW_BEFORE_SECONDS)),
        )
        val publish = NostrRelayWire.encode(NostrRelayWire.publish(claim))
        for (url in relays) {
            val socketBox = arrayOfNulls<NativeRelaySocket>(1)
            val thisOpened = AtomicBoolean(false)
            val thisSent = AtomicBoolean(false)
            fun sendOnce(s: NativeRelaySocket) {
                if (thisSent.compareAndSet(false, true)) {
                    s.send(request)
                    s.send(publish)
                }
            }
            val socket = runCatching {
                connector.connect(
                    url,
                    object : NativeRelayEvents {
                        override fun onOpen() {
                            opened.set(true)
                            thisOpened.set(true)
                            sendOnce(socketBox[0] ?: return)
                        }

                        override fun onMessage(text: String) {
                            when (val message = NostrRelayMessageDecoder.decode(text).message) {
                                is NostrRelayOkMessage -> if (message.eventId == claimId && message.accepted == true) accepted.set(true)
                                is NostrRelayEventMessage -> if (message.subscriptionId == subscriptionId) {
                                    readClaim(message.event, area, now)?.let { (key, h) -> synchronized(heard) { heard[key] = minOf(h, heard[key] ?: h) } }
                                }
                                else -> Unit
                            }
                        }

                        override fun onEnded() = Unit
                    },
                )
            }.getOrNull() ?: continue
            socketBox[0] = socket
            sockets += socket
            // A socket that opened inside connect(), before the box was filled: send now.
            if (thisOpened.get()) sendOnce(socket)
        }
        try {
            withTimeoutOrNull(connectTimeoutMillis) { while (!opened.get()) delay(POLL_MILLIS) }
            if (!opened.get()) return null
            delay(listenMillis)
            sockets.forEach { runCatching { it.send(again) } }
            delay(REANNOUNCE_GRACE_MILLIS.coerceAtMost(listenMillis))
        } finally {
            sockets.forEach { runCatching { it.close() } }
        }
        if (!accepted.get()) return null
        val claims = synchronized(heard) {
            heard[publicKey] = hops.coerceIn(0, 255)
            heard.entries.map { it.key to it.value }
        }
        val winner = BridgeSummaryCodec.claimWinner(area, claims) ?: return null
        return claims[winner].first == publicKey
    }

    /** (pubkey, hops) of a valid claim for [area] made in the window around [now]. */
    private fun readClaim(event: Map<String, Any?>, area: String, now: Long): Pair<String, Int>? {
        if (NativeNostrWire.integral(event["kind"]) != KIND_CLAIM.toLong()) return null
        val createdAt = NativeNostrWire.integral(event["created_at"]) ?: return null
        if (createdAt < now - WINDOW_BEFORE_SECONDS || createdAt > now + WINDOW_AFTER_SECONDS) return null
        if (NativeNostrWire.tagValue(event, "g") != area) return null
        val pubkey = event["pubkey"] as? String ?: return null
        if (!NativeNostrWire.isHex32(pubkey) || !NativeNostrWire.verify(event)) return null
        val hops = NativeNostrWire.tagValue(event, "hops")?.toIntOrNull()?.coerceIn(0, 255) ?: BridgeSummaryPlanner.UNKNOWN_HOPS
        return pubkey to hops
    }

    companion object {
        const val KIND_CLAIM = 21315
        private const val EXPIRATION_SECONDS = 120L
        private const val WINDOW_BEFORE_SECONDS = 60L
        private const val WINDOW_AFTER_SECONDS = 5L
        private const val POLL_MILLIS = 50L
        private const val REANNOUNCE_GRACE_MILLIS = 300L
    }
}
