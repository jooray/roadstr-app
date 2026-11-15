package app.roadstr.service.meshcore

import app.roadstr.core.geo.GeoMath
import app.roadstr.core.geo.GeoPoint
import app.roadstr.core.protocol.interop.BridgeRateLimiter
import app.roadstr.core.protocol.interop.BridgeSummaryCodec
import app.roadstr.core.protocol.interop.CompactConfirmation
import app.roadstr.core.protocol.interop.CompactCoordinates
import app.roadstr.core.protocol.interop.CompactError
import app.roadstr.core.protocol.interop.CompactOutcome
import app.roadstr.core.protocol.interop.CompactReport
import app.roadstr.core.protocol.interop.CompactRoadCodec
import app.roadstr.core.protocol.interop.CompactRoadType
import app.roadstr.core.protocol.interop.ExternalRoadReportAdapter
import app.roadstr.core.protocol.interop.InteropLifetime
import app.roadstr.core.protocol.interop.LoRaSettings
import app.roadstr.core.protocol.interop.RoadEventTransport
import app.roadstr.service.nostr.NativeInteropListener
import app.roadstr.service.nostr.NativeNostrWire
import app.roadstr.service.nostr.NativeRoadEvent
import app.roadstr.service.nostr.NativeRoadEventService
import app.roadstr.service.nostr.NativeScheduler
import java.security.MessageDigest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** What the user switched on. All off by default; each direction is its own decision. */
data class MeshBridgeConfig(
    /** Read road reports from the radio and show them. */
    val receive: Boolean = false,
    /** Put this device's own reports and votes on the radio. */
    val send: Boolean = false,
    /** Republish what is heard on the radio to the Nostr relays, with the original author. */
    val meshToNostr: Boolean = false,
    /**
     * Relays -> radio as bridge summaries (needs [send]): short, unsigned, on demand only, zero-hop
     * or region-scoped. Never the signed events and never votes.
     */
    val nostrToMesh: Boolean = false,
)

/** Everything the bridge refuses to do on its own, so none of it is invisible. */
data class MeshBridgeLimits(
    /** Frames taken from the radio per minute; the rest are dropped unread. */
    val ingestPerMinute: Int = 60,
    /** This device's own reports and votes: a loose guard against a runaway loop, not a quota. */
    val ownPerMinute: Int = 6,
    /** Relays -> radio, as summaries only. */
    val summaries: BridgeSummaryLimits = BridgeSummaryLimits(),
    /** Only events this close are republished to relays from the radio. */
    val republishRadiusMeters: Double = 250_000.0,
)

data class MeshBridgeStats(
    val received: Int = 0,
    val shown: Int = 0,
    val malformed: Int = 0,
    val invalidSignature: Int = 0,
    val rateLimited: Int = 0,
    val stale: Int = 0,
    /** Votes heard before their report, held for a while in case it follows. */
    val waitingForReport: Int = 0,
    val queuedForRelays: Int = 0,
    val publishedToRelays: Int = 0,
    val sentToRadio: Int = 0,
    val notRepresentable: Int = 0,
    /** Frames the radio refused as too large. The encoder keeps to 163 bytes, so this stays 0. */
    val tooLarge: Int = 0,
    /** Bridge summaries heard on the radio, and the unverified reports they brought. */
    val summariesHeard: Int = 0,
    val bridgeEntriesShown: Int = 0,
    val requestsHeard: Int = 0,
    /** Bridge summaries this device put on the radio. */
    val summariesSent: Int = 0,
    /** Summaries not sent because another bridge took the area, or no scope or relay was available. */
    val summariesYielded: Int = 0,
    val summariesWithoutScope: Int = 0,
)

/** How far a bridge summary may travel. Never a plain flood. */
sealed interface SummaryScope {
    /** Only the bridge's radio neighbours: path length 0, no repeater forwards it. */
    data object ZeroHop : SummaryScope

    /** Flooded only inside the flood region that covers [point]. */
    data class Region(val point: GeoPoint) : SummaryScope
}

/** The radio, as the bridge needs it. */
interface MeshRadioPort {
    val ready: Boolean

    fun send(payload: ByteArray, onResult: (MeshCoreSendResult) -> Unit)

    /** Whether this link can send zero-hop. */
    val zeroHop: Boolean get() = false

    /** Whether this link can limit a flood to a named region. */
    val regionScope: Boolean get() = false

    /** The radio's LoRa settings, for the airtime budget; null when unknown. */
    val loRa: LoRaSettings? get() = null

    /** Sends a bridge summary within [scope], or refuses with [MeshCoreSendResult.NoScope]. */
    fun sendSummary(payload: ByteArray, scope: SummaryScope, onResult: (MeshCoreSendResult) -> Unit) =
        onResult(MeshCoreSendResult.NoScope)
}

/**
 * Agreement between bridges over Nostr about who sends the summary for an area (SPECIFICATION.md
 * 4.3 rule 7). True: this bridge won. False: another one did. Null: no relay could be reached, so
 * this bridge has nothing current from the relays and sends nothing.
 */
fun interface BridgeClaims {
    suspend fun contest(area: String, hops: Int): Boolean?
}

/**
 * Moves road reports between a MeshCore radio and the app, and between the radio and the Nostr
 * relays, without ever acting as an author.
 *
 * What it guarantees, each covered by RoadMeshBridgeTest:
 *  - an event is always re-checked: a frame is rebuilt into a Nostr event and its signature
 *    verified before anything uses it, and nothing is forwarded that did not verify;
 *  - the author, ID and signature never change: the bridge does not sign, ever;
 *  - nothing is sent anywhere that already has it (the ledger), so relay -> radio -> relay cannot
 *    cycle, and every outgoing direction has a rate limit and an area;
 *  - relays -> radio carries only bridge summaries (SPECIFICATION.md 4.2-4.3 in jooray/roadbeacon):
 *    unsigned, on demand, zero-hop or region-scoped, within an airtime budget, one bridge per area;
 *    never a relay event's signed frame and never a vote;
 *  - receiving and bridging radio -> relays never transmits on the radio;
 *  - everything is off until the user turns it on, and a frame that is not exactly the format is
 *    dropped, never repaired.
 *
 * Not covered by any test here: a real radio. See docs/interoperability/MESHCORE_NOSTR.md.
 */
class RoadMeshBridge(
    private val radio: MeshRadioPort,
    private val roads: NativeRoadEventService,
    private val republish: MeshRepublishQueue,
    private val config: () -> MeshBridgeConfig,
    private val position: () -> GeoPoint?,
    private val nowSeconds: () -> Long,
    private val scope: CoroutineScope,
    private val limits: MeshBridgeLimits = MeshBridgeLimits(),
    /** Who sends the summary for an area; null: no agreement possible, so no summaries. */
    private val claims: BridgeClaims? = null,
    /** Runs the random wait before a summary; null runs it at once (tests that do not care). */
    private val scheduler: NativeScheduler? = null,
    private val random: java.util.Random = java.security.SecureRandom(),
) : NativeInteropListener {
    private val lock = Any()
    private val ingest = BridgeRateLimiter(limits.ingestPerMinute, 60)
    private val own = BridgeRateLimiter(limits.ownPerMinute, 60)
    private val planner = BridgeSummaryPlanner(limits.summaries)
    /** Areas with a summary on its way (waiting, claiming or sending). */
    private val summaryInFlight = HashSet<String>()
    private val frames = object : LinkedHashMap<String, Boolean>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>) = size > MAX_FRAME_DIGESTS
    }

    private class Parked(val vote: CompactConfirmation, val parkedAt: Long)

    /** Votes heard before their report, by report ID. Bounded in total, per report and in time. */
    private val parked = LinkedHashMap<String, MutableList<Parked>>()
    private var parkedCount = 0
    private val ownBacklog = ArrayDeque<Map<String, Any?>>()
    private val transmitting = HashSet<String>()
    private val _stats = MutableStateFlow(MeshBridgeStats())

    val stats: StateFlow<MeshBridgeStats> = _stats.asStateFlow()

    // ── radio -> app (and relays) ───────────────────────────────────────────────────────────────

    /** Called by the client with every datagram of the Roadstr channel. */
    fun onDatagram(datagram: MeshCoreDatagram) {
        if (!config().receive) return
        val now = nowSeconds()
        bump { copy(received = received + 1) }
        val admitted = synchronized(lock) { ingest.tryAcquire(now) }
        if (!admitted) return bump { copy(rateLimited = rateLimited + 1) }
        val digest = digestOf(datagram.payload)
        val repeated = synchronized(lock) { frames.put(digest, true) != null }
        if (repeated) return
        when (BridgeSummaryCodec.familyOf(datagram.payload)) {
            BridgeSummaryCodec.Family.Summary -> return acceptSummary(datagram.payload, now)
            BridgeSummaryCodec.Family.Request -> return acceptRequest(datagram, now)
            BridgeSummaryCodec.Family.Unknown -> return bump { copy(malformed = malformed + 1) }
            BridgeSummaryCodec.Family.Signed -> Unit
        }
        when (val outcome = CompactRoadCodec.decode(datagram.payload)) {
            is CompactOutcome.Failed -> countFailure(outcome.error)
            is CompactOutcome.Ok -> when (val decoded = outcome.value) {
                is CompactReport -> acceptReport(decoded, now, datagram.hops)
                is CompactConfirmation -> acceptVote(decoded, now, datagram.hops)
            }
        }
    }

    /**
     * Another bridge's summary: its entries are shown as unverified, never republished, never
     * re-sent, and its area counts as served.
     */
    private fun acceptSummary(payload: ByteArray, now: Long) {
        val summary = (BridgeSummaryCodec.decodeSummary(payload) as? BridgeSummaryCodec.Result.Ok)?.value
            ?: return bump { copy(malformed = malformed + 1) }
        bump { copy(summariesHeard = summariesHeard + 1) }
        val ref = GeoPoint(CompactCoordinates.degrees(summary.refLatitudeE6), CompactCoordinates.degrees(summary.refLongitudeE6))
        synchronized(lock) { planner.noteSummaryHeard(ref, now) }
        val shown = roads.acceptBridgeSummary(summary.entries, now)
        if (shown > 0) bump { copy(bridgeEntriesShown = bridgeEntriesShown + shown) }
    }

    /** A driver on the mesh asks for a summary. Never published anywhere. */
    private fun acceptRequest(datagram: MeshCoreDatagram, now: Long) {
        val request = (BridgeSummaryCodec.decodeRequest(datagram.payload) as? BridgeSummaryCodec.Result.Ok)?.value
            ?: return bump { copy(malformed = malformed + 1) }
        bump { copy(requestsHeard = requestsHeard + 1) }
        if (!summariesWanted()) return
        val demand = synchronized(lock) { planner.noteRequest(request, datagram.hops, position(), now) } ?: return
        scheduleSummary(demand.area)
    }

    /** A signed frame from another node: someone uses the mesh at [where]. Only schedules; never sends now. */
    private fun noteDemand(eventId: String?, where: GeoPoint?, hops: Int?, now: Long) {
        if (!summariesWanted()) return
        // Our own transmission given back by a repeater is not someone else on the mesh.
        if (eventId != null && roads.ledger.wasForwarded(eventId, RoadEventTransport.MESH)) return
        val bridgeAt = position() ?: return
        val demand = synchronized(lock) { planner.noteSignedFrame(where ?: bridgeAt, hops, bridgeAt, now) } ?: return
        scheduleSummary(demand.area)
    }

    private fun acceptReport(decoded: CompactReport, now: Long, hops: Int?) {
        val report = (ExternalRoadReportAdapter.adaptReport(decoded.event) as? CompactOutcome.Ok)?.value
            ?: return bump { copy(malformed = malformed + 1) }
        // A replay of an old frame, or a clock that is wrong by more than a few minutes, is noise.
        val fresh = report.createdAt <= now + InteropLifetime.MAX_FUTURE_SKEW_SECONDS &&
            InteropLifetime.isVisible(report.createdAt, report.type, emptyList(), now, report.relayExpiration)
        if (!fresh) return bump { copy(stale = stale + 1) }
        val displayed = roads.acceptInteropEvent(decoded.event, RoadEventTransport.MESH, alreadyVerified = true)
        if (displayed) bump { copy(shown = shown + 1) }
        val where = GeoPoint(CompactCoordinates.degrees(report.latitudeE6), CompactCoordinates.degrees(report.longitudeE6))
        val shownUntil = minOf(report.createdAt + report.type.effectiveTtlSeconds, report.relayExpiration)
        republishIfAllowed(decoded.event, shownUntil, where)
        noteDemand(decoded.event["id"] as? String, where, hops, now)
    }

    private fun acceptVote(decoded: CompactConfirmation, now: Long, hops: Int?) {
        val createdAt = NativeNostrWire.integral(decoded.event["created_at"]) ?: return
        val tooNew = createdAt > now + InteropLifetime.MAX_FUTURE_SKEW_SECONDS
        if (tooNew || now - createdAt > MAX_VOTE_AGE_SECONDS) return bump { copy(stale = stale + 1) }
        // A vote carries no position: the demand is where the bridge is.
        noteDemand(decoded.event["id"] as? String, null, hops, now)
        // The vote frame is self-contained and already verified; only its report may be missing.
        val report = roads.find(decoded.referencedEventId) ?: return park(decoded, now)
        applyVote(decoded, report, now)
    }

    private fun applyVote(decoded: CompactConfirmation, report: NativeRoadEvent, now: Long) {
        val createdAt = NativeNostrWire.integral(decoded.event["created_at"]) ?: return
        if (createdAt < report.createdAt) return bump { copy(stale = stale + 1) }
        val displayed = roads.acceptInteropEvent(decoded.event, RoadEventTransport.MESH, alreadyVerified = true)
        if (displayed) bump { copy(shown = shown + 1) }
        republishIfAllowed(decoded.event, now + CONFIRMATION_REPUBLISH_SECONDS, GeoPoint(report.latitude, report.longitude))
    }

    private fun countFailure(error: CompactError) {
        when (error) {
            CompactError.SIGNATURE_INVALID -> bump { copy(invalidSignature = invalidSignature + 1) }
            else -> bump { copy(malformed = malformed + 1) }
        }
    }

    // ── votes that arrived before their report ──────────────────────────────────────────────────

    private fun park(vote: CompactConfirmation, now: Long) {
        synchronized(lock) {
            expireParkedLocked(now)
            val waiting = parked.getOrPut(vote.referencedEventId) { ArrayList() }
            val id = vote.event["id"]
            if (waiting.any { it.vote.event["id"] == id } || waiting.size >= MAX_PARKED_PER_REPORT) return
            if (parkedCount >= MAX_PARKED) return
            waiting += Parked(vote, now)
            parkedCount++
        }
        bump { copy(waitingForReport = waitingForReport + 1) }
    }

    /** The report [reportId] is now known, from the radio or a relay: apply what waited for it. */
    private fun applyParked(reportId: String) {
        val now = nowSeconds()
        val waiting = synchronized(lock) {
            val taken = parked.remove(reportId).orEmpty()
            parkedCount -= taken.size
            taken.filter { now - it.parkedAt <= PARKED_SECONDS }
        }
        if (waiting.isEmpty()) return
        val report = roads.find(reportId) ?: return
        for (entry in waiting) applyVote(entry.vote, report, now)
    }

    private fun expireParkedLocked(now: Long) {
        val iterator = parked.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            val kept = entry.value.filter { now - it.parkedAt <= PARKED_SECONDS }
            parkedCount -= entry.value.size - kept.size
            if (kept.isEmpty()) iterator.remove() else entry.setValue(kept.toMutableList())
        }
    }

    // ── radio -> relays ─────────────────────────────────────────────────────────────────────────

    private fun republishIfAllowed(event: Map<String, Any?>, expiresAt: Long, where: GeoPoint) {
        if (!config().meshToNostr) return
        val id = event["id"] as? String ?: return
        if (!roads.ledger.shouldForward(id, RoadEventTransport.RELAY)) return
        val here = position()
        if (here == null || GeoMath.distanceMeters(here, where) > limits.republishRadiusMeters) return
        if (!republish.enqueue(event, expiresAt)) return
        bump { copy(queuedForRelays = queuedForRelays + 1) }
        scope.launch { flushRepublish() }
    }

    /**
     * Tries to publish what is waiting. Safe to call at any time; does nothing offline, and nothing
     * once the user switched the bridge off (what is waiting then stays, until cleared or published
     * after it is switched on again).
     */
    suspend fun flushRepublish() {
        if (!config().meshToNostr) return
        val published = republish.flush(
            publish = { roads.publishPlain(it) },
            onPublished = { id -> roads.ledger.markForwarded(id, RoadEventTransport.RELAY) },
        )
        if (published > 0) bump { copy(publishedToRelays = publishedToRelays + published) }
    }

    // ── relays -> radio: bridge summaries only ─────────────────────────────────────────────────

    /** The service accepted an event: release votes that waited for it. Relay events are never put on the radio as they are. */
    override fun onInteropEvent(event: Map<String, Any?>, via: RoadEventTransport, newOnTransport: Boolean) {
        val id = event["id"] as? String ?: return
        val report = NativeNostrWire.integral(event["kind"]) == CompactRoadCodec.KIND_REPORT.toLong()
        // Off the relay thread and off the service's lock.
        if (report) scope.launch { applyParked(id) }
    }

    private fun summariesWanted(): Boolean {
        val cfg = config()
        return cfg.nostrToMesh && cfg.send && claims != null
    }

    /** Waits 2-10 s at random, then tries; one attempt per area at a time. */
    private fun scheduleSummary(area: String) {
        val first = synchronized(lock) { summaryInFlight.add(area) }
        if (!first) return
        val hold = synchronized(lock) { planner.holdMillis(random) }
        val run = { scope.launch { try { attemptSummary(area) } finally { synchronized(lock) { summaryInFlight.remove(area) } } } }
        val timer = scheduler
        if (timer == null) run() else timer.schedule(hold) { run() }
    }

    private suspend fun attemptSummary(area: String) {
        if (!summariesWanted() || !radio.ready) return
        val agreement = claims ?: return
        val now = nowSeconds()
        val selection = synchronized(lock) {
            val demand = planner.due(area, now) ?: return
            planner.select(demand, candidates(), now)
        } ?: return
        val demand = selection.demand
        val point = selection.demand.point
        val payload = (BridgeSummaryCodec.encodeSummary(
            BridgeSummaryPlanner.e6(point.latitude), BridgeSummaryPlanner.e6(point.longitude), selection.entries,
        ) as? BridgeSummaryCodec.Result.Ok)?.value ?: return bump { copy(notRepresentable = notRepresentable + 1) }
        // Zero-hop reaches the asker only if it was heard directly; otherwise the region around it.
        // A link that can do neither sends nothing: it would have to flood.
        val summaryScope = when {
            radio.zeroHop && demand.hops == 0 -> SummaryScope.ZeroHop
            radio.regionScope -> SummaryScope.Region(point)
            else -> return bump { copy(summariesWithoutScope = summariesWithoutScope + 1) }
        }
        val settings = radio.loRa ?: LoRaSettings.ASSUMED
        val packet = BridgeSummaryCodec.packetBytes(payload.size, region = summaryScope is SummaryScope.Region)
        val airtime = BridgeSummaryCodec.airtimeMillis(settings.spreadingFactor, settings.bandwidthHz, settings.codingRate, packet)
        if (!synchronized(lock) { planner.budgetAllows(airtime, now) }) return bump { copy(rateLimited = rateLimited + 1) }

        when (agreement.contest(area, demand.hops)) {
            null -> return bump { copy(summariesYielded = summariesYielded + 1) }
            false -> {
                synchronized(lock) { planner.noteClaimLost(area, nowSeconds()) }
                return bump { copy(summariesYielded = summariesYielded + 1) }
            }
            true -> Unit
        }
        // Another bridge's summary for the area may have been heard during the claim.
        val sendAt = nowSeconds()
        val stillDue = synchronized(lock) { planner.due(area, sendAt) != null && planner.budgetAllows(airtime, sendAt) }
        if (!stillDue || !summariesWanted()) return
        radio.sendSummary(payload, summaryScope) { result ->
            when (result) {
                MeshCoreSendResult.Sent -> {
                    synchronized(lock) { planner.recordSent(selection, airtime, nowSeconds()) }
                    bump { copy(summariesSent = summariesSent + 1) }
                }
                MeshCoreSendResult.NoScope -> bump { copy(summariesWithoutScope = summariesWithoutScope + 1) }
                MeshCoreSendResult.TooLarge -> bump { copy(tooLarge = tooLarge + 1) }
                else -> Unit
            }
        }
    }

    /** Verified reports from the relays that the radio has not carried, as the planner needs them. */
    private fun candidates(): List<SummaryCandidate> = roads.bridgeCandidates().mapNotNull { event ->
        if (roads.ledger.seenOn(event.id, RoadEventTransport.MESH) || roads.ledger.wasForwarded(event.id, RoadEventTransport.MESH)) {
            return@mapNotNull null
        }
        val type = CompactRoadType.fromNative(event.category) ?: return@mapNotNull null
        val shownUntil = event.lifetimeEndsAt
            ?: minOf(event.createdAt + event.category.ttlSeconds, event.expiresAt ?: Long.MAX_VALUE)
        SummaryCandidate(
            id = event.id,
            category = type.value,
            latitudeE6 = BridgeSummaryPlanner.e6(event.latitude),
            longitudeE6 = BridgeSummaryPlanner.e6(event.longitude),
            createdAt = event.createdAt,
            shownUntil = shownUntil,
            stillThere = event.confirmations,
            gone = event.denials,
        )
    }

    // ── this device's own events ────────────────────────────────────────────────────────────────

    /**
     * A report or vote this device just signed. Sent at once if the radio is up; held (a few,
     * briefly) if it is not, because the driver asked for it to be transmitted.
     */
    fun sendOwn(event: Map<String, Any?>) {
        val id = event["id"] as? String ?: return
        // The app publishes its own events to the relays itself; a radio echo must not do it again.
        roads.ledger.markForwarded(id, RoadEventTransport.RELAY)
        if (!config().send) return
        if (!radio.ready) {
            synchronized(lock) {
                if (ownBacklog.size >= MAX_OWN_BACKLOG) ownBacklog.removeFirst()
                ownBacklog.addLast(event)
            }
            return
        }
        transmitOwn(event)
    }

    /** The radio just became ready: send what was held for it. */
    fun onRadioReady() {
        val held = synchronized(lock) { ArrayList(ownBacklog).also { ownBacklog.clear() } }
        for (event in held) transmitOwn(event)
    }

    private fun transmitOwn(event: Map<String, Any?>) {
        if (!config().send) return
        val id = event["id"] as? String ?: return
        val prepared = prepare(event) ?: return
        val now = nowSeconds()
        if (!prepared.live(now)) return
        // A vote is worth airtime only where its report can be heard too.
        val reportId = prepared.referencedReport
        if (reportId != null && !reportKnownOnRadio(reportId)) return
        if (!synchronized(lock) { own.tryAcquire(now) }) return bump { copy(rateLimited = rateLimited + 1) }
        transmit(id, prepared.frame)
    }

    private fun reportKnownOnRadio(reportId: String): Boolean =
        roads.ledger.seenOn(reportId, RoadEventTransport.MESH) || roads.ledger.wasForwarded(reportId, RoadEventTransport.MESH)

    // ── shared ──────────────────────────────────────────────────────────────────────────────────

    private class Prepared(
        val frame: ByteArray,
        val author: String,
        /** Where a report is; null for a vote, which carries no position. */
        val where: GeoPoint?,
        val referencedReport: String?,
        val endsAt: Long,
    ) {
        fun live(now: Long): Boolean = endsAt - now >= MIN_REMAINING_SECONDS
    }

    /** The frame for [event] if it can be encoded exactly, with what the policy checks need. */
    private fun prepare(event: Map<String, Any?>): Prepared? {
        val author = event["pubkey"] as? String ?: return null
        val kind = NativeNostrWire.integral(event["kind"])
        val prepared = if (kind == CompactRoadCodec.KIND_REPORT.toLong()) prepareReport(event, author) else prepareVote(event, author)
        if (prepared == null) bump { copy(notRepresentable = notRepresentable + 1) }
        return prepared
    }

    private fun prepareReport(event: Map<String, Any?>, author: String): Prepared? {
        val report = (ExternalRoadReportAdapter.adaptReport(event) as? CompactOutcome.Ok)?.value ?: return null
        val frame = (CompactRoadCodec.encodeReport(event) as? CompactOutcome.Ok)?.value ?: return null
        val where = GeoPoint(CompactCoordinates.degrees(report.latitudeE6), CompactCoordinates.degrees(report.longitudeE6))
        val endsAt = minOf(report.createdAt + report.type.effectiveTtlSeconds, report.relayExpiration)
        return Prepared(frame, author, where, null, endsAt)
    }

    private fun prepareVote(event: Map<String, Any?>, author: String): Prepared? {
        val frame = (CompactRoadCodec.encodeConfirmation(event) as? CompactOutcome.Ok)?.value ?: return null
        val vote = (CompactRoadCodec.decodeConfirmation(frame) as? CompactOutcome.Ok)?.value ?: return null
        val createdAt = NativeNostrWire.integral(event["created_at"]) ?: return null
        return Prepared(frame, author, null, vote.referencedEventId, createdAt + CONFIRMATION_REPUBLISH_SECONDS)
    }

    private fun transmit(eventId: String, frame: ByteArray) {
        // The same event can reach here twice at once (as the device's own, and as seen on a relay).
        val first = synchronized(lock) { transmitting.add(eventId) }
        if (!first) return
        if (roads.ledger.wasForwarded(eventId, RoadEventTransport.MESH)) {
            synchronized(lock) { transmitting.remove(eventId) }
            return
        }
        radio.send(frame) { result ->
            synchronized(lock) { transmitting.remove(eventId) }
            when (result) {
                MeshCoreSendResult.Sent -> {
                    roads.ledger.markForwarded(eventId, RoadEventTransport.MESH)
                    roads.ledger.observe(eventId, RoadEventTransport.MESH)
                    bump { copy(sentToRadio = sentToRadio + 1) }
                }
                MeshCoreSendResult.TooLarge -> bump { copy(tooLarge = tooLarge + 1) }
                else -> Unit
            }
        }
    }

    private fun digestOf(payload: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(payload).take(DIGEST_BYTES).joinToString("") { "%02x".format(it) }

    private inline fun bump(crossinline change: MeshBridgeStats.() -> MeshBridgeStats) {
        _stats.update { it.change() }
    }

    private companion object {
        const val MAX_FRAME_DIGESTS = 512
        const val MAX_PARKED = 64
        const val MAX_PARKED_PER_REPORT = 8
        const val PARKED_SECONDS = 15 * 60L

        /** The radio is a live medium: a vote older than a day is a replay, not news. */
        const val MAX_VOTE_AGE_SECONDS = 24 * 3_600L
        const val MAX_OWN_BACKLOG = 10
        const val DIGEST_BYTES = 16
        const val CONFIRMATION_REPUBLISH_SECONDS = 6 * 3_600L
        const val MIN_REMAINING_SECONDS = 5 * 60L
    }
}
