package app.roadstr.core.protocol.interop

import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.math.abs
import kotlin.math.ceil

/**
 * The unsigned frames a bridge uses for relays -> mesh (SPECIFICATION.md sections 4.2 and 4.3 in
 * jooray/roadbeacon): the bridge summary (first byte 0x10) and the summary request (0x20). Both
 * travel on the same `data_type` 0x0150 as the signed frames; the high nibble of the first byte
 * tells them apart, and every version-0 decoder refuses a non-zero high nibble.
 *
 * Nothing here is signed or verifiable: a summary is what one bridge says the relays have, and it
 * is shown as such.
 */
object BridgeSummaryCodec {
    const val TYPE_SUMMARY = 0x10
    const val TYPE_REQUEST = 0x20
    const val HEADER_SIZE = 5
    const val ENTRY_SIZE = 8
    const val MAX_ENTRIES = 5
    const val REQUEST_SIZE = 13
    const val MAX_REQUEST_RADIUS_KM = 25
    const val DEFAULT_REQUEST_RADIUS_KM = 25

    /** Duration code 255: "more than 30 days" (age only). */
    const val DURATION_OVER = 255
    private const val MAX_REF_LAT = 9_000
    private const val MAX_REF_LON = 18_000
    private const val E6_PER_REF = 10_000
    private const val E6_PER_OFFSET = 10

    /** What the first byte of a 0x0150 payload says it is. */
    enum class Family { Signed, Summary, Request, Unknown }

    fun familyOf(payload: ByteArray): Family {
        if (payload.isEmpty()) return Family.Unknown
        val first = payload[0].toInt() and 0xFF
        return when (first and 0xF0) {
            0x00 -> Family.Signed
            TYPE_SUMMARY -> Family.Summary
            TYPE_REQUEST -> Family.Request
            else -> Family.Unknown
        }
    }

    // ── duration code ───────────────────────────────────────────────────────────────────────────

    /** Rounded down; null when it does not fit (more than 30 days, or negative). */
    fun encodeDuration(seconds: Long): Int? {
        if (seconds < 0) return null
        val minutes = seconds / 60
        if (minutes < 60) return minutes.toInt()
        val hours = seconds / 3_600
        if (hours < 24) return (59 + hours).toInt()
        val days = seconds / 86_400
        if (days <= 30) return (82 + days).toInt()
        return null
    }

    /** Seconds, or null for the reserved codes 113..254 and for 255. */
    fun decodeDuration(code: Int): Long? = when (code) {
        in 0..59 -> code * 60L
        in 60..82 -> (code - 59) * 3_600L
        in 83..112 -> (code - 82) * 86_400L
        else -> null
    }

    // ── coordinates ─────────────────────────────────────────────────────────────────────────────

    private fun roundHalfAway(num: Long, den: Long): Long {
        val q = abs(num) / den
        val r = abs(num) % den
        val rounded = if (2 * r >= den) q + 1 else q
        return if (num >= 0) rounded else -rounded
    }

    /** The 0.01-degree reference of a coordinate in degrees x 10^6. */
    fun refOf(e6: Int): Int = roundHalfAway(e6.toLong(), E6_PER_REF.toLong()).toInt()

    /** Offset in 0.00001 degree from [ref]; null when it does not fit an int16. */
    fun offsetOf(e6: Int, ref: Int): Int? {
        val offset = roundHalfAway(e6.toLong() - ref.toLong() * E6_PER_REF, E6_PER_OFFSET.toLong())
        return if (offset in Short.MIN_VALUE..Short.MAX_VALUE) offset.toInt() else null
    }

    /** `bridge:` + the first 16 hex digits of SHA-256(category ‖ lat E6 ‖ lon E6). */
    fun localId(category: Int, latitudeE6: Int, longitudeE6: Int): String {
        val bytes = ByteBuffer.allocate(9).put(category.toByte()).putInt(latitudeE6).putInt(longitudeE6).array()
        return "bridge:" + hex(sha256(bytes)).take(16)
    }

    // ── summary ─────────────────────────────────────────────────────────────────────────────────

    /** One report as a bridge offers it; ages and remaining times in seconds. */
    data class Entry(
        val latitudeE6: Int,
        val longitudeE6: Int,
        val category: Int,
        val ageSeconds: Long,
        val remainingSeconds: Long,
        val stillThere: Int,
        val gone: Int,
    ) {
        val id: String get() = localId(category, latitudeE6, longitudeE6)
    }

    enum class Error { BAD_LENGTH, BAD_TYPE, BAD_REFERENCE, BAD_RADIUS, BAD_DURATION, RESERVED_BITS, NOT_REPRESENTABLE }

    sealed interface Result<out T> {
        data class Ok<T>(val value: T) : Result<T>

        data class Failed(val error: Error) : Result<Nothing>
    }

    /**
     * The summary about [pointLatE6]/[pointLonE6] with [entries] (1..5). Fails when an entry does
     * not fit the offset range or its remaining time is not representable; callers leave such
     * reports out before encoding.
     */
    fun encodeSummary(pointLatE6: Int, pointLonE6: Int, entries: List<Entry>): Result<ByteArray> {
        if (entries.isEmpty() || entries.size > MAX_ENTRIES) return Result.Failed(Error.BAD_LENGTH)
        val refLat = refOf(pointLatE6)
        val refLon = refOf(pointLonE6)
        if (abs(refLat) > MAX_REF_LAT || abs(refLon) > MAX_REF_LON) return Result.Failed(Error.BAD_REFERENCE)
        val buffer = ByteBuffer.allocate(HEADER_SIZE + ENTRY_SIZE * entries.size)
        buffer.put(TYPE_SUMMARY.toByte()).putShort(refLat.toShort()).putShort(refLon.toShort())
        for (entry in entries) {
            val dLat = offsetOf(entry.latitudeE6, refLat) ?: return Result.Failed(Error.NOT_REPRESENTABLE)
            val dLon = offsetOf(entry.longitudeE6, refLon) ?: return Result.Failed(Error.NOT_REPRESENTABLE)
            val remaining = encodeDuration(entry.remainingSeconds)?.takeIf { it > 0 }
                ?: return Result.Failed(Error.NOT_REPRESENTABLE)
            val age = encodeDuration(entry.ageSeconds) ?: DURATION_OVER
            buffer.putShort(dLat.toShort()).putShort(dLon.toShort())
                .put(entry.category.toByte())
                .put(age.toByte())
                .put(remaining.toByte())
                .put(((entry.stillThere.coerceIn(0, 15) shl 4) or entry.gone.coerceIn(0, 15)).toByte())
        }
        return Result.Ok(buffer.array())
    }

    /** Fits [entryLatE6]/[entryLonE6] into a summary about the given point. */
    fun fits(pointLatE6: Int, pointLonE6: Int, entryLatE6: Int, entryLonE6: Int): Boolean =
        offsetOf(entryLatE6, refOf(pointLatE6)) != null && offsetOf(entryLonE6, refOf(pointLonE6)) != null

    data class Summary(val refLatitudeE6: Int, val refLongitudeE6: Int, val entries: List<Entry>)

    /** Entries that break a rule are left out; the frame fails only for the header rules. */
    fun decodeSummary(frame: ByteArray): Result<Summary> {
        val size = frame.size
        if (size < HEADER_SIZE + ENTRY_SIZE || (size - HEADER_SIZE) % ENTRY_SIZE != 0 ||
            (size - HEADER_SIZE) / ENTRY_SIZE > MAX_ENTRIES
        ) {
            return Result.Failed(Error.BAD_LENGTH)
        }
        if (frame[0].toInt() and 0xFF != TYPE_SUMMARY) return Result.Failed(Error.BAD_TYPE)
        val buffer = ByteBuffer.wrap(frame)
        buffer.get()
        val refLat = buffer.short.toInt()
        val refLon = buffer.short.toInt()
        if (abs(refLat) > MAX_REF_LAT || abs(refLon) > MAX_REF_LON) return Result.Failed(Error.BAD_REFERENCE)
        val entries = ArrayList<Entry>()
        repeat((size - HEADER_SIZE) / ENTRY_SIZE) {
            val latE6 = refLat * E6_PER_REF + buffer.short * E6_PER_OFFSET
            val lonE6 = refLon * E6_PER_REF + buffer.short * E6_PER_OFFSET
            val category = buffer.get().toInt() and 0xFF
            val ageCode = buffer.get().toInt() and 0xFF
            val remainingCode = buffer.get().toInt() and 0xFF
            val votes = buffer.get().toInt() and 0xFF
            val type = CompactRoadType.fromValue(category) ?: return@repeat
            val remaining = decodeDuration(remainingCode)?.takeIf { it > 0 } ?: return@repeat
            val age = decodeDuration(ageCode) ?: return@repeat
            if (age > type.effectiveTtlSeconds) return@repeat
            if (abs(latE6.toLong()) > CompactCoordinates.MAX_LATITUDE_E6 ||
                abs(lonE6.toLong()) > CompactCoordinates.MAX_LONGITUDE_E6
            ) {
                return@repeat
            }
            entries += Entry(latE6, lonE6, category, age, remaining, votes shr 4, votes and 0x0F)
        }
        return Result.Ok(Summary(refLat * E6_PER_REF, refLon * E6_PER_REF, entries))
    }

    // ── request ─────────────────────────────────────────────────────────────────────────────────

    data class Request(
        val latitudeE6: Int,
        val longitudeE6: Int,
        val radiusKm: Int,
        /** Only reports younger than this; null = any age. */
        val sinceSeconds: Long?,
        /** Registry values asked for; empty = all. */
        val categories: List<Int>,
    ) {
        fun wants(category: Int): Boolean = categories.isEmpty() || category in categories
    }

    fun encodeRequest(pointLatE6: Int, pointLonE6: Int, radiusKm: Int, sinceSeconds: Long?, categories: List<Int>): ByteArray {
        require(radiusKm in 0..MAX_REQUEST_RADIUS_KM) { "radius out of range" }
        var mask = 0
        for (c in categories) mask = mask or (1 shl (if (c == 255) 15 else c.also { require(it in 0..13) }))
        val since = if (sinceSeconds == null) DURATION_OVER else requireNotNull(encodeDuration(sinceSeconds))
        return ByteBuffer.allocate(REQUEST_SIZE)
            .put(TYPE_REQUEST.toByte())
            .putShort(refOf(pointLatE6).toShort())
            .putShort(refOf(pointLonE6).toShort())
            .put(radiusKm.toByte())
            .put(since.toByte())
            .putShort(mask.toShort())
            .array()
    }

    fun decodeRequest(frame: ByteArray): Result<Request> {
        if (frame.size != REQUEST_SIZE) return Result.Failed(Error.BAD_LENGTH)
        if (frame[0].toInt() and 0xFF != TYPE_REQUEST) return Result.Failed(Error.BAD_TYPE)
        val buffer = ByteBuffer.wrap(frame)
        buffer.get()
        val lat = buffer.short.toInt()
        val lon = buffer.short.toInt()
        val radius = buffer.get().toInt() and 0xFF
        val since = buffer.get().toInt() and 0xFF
        val mask = buffer.short.toInt() and 0xFFFF
        if ((9 until REQUEST_SIZE).any { frame[it].toInt() != 0 }) return Result.Failed(Error.RESERVED_BITS)
        if (abs(lat) > MAX_REF_LAT || abs(lon) > MAX_REF_LON) return Result.Failed(Error.BAD_REFERENCE)
        if (radius > MAX_REQUEST_RADIUS_KM) return Result.Failed(Error.BAD_RADIUS)
        if (since != DURATION_OVER && decodeDuration(since) == null) return Result.Failed(Error.BAD_DURATION)
        val categories = (0..13).filter { mask shr it and 1 == 1 } + (if (mask shr 15 and 1 == 1) listOf(255) else emptyList())
        return Result.Ok(
            Request(
                latitudeE6 = lat * E6_PER_REF,
                longitudeE6 = lon * E6_PER_REF,
                radiusKm = if (radius == 0) DEFAULT_REQUEST_RADIUS_KM else radius,
                sinceSeconds = if (since == DURATION_OVER) null else decodeDuration(since),
                categories = categories,
            ),
        )
    }

    // ── claims and airtime ──────────────────────────────────────────────────────────────────────

    /** SHA-256(pubkey bytes ‖ area as UTF-8): the tie-break of a claim, lower wins. */
    fun claimHash(pubkeyHex: String, area: String): ByteArray =
        sha256(unhex(pubkeyHex) + area.toByteArray(Charsets.UTF_8))

    /** Index of the winning claim: fewest hops, then the lowest [claimHash] as unsigned bytes. */
    fun claimWinner(area: String, claims: List<Pair<String, Int>>): Int? {
        if (claims.isEmpty()) return null
        return claims.indices.minWithOrNull(
            compareBy<Int> { claims[it].second }.thenComparator { a, b ->
                compareUnsigned(claimHash(claims[a].first, area), claimHash(claims[b].first, area))
            },
        )
    }

    /** The whole LoRa packet for a channel datagram of [contentBytes]: 5 header bytes, 16-byte blocks, region code. */
    fun packetBytes(contentBytes: Int, region: Boolean): Int {
        val block = ceil((3 + contentBytes) / 16.0).toInt() * 16
        return 5 + block + if (region) 4 else 0
    }

    /** Semtech LoRa time on air in ms: explicit header, CRC on, MeshCore's preamble (32 up to SF8, 16 above). */
    fun airtimeMillis(spreadingFactor: Int, bandwidthHz: Int, codingRate: Int, packetBytes: Int): Double {
        val symbol = Math.pow(2.0, spreadingFactor.toDouble()) / bandwidthHz * 1000.0
        val lowRate = if (symbol > 16.0) 1 else 0
        val preamble = if (spreadingFactor <= 8) 32 else 16
        val numerator = 8 * packetBytes - 4 * spreadingFactor + 28 + 16
        val payload = 8 + maxOf(ceil(numerator.toDouble() / (4 * (spreadingFactor - 2 * lowRate))).toInt() * codingRate, 0)
        return (preamble + 4.25 + payload) * symbol
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val c = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (c != 0) return c
        }
        return a.size - b.size
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun unhex(text: String): ByteArray =
        ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

/** LoRa settings of the radio, for the airtime budget; MeshCore's codingRate is 5..8 (4/5..4/8). */
data class LoRaSettings(val spreadingFactor: Int, val bandwidthHz: Int, val codingRate: Int) {
    val plausible: Boolean get() = spreadingFactor in 5..12 && bandwidthHz in 7_000..1_000_000 && codingRate in 5..8

    companion object {
        /** What the budget assumes when the radio does not say: slow, so the budget errs on the safe side. */
        val ASSUMED = LoRaSettings(spreadingFactor = 11, bandwidthHz = 250_000, codingRate = 5)
    }
}
