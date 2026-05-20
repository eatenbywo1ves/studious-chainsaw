package redking.protocol

/**
 * Message types for the RedKing P2P protocol.
 */
enum class MessageType {
    // Network management
    PING,
    PONG,
    HELLO,
    GOODBYE,

    // Swap protocol
    SWAP_REQUEST,
    SWAP_ACCEPT,
    SWAP_REJECT,

    // Broadcast messages
    BROADCAST,
    COMMAND,

    // Data transfer
    DATA,
    ACK
}

/**
 * Represents a message in the RedKing protocol.
 * All messages are signed to prevent tampering.
 */
data class Message(
    val type: MessageType,
    val senderId: String,
    val payload: String,
    val timestamp: Long = System.currentTimeMillis(),
    var signature: String = "",
    val messageId: String = Companion.generateMessageId()
) {
    companion object {
        private var counter = 0L

        fun generateMessageId(): String {
            return "${System.currentTimeMillis()}-${counter++}"
        }

        /**
         * Deserialize a message from string.
         */
        fun deserialize(data: String): Message? {
            return try {
                val lines = data.split('\n', limit = 6)
                if (lines.size < 6) return null

                Message(
                    type = MessageType.valueOf(lines[0]),
                    senderId = lines[1],
                    timestamp = lines[2].toLong(),
                    messageId = lines[3],
                    signature = lines[4],
                    payload = lines[5]
                )
            } catch (e: Exception) {
                null
            }
        }
    }

    /**
     * Create the string that will be signed.
     * Includes all fields except the signature itself.
     */
    fun toSignableString(): String {
        return "$type|$senderId|$payload|$timestamp|$messageId"
    }

    /**
     * Serialize message to string for transmission.
     */
    fun serialize(): String {
        return buildString {
            append(type.name)
            append('\n')
            append(senderId)
            append('\n')
            append(timestamp)
            append('\n')
            append(messageId)
            append('\n')
            append(signature)
            append('\n')
            append(payload)
        }
    }
}

/**
 * Represents a signed command that can be broadcast to the network.
 */
data class SignedCommand(
    val commandType: String,
    val parameters: Map<String, String>,
    val issuerPublicKey: String,
    val signature: String,
    val timestamp: Long
) {
    fun toPayload(): String {
        val params = parameters.entries.joinToString(",") { "${it.key}=${it.value}" }
        return "$commandType|$params|$issuerPublicKey|$signature|$timestamp"
    }

    companion object {
        fun fromPayload(payload: String): SignedCommand? {
            return try {
                val parts = payload.split('|')
                if (parts.size < 5) return null

                val params = parts[1].split(',')
                    .filter { it.contains('=') }
                    .associate {
                        val (k, v) = it.split('=', limit = 2)
                        k to v
                    }

                SignedCommand(
                    commandType = parts[0],
                    parameters = params,
                    issuerPublicKey = parts[2],
                    signature = parts[3],
                    timestamp = parts[4].toLong()
                )
            } catch (e: Exception) {
                null
            }
        }
    }
}
