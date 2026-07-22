package com.strike48.pick.shared

import com.novi.bincode.BincodeDeserializer
import com.novi.bincode.BincodeSerializer
import com.novi.serde.DeserializationError
import com.novi.serde.Deserializer
import com.novi.serde.Serializer

fun <T> List<T>.serialize(
    serializer: Serializer,
    serializeElement: Serializer.(T) -> Unit,
) {
    serializer.serialize_len(size.toLong())
    forEach { element ->
        serializer.serializeElement(element)
    }
}

fun <T> Deserializer.deserializeListOf(deserializeElement: (Deserializer) -> T): List<T> {
    val length = deserialize_len()
    val list = mutableListOf<T>()
    repeat(length.toInt()) {
        list.add(deserializeElement(this))
    }
    return list
}

fun <T> T?.serializeOptionOf(
    serializer: Serializer,
    serializeElement: Serializer.(T) -> Unit,
) {
    if (this != null) {
        serializer.serialize_option_tag(true)
        serializer.serializeElement(this)
    } else {
        serializer.serialize_option_tag(false)
    }
}

fun <T> Deserializer.deserializeOptionOf(deserializeElement: (Deserializer) -> T): T? {
    val tag = deserialize_option_tag()
    return if (tag) {
        deserializeElement(this)
    } else {
        null
    }
}

/// What the agent is currently doing, projected from the server's AgentStatus.
/// Drives the animated status line (never a spinner) while a scan/chat is live.
/// `Idle` means no activity (terminal / not running).
enum class AgentActivity {
    IDLE,
    THINKING,
    RESPONDING,
    RUNNINGTOOLS,
    AWAITINGCONSENT;

    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_variant_index(ordinal)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): AgentActivity {
            deserializer.increase_container_depth()
            val index = deserializer.deserialize_variant_index()
            deserializer.decrease_container_depth()
            return when (index) {
                0 -> IDLE
                1 -> THINKING
                2 -> RESPONDING
                3 -> RUNNINGTOOLS
                4 -> AWAITINGCONSENT
                else -> throw DeserializationError("Unknown variant index for AgentActivity: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): AgentActivity {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ConnectOutcome(
    val ok: Unit? = null,
    val err: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        ok.serializeOptionOf(serializer) {
            serializer.serialize_unit(it)
        }
        err.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ConnectOutcome {
            deserializer.increase_container_depth()
            val ok =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_unit()
                }
            val err =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return ConnectOutcome(ok, err)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ConnectOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

enum class ConnectionPhase {
    SIGNINGIN,
    CONNECTING,
    REGISTERING,
    CONNECTED,
    NEEDSSIGNIN;

    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_variant_index(ordinal)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): ConnectionPhase {
            deserializer.increase_container_depth()
            val index = deserializer.deserialize_variant_index()
            deserializer.decrease_container_depth()
            return when (index) {
                0 -> SIGNINGIN
                1 -> CONNECTING
                2 -> REGISTERING
                3 -> CONNECTED
                4 -> NEEDSSIGNIN
                else -> throw DeserializationError("Unknown variant index for ConnectionPhase: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ConnectionPhase {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ConnectionView(
    val phase: com.strike48.pick.shared.ConnectionPhase,
    val label: String,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        phase.serialize(serializer)
        serializer.serialize_str(label)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ConnectionView {
            deserializer.increase_container_depth()
            val phase = com.strike48.pick.shared.ConnectionPhase.deserialize(deserializer)
            val label = deserializer.deserialize_str()
            deserializer.decrease_container_depth()
            return ConnectionView(phase, label)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ConnectionView {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ConversationDelta(
    val messages: List<com.strike48.pick.shared.MessageView>,
    val toolCalls: List<com.strike48.pick.shared.ToolCallView>,
    val done: Boolean,
    /// What the agent is doing right now (Thinking/Responding/RunningTools/...),
    /// projected from the server's AgentStatus. Drives the animated status line.
    val activity: com.strike48.pick.shared.AgentActivity,
    /// Set when the poll observed `AgentStatus::Error`: an inline notice built
    /// from `tokenUsageStats` distinguishing a token-limit hit from a generic
    /// upstream failure. `None` on a normal (success) delta. When present the
    /// App treats the delta as terminal and surfaces the notice.
    val notice: com.strike48.pick.shared.NoticeView? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        messages.serialize(serializer) {
            it.serialize(serializer)
        }
        toolCalls.serialize(serializer) {
            it.serialize(serializer)
        }
        serializer.serialize_bool(done)
        activity.serialize(serializer)
        notice.serializeOptionOf(serializer) {
            it.serialize(serializer)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ConversationDelta {
            deserializer.increase_container_depth()
            val messages =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.MessageView.deserialize(deserializer)
                }
            val toolCalls =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.ToolCallView.deserialize(deserializer)
                }
            val done = deserializer.deserialize_bool()
            val activity = com.strike48.pick.shared.AgentActivity.deserialize(deserializer)
            val notice =
                deserializer.deserializeOptionOf {
                    com.strike48.pick.shared.NoticeView.deserialize(deserializer)
                }
            deserializer.decrease_container_depth()
            return ConversationDelta(messages, toolCalls, done, activity, notice)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ConversationDelta {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ConversationRef(
    val id: String,
    val title: String,
    val relativeTime: String,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_str(id)
        serializer.serialize_str(title)
        serializer.serialize_str(relativeTime)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ConversationRef {
            deserializer.increase_container_depth()
            val id = deserializer.deserialize_str()
            val title = deserializer.deserialize_str()
            val relativeTime = deserializer.deserialize_str()
            deserializer.decrease_container_depth()
            return ConversationRef(id, title, relativeTime)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ConversationRef {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ConversationsOutcome(
    val conversations: List<com.strike48.pick.shared.ConversationRef>? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        conversations.serializeOptionOf(serializer) { level1 ->
            level1.serialize(serializer) {
                it.serialize(serializer)
            }
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ConversationsOutcome {
            deserializer.increase_container_depth()
            val conversations =
                deserializer.deserializeOptionOf {
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.ConversationRef.deserialize(deserializer)
                    }
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return ConversationsOutcome(conversations, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ConversationsOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class DeltaOutcome(
    val delta: com.strike48.pick.shared.ConversationDelta? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        delta.serializeOptionOf(serializer) {
            it.serialize(serializer)
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): DeltaOutcome {
            deserializer.increase_container_depth()
            val delta =
                deserializer.deserializeOptionOf {
                    com.strike48.pick.shared.ConversationDelta.deserialize(deserializer)
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return DeltaOutcome(delta, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): DeltaOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class DocRef(
    val id: String,
    val title: String,
    val conversationId: String,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_str(id)
        serializer.serialize_str(title)
        serializer.serialize_str(conversationId)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): DocRef {
            deserializer.increase_container_depth()
            val id = deserializer.deserialize_str()
            val title = deserializer.deserialize_str()
            val conversationId = deserializer.deserialize_str()
            deserializer.decrease_container_depth()
            return DocRef(id, title, conversationId)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): DocRef {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class DocView(
    val id: String,
    val title: String,
    val markdownBody: String,
    /// Pre-parsed markdown blocks for native rendering. Derived from `markdown_body`.
    val blocks: List<com.strike48.pick.shared.MarkdownBlock>,
    val shareUrl: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_str(id)
        serializer.serialize_str(title)
        serializer.serialize_str(markdownBody)
        blocks.serialize(serializer) {
            it.serialize(serializer)
        }
        shareUrl.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): DocView {
            deserializer.increase_container_depth()
            val id = deserializer.deserialize_str()
            val title = deserializer.deserialize_str()
            val markdownBody = deserializer.deserialize_str()
            val blocks =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.MarkdownBlock.deserialize(deserializer)
                }
            val shareUrl =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return DocView(id, title, markdownBody, blocks, shareUrl)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): DocView {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class DocumentContentOutcome(
    val content: String? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        content.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): DocumentContentOutcome {
            deserializer.increase_container_depth()
            val content =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return DocumentContentOutcome(content, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): DocumentContentOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class DocumentsOutcome(
    val documents: List<com.strike48.pick.shared.DocRef>? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        documents.serializeOptionOf(serializer) { level1 ->
            level1.serialize(serializer) {
                it.serialize(serializer)
            }
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): DocumentsOutcome {
            deserializer.increase_container_depth()
            val documents =
                deserializer.deserializeOptionOf {
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.DocRef.deserialize(deserializer)
                    }
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return DocumentsOutcome(documents, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): DocumentsOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

sealed interface Effect {
    fun serialize(serializer: Serializer)

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    data class Render(
        val value: com.strike48.pick.shared.RenderOperation,
    ) : Effect {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(0)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Render {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.RenderOperation.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return Render(value)
            }
        }
    }

    data class Pentest(
        val value: com.strike48.pick.shared.PentestOperation,
    ) : Effect {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(1)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Pentest {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.PentestOperation.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return Pentest(value)
            }
        }
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): Effect {
            val index = deserializer.deserialize_variant_index()
            return when (index) {
                0 -> Render.deserialize(deserializer)
                1 -> Pentest.deserialize(deserializer)
                else -> throw DeserializationError("Unknown variant index for Effect: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): Effect {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

sealed interface Event {
    fun serialize(serializer: Serializer)

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    data object StartScan: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(0)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): StartScan {
            return StartScan
        }
    }

    data class SendMessage(
        val value: String,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(1)
            serializer.serialize_str(value)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SendMessage {
                deserializer.increase_container_depth()
                val value = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return SendMessage(value)
            }
        }
    }

    data object NewChat: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(2)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): NewChat {
            return NewChat
        }
    }

    data object OpenHistory: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(3)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): OpenHistory {
            return OpenHistory
        }
    }

    data object CloseHistory: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(4)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): CloseHistory {
            return CloseHistory
        }
    }

    data class SelectConversation(
        val value: String,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(5)
            serializer.serialize_str(value)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SelectConversation {
                deserializer.increase_container_depth()
                val value = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return SelectConversation(value)
            }
        }
    }

    /// User opened the Reports list — (re)fetch all documents on demand, so the
    /// list is populated even without a just-completed scan.
    data object OpenDocuments: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(6)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): OpenDocuments {
            return OpenDocuments
        }
    }

    data class OpenDocument(
        val value: String,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(7)
            serializer.serialize_str(value)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): OpenDocument {
                deserializer.increase_container_depth()
                val value = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return OpenDocument(value)
            }
        }
    }

    data object CloseDocument: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(8)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): CloseDocument {
            return CloseDocument
        }
    }

    data class CreateShareLink(
        val value: String,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(9)
            serializer.serialize_str(value)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): CreateShareLink {
                deserializer.increase_container_depth()
                val value = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return CreateShareLink(value)
            }
        }
    }

    data object RetrySignIn: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(10)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): RetrySignIn {
            return RetrySignIn
        }
    }

    data object DismissError: Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(11)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): DismissError {
            return DismissError
        }
    }

    data class SignInResult(
        val value: com.strike48.pick.shared.SignInOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(12)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SignInResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.SignInOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return SignInResult(value)
            }
        }
    }

    data class ConnectResult(
        val value: com.strike48.pick.shared.ConnectOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(13)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): ConnectResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.ConnectOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return ConnectResult(value)
            }
        }
    }

    data class ScanResult(
        val value: com.strike48.pick.shared.ScanOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(14)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): ScanResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.ScanOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return ScanResult(value)
            }
        }
    }

    data class Delta(
        val value: com.strike48.pick.shared.DeltaOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(15)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Delta {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.DeltaOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return Delta(value)
            }
        }
    }

    data class ConversationsResult(
        val value: com.strike48.pick.shared.ConversationsOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(16)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): ConversationsResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.ConversationsOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return ConversationsResult(value)
            }
        }
    }

    data class LoadConversationResult(
        val value: com.strike48.pick.shared.LoadConversationOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(17)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): LoadConversationResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.LoadConversationOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return LoadConversationResult(value)
            }
        }
    }

    data class DocumentsResult(
        val value: com.strike48.pick.shared.DocumentsOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(18)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): DocumentsResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.DocumentsOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return DocumentsResult(value)
            }
        }
    }

    data class DocumentContentResult(
        val value: com.strike48.pick.shared.DocumentContentOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(19)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): DocumentContentResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.DocumentContentOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return DocumentContentResult(value)
            }
        }
    }

    data class ShareLinkResult(
        val value: com.strike48.pick.shared.ShareLinkOutcome,
    ) : Event {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(20)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): ShareLinkResult {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.ShareLinkOutcome.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return ShareLinkResult(value)
            }
        }
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): Event {
            val index = deserializer.deserialize_variant_index()
            return when (index) {
                0 -> StartScan.deserialize(deserializer)
                1 -> SendMessage.deserialize(deserializer)
                2 -> NewChat.deserialize(deserializer)
                3 -> OpenHistory.deserialize(deserializer)
                4 -> CloseHistory.deserialize(deserializer)
                5 -> SelectConversation.deserialize(deserializer)
                6 -> OpenDocuments.deserialize(deserializer)
                7 -> OpenDocument.deserialize(deserializer)
                8 -> CloseDocument.deserialize(deserializer)
                9 -> CreateShareLink.deserialize(deserializer)
                10 -> RetrySignIn.deserialize(deserializer)
                11 -> DismissError.deserialize(deserializer)
                12 -> SignInResult.deserialize(deserializer)
                13 -> ConnectResult.deserialize(deserializer)
                14 -> ScanResult.deserialize(deserializer)
                15 -> Delta.deserialize(deserializer)
                16 -> ConversationsResult.deserialize(deserializer)
                17 -> LoadConversationResult.deserialize(deserializer)
                18 -> DocumentsResult.deserialize(deserializer)
                19 -> DocumentContentResult.deserialize(deserializer)
                20 -> ShareLinkResult.deserialize(deserializer)
                else -> throw DeserializationError("Unknown variant index for Event: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): Event {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class LoadConversationOutcome(
    val messages: List<com.strike48.pick.shared.MessageView>? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        messages.serializeOptionOf(serializer) { level1 ->
            level1.serialize(serializer) {
                it.serialize(serializer)
            }
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): LoadConversationOutcome {
            deserializer.increase_container_depth()
            val messages =
                deserializer.deserializeOptionOf {
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.MessageView.deserialize(deserializer)
                    }
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return LoadConversationOutcome(messages, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): LoadConversationOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// A top-level rendered block. Nested lists are flattened to top-level items.
sealed interface MarkdownBlock {
    fun serialize(serializer: Serializer)

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    data class Heading(
        val level: UByte,
        val spans: List<com.strike48.pick.shared.Span>,
    ) : MarkdownBlock {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(0)
            serializer.serialize_u8(level)
            spans.serialize(serializer) {
                it.serialize(serializer)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Heading {
                deserializer.increase_container_depth()
                val level = deserializer.deserialize_u8()
                val spans =
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.Span.deserialize(deserializer)
                    }
                deserializer.decrease_container_depth()
                return Heading(level, spans)
            }
        }
    }

    data class Paragraph(
        val spans: List<com.strike48.pick.shared.Span>,
    ) : MarkdownBlock {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(1)
            spans.serialize(serializer) {
                it.serialize(serializer)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Paragraph {
                deserializer.increase_container_depth()
                val spans =
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.Span.deserialize(deserializer)
                    }
                deserializer.decrease_container_depth()
                return Paragraph(spans)
            }
        }
    }

    /// A list item. `number` is 0 for unordered items.
    data class ListItem(
        val ordered: Boolean,
        val number: UInt,
        val spans: List<com.strike48.pick.shared.Span>,
    ) : MarkdownBlock {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(2)
            serializer.serialize_bool(ordered)
            serializer.serialize_u32(number)
            spans.serialize(serializer) {
                it.serialize(serializer)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): ListItem {
                deserializer.increase_container_depth()
                val ordered = deserializer.deserialize_bool()
                val number = deserializer.deserialize_u32()
                val spans =
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.Span.deserialize(deserializer)
                    }
                deserializer.decrease_container_depth()
                return ListItem(ordered, number, spans)
            }
        }
    }

    /// A fenced/indented code block. Its text is verbatim, never styled inline.
    data class CodeBlock(
        val text: String,
    ) : MarkdownBlock {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(3)
            serializer.serialize_str(text)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): CodeBlock {
                deserializer.increase_container_depth()
                val text = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return CodeBlock(text)
            }
        }
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): MarkdownBlock {
            val index = deserializer.deserialize_variant_index()
            return when (index) {
                0 -> Heading.deserialize(deserializer)
                1 -> Paragraph.deserialize(deserializer)
                2 -> ListItem.deserialize(deserializer)
                3 -> CodeBlock.deserialize(deserializer)
                else -> throw DeserializationError("Unknown variant index for MarkdownBlock: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): MarkdownBlock {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

enum class MessageKind {
    USER,
    AGENTTEXT,
    TOOLCALL;

    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_variant_index(ordinal)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): MessageKind {
            deserializer.increase_container_depth()
            val index = deserializer.deserialize_variant_index()
            deserializer.decrease_container_depth()
            return when (index) {
                0 -> USER
                1 -> AGENTTEXT
                2 -> TOOLCALL
                else -> throw DeserializationError("Unknown variant index for MessageKind: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): MessageKind {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// One ordered part of an agent message. The shells render these IN ORDER so a
/// message reads exactly as it does in the Dioxus app: interleaved prose,
/// thinking blocks, and tool cards.
sealed interface MessagePartView {
    fun serialize(serializer: Serializer)

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    /// A run of prose, pre-parsed into render-ready markdown blocks.
    data class Text(
        val blocks: List<com.strike48.pick.shared.MarkdownBlock>,
    ) : MessagePartView {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(0)
            blocks.serialize(serializer) {
                it.serialize(serializer)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Text {
                deserializer.increase_container_depth()
                val blocks =
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.MarkdownBlock.deserialize(deserializer)
                    }
                deserializer.decrease_container_depth()
                return Text(blocks)
            }
        }
    }

    /// A collapsible "thinking" block (raw text, not markdown-styled).
    data class Thinking(
        val text: String,
    ) : MessagePartView {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(1)
            serializer.serialize_str(text)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Thinking {
                deserializer.increase_container_depth()
                val text = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return Thinking(text)
            }
        }
    }

    /// A tool-call card.
    data class Tool(
        val tool: com.strike48.pick.shared.ToolCallView,
    ) : MessagePartView {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(2)
            tool.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Tool {
                deserializer.increase_container_depth()
                val tool = com.strike48.pick.shared.ToolCallView.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return Tool(tool)
            }
        }
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): MessagePartView {
            val index = deserializer.deserialize_variant_index()
            return when (index) {
                0 -> Text.deserialize(deserializer)
                1 -> Thinking.deserialize(deserializer)
                2 -> Tool.deserialize(deserializer)
                else -> throw DeserializationError("Unknown variant index for MessagePartView: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): MessagePartView {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class MessageView(
    val sender: String,
    val kind: com.strike48.pick.shared.MessageKind,
    /// Ordered parts (text/thinking/tool). Shells prefer this over the legacy
    /// flattened `markdown`/`blocks`/`tool` fields, which are kept for a smooth
    /// migration and are derived from the same source message.
    val parts: List<com.strike48.pick.shared.MessagePartView>,
    val markdown: String,
    /// Pre-parsed markdown blocks for native rendering. Derived from `markdown`.
    val blocks: List<com.strike48.pick.shared.MarkdownBlock>,
    val tool: com.strike48.pick.shared.ToolCallView? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_str(sender)
        kind.serialize(serializer)
        parts.serialize(serializer) {
            it.serialize(serializer)
        }
        serializer.serialize_str(markdown)
        blocks.serialize(serializer) {
            it.serialize(serializer)
        }
        tool.serializeOptionOf(serializer) {
            it.serialize(serializer)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): MessageView {
            deserializer.increase_container_depth()
            val sender = deserializer.deserialize_str()
            val kind = com.strike48.pick.shared.MessageKind.deserialize(deserializer)
            val parts =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.MessagePartView.deserialize(deserializer)
                }
            val markdown = deserializer.deserialize_str()
            val blocks =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.MarkdownBlock.deserialize(deserializer)
                }
            val tool =
                deserializer.deserializeOptionOf {
                    com.strike48.pick.shared.ToolCallView.deserialize(deserializer)
                }
            deserializer.decrease_container_depth()
            return MessageView(sender, kind, parts, markdown, blocks, tool)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): MessageView {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// Severity for an inline notice surfaced when the agent backend errors.
/// Mirrors pentest-core's `ChatNoticeKind`; drives styling, not behaviour.
enum class NoticeKind {
    /// The server hit a hard limit (token/rate). User action required.
    TOKENLIMIT,
    /// Some other upstream failure — usually transient.
    UPSTREAMERROR;

    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_variant_index(ordinal)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): NoticeKind {
            deserializer.increase_container_depth()
            val index = deserializer.deserialize_variant_index()
            deserializer.decrease_container_depth()
            return when (index) {
                0 -> TOKENLIMIT
                1 -> UPSTREAMERROR
                else -> throw DeserializationError("Unknown variant index for NoticeKind: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): NoticeKind {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// A render-ready notice describing why a scan/chat stopped without a reply.
/// Mirrors pentest-core's `ChatNotice` across the ViewModel boundary.
data class NoticeView(
    val kind: com.strike48.pick.shared.NoticeKind,
    val title: String,
    val detail: String,
    /// Optional URL to the Studio session (e.g. for checking token usage).
    val studioUrl: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        kind.serialize(serializer)
        serializer.serialize_str(title)
        serializer.serialize_str(detail)
        studioUrl.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): NoticeView {
            deserializer.increase_container_depth()
            val kind = com.strike48.pick.shared.NoticeKind.deserialize(deserializer)
            val title = deserializer.deserialize_str()
            val detail = deserializer.deserialize_str()
            val studioUrl =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return NoticeView(kind, title, detail, studioUrl)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): NoticeView {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

sealed interface PentestOperation {
    fun serialize(serializer: Serializer)

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    data class SignIn(
        val apiUrl: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(0)
            serializer.serialize_str(apiUrl)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SignIn {
                deserializer.increase_container_depth()
                val apiUrl = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return SignIn(apiUrl)
            }
        }
    }

    data class Connect(
        val apiUrl: String,
        val tenant: String,
        val token: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(1)
            serializer.serialize_str(apiUrl)
            serializer.serialize_str(tenant)
            serializer.serialize_str(token)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Connect {
                deserializer.increase_container_depth()
                val apiUrl = deserializer.deserialize_str()
                val tenant = deserializer.deserialize_str()
                val token = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return Connect(apiUrl, tenant, token)
            }
        }
    }

    data class SendScan(
        val conversationId: String? = null,
        val prompt: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(2)
            conversationId.serializeOptionOf(serializer) {
                serializer.serialize_str(it)
            }
            serializer.serialize_str(prompt)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SendScan {
                deserializer.increase_container_depth()
                val conversationId =
                    deserializer.deserializeOptionOf {
                        deserializer.deserialize_str()
                    }
                val prompt = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return SendScan(conversationId, prompt)
            }
        }
    }

    data class SendMessage(
        val conversationId: String? = null,
        val text: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(3)
            conversationId.serializeOptionOf(serializer) {
                serializer.serialize_str(it)
            }
            serializer.serialize_str(text)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SendMessage {
                deserializer.increase_container_depth()
                val conversationId =
                    deserializer.deserializeOptionOf {
                        deserializer.deserialize_str()
                    }
                val text = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return SendMessage(conversationId, text)
            }
        }
    }

    data class PollConversation(
        val conversationId: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(4)
            serializer.serialize_str(conversationId)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): PollConversation {
                deserializer.increase_container_depth()
                val conversationId = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return PollConversation(conversationId)
            }
        }
    }

    data object ListConversations: PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(5)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): ListConversations {
            return ListConversations
        }
    }

    data class LoadConversation(
        val conversationId: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(6)
            serializer.serialize_str(conversationId)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): LoadConversation {
                deserializer.increase_container_depth()
                val conversationId = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return LoadConversation(conversationId)
            }
        }
    }

    data class ListDocuments(
        val agentId: String? = null,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(7)
            agentId.serializeOptionOf(serializer) {
                serializer.serialize_str(it)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): ListDocuments {
                deserializer.increase_container_depth()
                val agentId =
                    deserializer.deserializeOptionOf {
                        deserializer.deserialize_str()
                    }
                deserializer.decrease_container_depth()
                return ListDocuments(agentId)
            }
        }
    }

    data class GetDocumentContent(
        val documentId: String,
        val conversationId: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(8)
            serializer.serialize_str(documentId)
            serializer.serialize_str(conversationId)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): GetDocumentContent {
                deserializer.increase_container_depth()
                val documentId = deserializer.deserialize_str()
                val conversationId = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return GetDocumentContent(documentId, conversationId)
            }
        }
    }

    data class CreateSharedLink(
        val conversationId: String,
        val documentId: String,
    ) : PentestOperation {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(9)
            serializer.serialize_str(conversationId)
            serializer.serialize_str(documentId)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): CreateSharedLink {
                deserializer.increase_container_depth()
                val conversationId = deserializer.deserialize_str()
                val documentId = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return CreateSharedLink(conversationId, documentId)
            }
        }
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): PentestOperation {
            val index = deserializer.deserialize_variant_index()
            return when (index) {
                0 -> SignIn.deserialize(deserializer)
                1 -> Connect.deserialize(deserializer)
                2 -> SendScan.deserialize(deserializer)
                3 -> SendMessage.deserialize(deserializer)
                4 -> PollConversation.deserialize(deserializer)
                5 -> ListConversations.deserialize(deserializer)
                6 -> LoadConversation.deserialize(deserializer)
                7 -> ListDocuments.deserialize(deserializer)
                8 -> GetDocumentContent.deserialize(deserializer)
                9 -> CreateSharedLink.deserialize(deserializer)
                else -> throw DeserializationError("Unknown variant index for PentestOperation: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): PentestOperation {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

sealed interface PentestOutcome {
    fun serialize(serializer: Serializer)

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    data class SignedIn(
        val token: String,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(0)
            serializer.serialize_str(token)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SignedIn {
                deserializer.increase_container_depth()
                val token = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return SignedIn(token)
            }
        }
    }

    data object Connected: PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(1)
            serializer.decrease_container_depth()
        }

        fun deserialize(deserializer: Deserializer): Connected {
            return Connected
        }
    }

    data class ScanQueued(
        val conversationId: String,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(2)
            serializer.serialize_str(conversationId)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): ScanQueued {
                deserializer.increase_container_depth()
                val conversationId = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return ScanQueued(conversationId)
            }
        }
    }

    data class Delta(
        val value: com.strike48.pick.shared.ConversationDelta,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(3)
            value.serialize(serializer)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Delta {
                deserializer.increase_container_depth()
                val value = com.strike48.pick.shared.ConversationDelta.deserialize(deserializer)
                deserializer.decrease_container_depth()
                return Delta(value)
            }
        }
    }

    data class Conversations(
        val list: List<com.strike48.pick.shared.ConversationRef>,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(4)
            list.serialize(serializer) {
                it.serialize(serializer)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Conversations {
                deserializer.increase_container_depth()
                val list =
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.ConversationRef.deserialize(deserializer)
                    }
                deserializer.decrease_container_depth()
                return Conversations(list)
            }
        }
    }

    data class LoadedMessages(
        val messages: List<com.strike48.pick.shared.MessageView>,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(5)
            messages.serialize(serializer) {
                it.serialize(serializer)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): LoadedMessages {
                deserializer.increase_container_depth()
                val messages =
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.MessageView.deserialize(deserializer)
                    }
                deserializer.decrease_container_depth()
                return LoadedMessages(messages)
            }
        }
    }

    data class Documents(
        val list: List<com.strike48.pick.shared.DocRef>,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(6)
            list.serialize(serializer) {
                it.serialize(serializer)
            }
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Documents {
                deserializer.increase_container_depth()
                val list =
                    deserializer.deserializeListOf {
                        com.strike48.pick.shared.DocRef.deserialize(deserializer)
                    }
                deserializer.decrease_container_depth()
                return Documents(list)
            }
        }
    }

    data class DocumentContent(
        val markdown: String,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(7)
            serializer.serialize_str(markdown)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): DocumentContent {
                deserializer.increase_container_depth()
                val markdown = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return DocumentContent(markdown)
            }
        }
    }

    data class SharedLink(
        val url: String,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(8)
            serializer.serialize_str(url)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): SharedLink {
                deserializer.increase_container_depth()
                val url = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return SharedLink(url)
            }
        }
    }

    data class Error(
        val message: String,
    ) : PentestOutcome {
        override fun serialize(serializer: Serializer) {
            serializer.increase_container_depth()
            serializer.serialize_variant_index(9)
            serializer.serialize_str(message)
            serializer.decrease_container_depth()
        }

        companion object {
            fun deserialize(deserializer: Deserializer): Error {
                deserializer.increase_container_depth()
                val message = deserializer.deserialize_str()
                deserializer.decrease_container_depth()
                return Error(message)
            }
        }
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): PentestOutcome {
            val index = deserializer.deserialize_variant_index()
            return when (index) {
                0 -> SignedIn.deserialize(deserializer)
                1 -> Connected.deserialize(deserializer)
                2 -> ScanQueued.deserialize(deserializer)
                3 -> Delta.deserialize(deserializer)
                4 -> Conversations.deserialize(deserializer)
                5 -> LoadedMessages.deserialize(deserializer)
                6 -> Documents.deserialize(deserializer)
                7 -> DocumentContent.deserialize(deserializer)
                8 -> SharedLink.deserialize(deserializer)
                9 -> Error.deserialize(deserializer)
                else -> throw DeserializationError("Unknown variant index for PentestOutcome: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): PentestOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// The single operation `Render` implements.
data object RenderOperation {
    fun serialize(serializer: Serializer) {}

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    fun deserialize(deserializer: Deserializer): RenderOperation {
        return RenderOperation
    }

    @Throws(DeserializationError::class)
    fun bincodeDeserialize(input: ByteArray?): RenderOperation {
        if (input == null) {
            throw DeserializationError("Cannot deserialize null array")
        }
        val deserializer = BincodeDeserializer(input)
        val value = deserialize(deserializer)
        if (deserializer.get_buffer_offset() < input.size) {
            throw DeserializationError("Some input bytes were not read")
        }
        return value
    }
}

/// Request for a side-effect passed from the Core to the Shell.
/// 
/// The `EffectId` links the `Request` with the corresponding call to [`Core::resolve`] to pass the data back
/// to the [`App::update`] function (wrapped in the event provided to the capability originating the effect).
data class Request(
    val id: UInt,
    val effect: com.strike48.pick.shared.Effect,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_u32(id)
        effect.serialize(serializer)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): Request {
            deserializer.increase_container_depth()
            val id = deserializer.deserialize_u32()
            val effect = com.strike48.pick.shared.Effect.deserialize(deserializer)
            deserializer.decrease_container_depth()
            return Request(id, effect)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): Request {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// A batch of effect requests from the Core to the Shell, as serialised by
/// [`Bridge::update`] and [`Bridge::resolve`].
/// 
/// The wire format is identical to `Vec<Request<Eff>>` (the newtype is
/// `serde(transparent)`), so existing shell code that already deserialises
/// a `Vec<Request>` remains binary-compatible.
/// 
/// Registering this type with the type-generation system causes the code
/// generators to emit a `Requests` type (with a `value` field containing the
/// list) together with a top-level `bincodeDeserialize` / `BincodeDeserialize`
/// helper, replacing the hand-written extension files that were previously
/// appended by `add_extensions()`.
data class Requests(
    val value: List<com.strike48.pick.shared.Request>,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        value.serialize(serializer) {
            it.serialize(serializer)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): Requests {
            deserializer.increase_container_depth()
            val value =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.Request.deserialize(deserializer)
                }
            deserializer.decrease_container_depth()
            return Requests(value)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): Requests {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ScanOutcome(
    val conversationId: String? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        conversationId.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ScanOutcome {
            deserializer.increase_container_depth()
            val conversationId =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return ScanOutcome(conversationId, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ScanOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

enum class Screen {
    SCAN,
    CHAT,
    DOCUMENTS,
    DOCVIEWER,
    NEEDSSIGNIN;

    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_variant_index(ordinal)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): Screen {
            deserializer.increase_container_depth()
            val index = deserializer.deserialize_variant_index()
            deserializer.decrease_container_depth()
            return when (index) {
                0 -> SCAN
                1 -> CHAT
                2 -> DOCUMENTS
                3 -> DOCVIEWER
                4 -> NEEDSSIGNIN
                else -> throw DeserializationError("Unknown variant index for Screen: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): Screen {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ShareLinkOutcome(
    val url: String? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        url.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ShareLinkOutcome {
            deserializer.increase_container_depth()
            val url =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return ShareLinkOutcome(url, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ShareLinkOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class SignInOutcome(
    val token: String? = null,
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        token.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): SignInOutcome {
            deserializer.increase_container_depth()
            val token =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return SignInOutcome(token, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): SignInOutcome {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// A run of text with a single inline style.
data class Span(
    val text: String,
    val style: com.strike48.pick.shared.SpanStyle,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_str(text)
        style.serialize(serializer)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): Span {
            deserializer.increase_container_depth()
            val text = deserializer.deserialize_str()
            val style = com.strike48.pick.shared.SpanStyle.deserialize(deserializer)
            deserializer.decrease_container_depth()
            return Span(text, style)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): Span {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

/// The inline style applied to a span of text. Bold+italic collapses to Bold.
enum class SpanStyle {
    PLAIN,
    BOLD,
    ITALIC,
    CODE;

    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_variant_index(ordinal)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): SpanStyle {
            deserializer.increase_container_depth()
            val index = deserializer.deserialize_variant_index()
            deserializer.decrease_container_depth()
            return when (index) {
                0 -> PLAIN
                1 -> BOLD
                2 -> ITALIC
                3 -> CODE
                else -> throw DeserializationError("Unknown variant index for SpanStyle: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): SpanStyle {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ToolCallView(
    val name: String,
    val status: com.strike48.pick.shared.ToolStatus,
    /// Raw JSON arguments the agent invoked the tool with, when available.
    val arguments: String? = null,
    /// Raw tool result payload, when the call has completed.
    val result: String? = null,
    /// Error text, when the call failed.
    val error: String? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_str(name)
        status.serialize(serializer)
        arguments.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        result.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ToolCallView {
            deserializer.increase_container_depth()
            val name = deserializer.deserialize_str()
            val status = com.strike48.pick.shared.ToolStatus.deserialize(deserializer)
            val arguments =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            val result =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            deserializer.decrease_container_depth()
            return ToolCallView(name, status, arguments, result, error)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ToolCallView {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

enum class ToolStatus {
    RUNNING,
    SUCCESS,
    ERROR;

    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        serializer.serialize_variant_index(ordinal)
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        @Throws(DeserializationError::class)
        fun deserialize(deserializer: Deserializer): ToolStatus {
            deserializer.increase_container_depth()
            val index = deserializer.deserialize_variant_index()
            deserializer.decrease_container_depth()
            return when (index) {
                0 -> RUNNING
                1 -> SUCCESS
                2 -> ERROR
                else -> throw DeserializationError("Unknown variant index for ToolStatus: $index")
            }
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ToolStatus {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}

data class ViewModel(
    val screen: com.strike48.pick.shared.Screen,
    val connection: com.strike48.pick.shared.ConnectionView,
    val messages: List<com.strike48.pick.shared.MessageView>,
    val scanInProgress: Boolean,
    val showScanCard: Boolean,
    val conversationDocs: List<com.strike48.pick.shared.DocRef>,
    val allDocuments: List<com.strike48.pick.shared.DocRef>,
    val history: List<com.strike48.pick.shared.ConversationRef>,
    val openDocument: com.strike48.pick.shared.DocView? = null,
    val needsSignIn: Boolean,
    val error: String? = null,
    val toolCalls: List<com.strike48.pick.shared.ToolCallView>,
    /// What the agent is doing right now. Shells render an animated status line
    /// (never a spinner) whenever this is not `Idle`.
    val agentActivity: com.strike48.pick.shared.AgentActivity,
    /// Pre-formatted human label for `agent_activity` (empty when Idle).
    val activityLabel: String,
    /// Inline notice surfaced when the agent backend errored (token limit or a
    /// generic upstream failure) instead of producing a reply. `None` normally.
    val notice: com.strike48.pick.shared.NoticeView? = null,
) {
    fun serialize(serializer: Serializer) {
        serializer.increase_container_depth()
        screen.serialize(serializer)
        connection.serialize(serializer)
        messages.serialize(serializer) {
            it.serialize(serializer)
        }
        serializer.serialize_bool(scanInProgress)
        serializer.serialize_bool(showScanCard)
        conversationDocs.serialize(serializer) {
            it.serialize(serializer)
        }
        allDocuments.serialize(serializer) {
            it.serialize(serializer)
        }
        history.serialize(serializer) {
            it.serialize(serializer)
        }
        openDocument.serializeOptionOf(serializer) {
            it.serialize(serializer)
        }
        serializer.serialize_bool(needsSignIn)
        error.serializeOptionOf(serializer) {
            serializer.serialize_str(it)
        }
        toolCalls.serialize(serializer) {
            it.serialize(serializer)
        }
        agentActivity.serialize(serializer)
        serializer.serialize_str(activityLabel)
        notice.serializeOptionOf(serializer) {
            it.serialize(serializer)
        }
        serializer.decrease_container_depth()
    }

    fun bincodeSerialize(): ByteArray {
        val serializer = BincodeSerializer()
        serialize(serializer)
        return serializer.get_bytes()
    }

    companion object {
        fun deserialize(deserializer: Deserializer): ViewModel {
            deserializer.increase_container_depth()
            val screen = com.strike48.pick.shared.Screen.deserialize(deserializer)
            val connection = com.strike48.pick.shared.ConnectionView.deserialize(deserializer)
            val messages =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.MessageView.deserialize(deserializer)
                }
            val scanInProgress = deserializer.deserialize_bool()
            val showScanCard = deserializer.deserialize_bool()
            val conversationDocs =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.DocRef.deserialize(deserializer)
                }
            val allDocuments =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.DocRef.deserialize(deserializer)
                }
            val history =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.ConversationRef.deserialize(deserializer)
                }
            val openDocument =
                deserializer.deserializeOptionOf {
                    com.strike48.pick.shared.DocView.deserialize(deserializer)
                }
            val needsSignIn = deserializer.deserialize_bool()
            val error =
                deserializer.deserializeOptionOf {
                    deserializer.deserialize_str()
                }
            val toolCalls =
                deserializer.deserializeListOf {
                    com.strike48.pick.shared.ToolCallView.deserialize(deserializer)
                }
            val agentActivity = com.strike48.pick.shared.AgentActivity.deserialize(deserializer)
            val activityLabel = deserializer.deserialize_str()
            val notice =
                deserializer.deserializeOptionOf {
                    com.strike48.pick.shared.NoticeView.deserialize(deserializer)
                }
            deserializer.decrease_container_depth()
            return ViewModel(screen, connection, messages, scanInProgress, showScanCard, conversationDocs, allDocuments, history, openDocument, needsSignIn, error, toolCalls, agentActivity, activityLabel, notice)
        }

        @Throws(DeserializationError::class)
        fun bincodeDeserialize(input: ByteArray?): ViewModel {
            if (input == null) {
                throw DeserializationError("Cannot deserialize null array")
            }
            val deserializer = BincodeDeserializer(input)
            val value = deserialize(deserializer)
            if (deserializer.get_buffer_offset() < input.size) {
                throw DeserializationError("Some input bytes were not read")
            }
            return value
        }
    }
}
