import Serde

func serializeArray<T, S: Serializer>(
    value: [T],
    serializer: S,
    serializeElement: (T, S) throws -> Void
) throws {
    try serializer.serialize_len(value: value.count)
    for item in value {
        try serializeElement(item, serializer)
    }
}

func deserializeArray<T, D: Deserializer>(
    deserializer: D,
    deserializeElement: (D) throws -> T
) throws -> [T] {
    let length = try deserializer.deserialize_len()
    var obj: [T] = []
    for _ in 0..<length {
        obj.append(try deserializeElement(deserializer))
    }
    return obj
}

func serializeOption<T, S: Serializer>(
    value: T?,
    serializer: S,
    serializeElement: (T, S) throws -> Void
) throws {
    if let value = value {
        try serializer.serialize_option_tag(value: true)
        try serializeElement(value, serializer)
    } else {
        try serializer.serialize_option_tag(value: false)
    }
}

func deserializeOption<T, D: Deserializer>(
    deserializer: D,
    deserializeElement: (D) throws -> T
) throws -> T? {
    let tag = try deserializer.deserialize_option_tag()
    if tag {
        return try deserializeElement(deserializer)
    } else {
        return nil
    }
}

public struct ConnectOutcome {
    public var ok: Void?
    public var err: String?

    public init(ok: Void?, err: String?) {
        self.ok = ok
        self.err = err
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.ok, serializer: serializer) { value, serializer in
            try serializer.serialize_unit(value: value)
        }
        try serializeOption(value: self.err, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ConnectOutcome {
        try deserializer.increase_container_depth()
        let ok = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_unit()
        }
        let err = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return ConnectOutcome(ok: ok, err: err)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ConnectOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum ConnectionPhase: Hashable, Equatable {
    case signingIn
    case connecting
    case registering
    case connected
    case needsSignIn

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .signingIn:
            try serializer.serialize_variant_index(value: 0)
        case .connecting:
            try serializer.serialize_variant_index(value: 1)
        case .registering:
            try serializer.serialize_variant_index(value: 2)
        case .connected:
            try serializer.serialize_variant_index(value: 3)
        case .needsSignIn:
            try serializer.serialize_variant_index(value: 4)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ConnectionPhase {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            try deserializer.decrease_container_depth()
            return .signingIn
        case 1:
            try deserializer.decrease_container_depth()
            return .connecting
        case 2:
            try deserializer.decrease_container_depth()
            return .registering
        case 3:
            try deserializer.decrease_container_depth()
            return .connected
        case 4:
            try deserializer.decrease_container_depth()
            return .needsSignIn
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for ConnectionPhase: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ConnectionPhase {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ConnectionView: Hashable, Equatable {
    public var phase: ConnectionPhase
    public var label: String

    public init(phase: ConnectionPhase, label: String) {
        self.phase = phase
        self.label = label
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try self.phase.serialize(serializer: serializer)
        try serializer.serialize_str(value: self.label)
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ConnectionView {
        try deserializer.increase_container_depth()
        let phase = try ConnectionPhase.deserialize(deserializer: deserializer)
        let label = try deserializer.deserialize_str()
        try deserializer.decrease_container_depth()
        return ConnectionView(phase: phase, label: label)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ConnectionView {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ConversationDelta: Hashable, Equatable {
    public var messages: [MessageView]
    public var toolCalls: [ToolCallView]
    public var done: Bool

    public init(messages: [MessageView], toolCalls: [ToolCallView], done: Bool) {
        self.messages = messages
        self.toolCalls = toolCalls
        self.done = done
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeArray(value: self.messages, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializeArray(value: self.toolCalls, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializer.serialize_bool(value: self.done)
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ConversationDelta {
        try deserializer.increase_container_depth()
        let messages = try deserializeArray(deserializer: deserializer) { deserializer in
            try MessageView.deserialize(deserializer: deserializer)
        }
        let toolCalls = try deserializeArray(deserializer: deserializer) { deserializer in
            try ToolCallView.deserialize(deserializer: deserializer)
        }
        let done = try deserializer.deserialize_bool()
        try deserializer.decrease_container_depth()
        return ConversationDelta(messages: messages, toolCalls: toolCalls, done: done)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ConversationDelta {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ConversationRef: Hashable, Equatable {
    public var id: String
    public var title: String
    public var relativeTime: String

    public init(id: String, title: String, relativeTime: String) {
        self.id = id
        self.title = title
        self.relativeTime = relativeTime
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.serialize_str(value: self.id)
        try serializer.serialize_str(value: self.title)
        try serializer.serialize_str(value: self.relativeTime)
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ConversationRef {
        try deserializer.increase_container_depth()
        let id = try deserializer.deserialize_str()
        let title = try deserializer.deserialize_str()
        let relativeTime = try deserializer.deserialize_str()
        try deserializer.decrease_container_depth()
        return ConversationRef(id: id, title: title, relativeTime: relativeTime)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ConversationRef {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ConversationsOutcome: Hashable, Equatable {
    public var conversations: [ConversationRef]?
    public var error: String?

    public init(conversations: [ConversationRef]?, error: String?) {
        self.conversations = conversations
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.conversations, serializer: serializer) { value, serializer in
            try serializeArray(value: value, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ConversationsOutcome {
        try deserializer.increase_container_depth()
        let conversations = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializeArray(deserializer: deserializer) { deserializer in
                try ConversationRef.deserialize(deserializer: deserializer)
            }
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return ConversationsOutcome(conversations: conversations, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ConversationsOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct DeltaOutcome: Hashable, Equatable {
    public var delta: ConversationDelta?
    public var error: String?

    public init(delta: ConversationDelta?, error: String?) {
        self.delta = delta
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.delta, serializer: serializer) { value, serializer in
            try value.serialize(serializer: serializer)
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> DeltaOutcome {
        try deserializer.increase_container_depth()
        let delta = try deserializeOption(deserializer: deserializer) { deserializer in
            try ConversationDelta.deserialize(deserializer: deserializer)
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return DeltaOutcome(delta: delta, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> DeltaOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct DocRef: Hashable, Equatable {
    public var id: String
    public var title: String
    public var conversationId: String

    public init(id: String, title: String, conversationId: String) {
        self.id = id
        self.title = title
        self.conversationId = conversationId
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.serialize_str(value: self.id)
        try serializer.serialize_str(value: self.title)
        try serializer.serialize_str(value: self.conversationId)
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> DocRef {
        try deserializer.increase_container_depth()
        let id = try deserializer.deserialize_str()
        let title = try deserializer.deserialize_str()
        let conversationId = try deserializer.deserialize_str()
        try deserializer.decrease_container_depth()
        return DocRef(id: id, title: title, conversationId: conversationId)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> DocRef {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct DocView: Hashable, Equatable {
    public var id: String
    public var title: String
    public var markdownBody: String
    /// Pre-parsed markdown blocks for native rendering. Derived from `markdown_body`.
    public var blocks: [MarkdownBlock]
    public var shareUrl: String?

    public init(id: String, title: String, markdownBody: String, blocks: [MarkdownBlock], shareUrl: String?) {
        self.id = id
        self.title = title
        self.markdownBody = markdownBody
        self.blocks = blocks
        self.shareUrl = shareUrl
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.serialize_str(value: self.id)
        try serializer.serialize_str(value: self.title)
        try serializer.serialize_str(value: self.markdownBody)
        try serializeArray(value: self.blocks, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializeOption(value: self.shareUrl, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> DocView {
        try deserializer.increase_container_depth()
        let id = try deserializer.deserialize_str()
        let title = try deserializer.deserialize_str()
        let markdownBody = try deserializer.deserialize_str()
        let blocks = try deserializeArray(deserializer: deserializer) { deserializer in
            try MarkdownBlock.deserialize(deserializer: deserializer)
        }
        let shareUrl = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return DocView(id: id, title: title, markdownBody: markdownBody, blocks: blocks, shareUrl: shareUrl)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> DocView {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct DocumentContentOutcome: Hashable, Equatable {
    public var content: String?
    public var error: String?

    public init(content: String?, error: String?) {
        self.content = content
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.content, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> DocumentContentOutcome {
        try deserializer.increase_container_depth()
        let content = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return DocumentContentOutcome(content: content, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> DocumentContentOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct DocumentsOutcome: Hashable, Equatable {
    public var documents: [DocRef]?
    public var error: String?

    public init(documents: [DocRef]?, error: String?) {
        self.documents = documents
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.documents, serializer: serializer) { value, serializer in
            try serializeArray(value: value, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> DocumentsOutcome {
        try deserializer.increase_container_depth()
        let documents = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializeArray(deserializer: deserializer) { deserializer in
                try DocRef.deserialize(deserializer: deserializer)
            }
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return DocumentsOutcome(documents: documents, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> DocumentsOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum Effect: Hashable, Equatable {
    case render(RenderOperation)
    case pentest(PentestOperation)

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .render(let x):
            try serializer.serialize_variant_index(value: 0)
            try x.serialize(serializer: serializer)
        case .pentest(let x):
            try serializer.serialize_variant_index(value: 1)
            try x.serialize(serializer: serializer)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> Effect {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            let x = try RenderOperation.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .render(x)
        case 1:
            let x = try PentestOperation.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .pentest(x)
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for Effect: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> Effect {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum Event {
    case startScan
    case sendMessage(String)
    case newChat
    case openHistory
    case closeHistory
    case selectConversation(String)
    case openDocument(String)
    case closeDocument
    case createShareLink(String)
    case retrySignIn
    case dismissError
    case signInResult(SignInOutcome)
    case connectResult(ConnectOutcome)
    case scanResult(ScanOutcome)
    case delta(DeltaOutcome)
    case conversationsResult(ConversationsOutcome)
    case loadConversationResult(LoadConversationOutcome)
    case documentsResult(DocumentsOutcome)
    case documentContentResult(DocumentContentOutcome)
    case shareLinkResult(ShareLinkOutcome)

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .startScan:
            try serializer.serialize_variant_index(value: 0)
        case .sendMessage(let x):
            try serializer.serialize_variant_index(value: 1)
            try serializer.serialize_str(value: x)
        case .newChat:
            try serializer.serialize_variant_index(value: 2)
        case .openHistory:
            try serializer.serialize_variant_index(value: 3)
        case .closeHistory:
            try serializer.serialize_variant_index(value: 4)
        case .selectConversation(let x):
            try serializer.serialize_variant_index(value: 5)
            try serializer.serialize_str(value: x)
        case .openDocument(let x):
            try serializer.serialize_variant_index(value: 6)
            try serializer.serialize_str(value: x)
        case .closeDocument:
            try serializer.serialize_variant_index(value: 7)
        case .createShareLink(let x):
            try serializer.serialize_variant_index(value: 8)
            try serializer.serialize_str(value: x)
        case .retrySignIn:
            try serializer.serialize_variant_index(value: 9)
        case .dismissError:
            try serializer.serialize_variant_index(value: 10)
        case .signInResult(let x):
            try serializer.serialize_variant_index(value: 11)
            try x.serialize(serializer: serializer)
        case .connectResult(let x):
            try serializer.serialize_variant_index(value: 12)
            try x.serialize(serializer: serializer)
        case .scanResult(let x):
            try serializer.serialize_variant_index(value: 13)
            try x.serialize(serializer: serializer)
        case .delta(let x):
            try serializer.serialize_variant_index(value: 14)
            try x.serialize(serializer: serializer)
        case .conversationsResult(let x):
            try serializer.serialize_variant_index(value: 15)
            try x.serialize(serializer: serializer)
        case .loadConversationResult(let x):
            try serializer.serialize_variant_index(value: 16)
            try x.serialize(serializer: serializer)
        case .documentsResult(let x):
            try serializer.serialize_variant_index(value: 17)
            try x.serialize(serializer: serializer)
        case .documentContentResult(let x):
            try serializer.serialize_variant_index(value: 18)
            try x.serialize(serializer: serializer)
        case .shareLinkResult(let x):
            try serializer.serialize_variant_index(value: 19)
            try x.serialize(serializer: serializer)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> Event {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            try deserializer.decrease_container_depth()
            return .startScan
        case 1:
            let x = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .sendMessage(x)
        case 2:
            try deserializer.decrease_container_depth()
            return .newChat
        case 3:
            try deserializer.decrease_container_depth()
            return .openHistory
        case 4:
            try deserializer.decrease_container_depth()
            return .closeHistory
        case 5:
            let x = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .selectConversation(x)
        case 6:
            let x = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .openDocument(x)
        case 7:
            try deserializer.decrease_container_depth()
            return .closeDocument
        case 8:
            let x = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .createShareLink(x)
        case 9:
            try deserializer.decrease_container_depth()
            return .retrySignIn
        case 10:
            try deserializer.decrease_container_depth()
            return .dismissError
        case 11:
            let x = try SignInOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .signInResult(x)
        case 12:
            let x = try ConnectOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .connectResult(x)
        case 13:
            let x = try ScanOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .scanResult(x)
        case 14:
            let x = try DeltaOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .delta(x)
        case 15:
            let x = try ConversationsOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .conversationsResult(x)
        case 16:
            let x = try LoadConversationOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .loadConversationResult(x)
        case 17:
            let x = try DocumentsOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .documentsResult(x)
        case 18:
            let x = try DocumentContentOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .documentContentResult(x)
        case 19:
            let x = try ShareLinkOutcome.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .shareLinkResult(x)
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for Event: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> Event {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct LoadConversationOutcome: Hashable, Equatable {
    public var messages: [MessageView]?
    public var error: String?

    public init(messages: [MessageView]?, error: String?) {
        self.messages = messages
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.messages, serializer: serializer) { value, serializer in
            try serializeArray(value: value, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> LoadConversationOutcome {
        try deserializer.increase_container_depth()
        let messages = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializeArray(deserializer: deserializer) { deserializer in
                try MessageView.deserialize(deserializer: deserializer)
            }
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return LoadConversationOutcome(messages: messages, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> LoadConversationOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

/// A top-level rendered block. Nested lists are flattened to top-level items.
indirect public enum MarkdownBlock: Hashable, Equatable {
    case heading(level: UInt8, spans: [Span])
    case paragraph(spans: [Span])
    /// A list item. `number` is 0 for unordered items.
    case listItem(ordered: Bool, number: UInt32, spans: [Span])
    /// A fenced/indented code block. Its text is verbatim, never styled inline.
    case codeBlock(text: String)

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .heading(let level, let spans):
            try serializer.serialize_variant_index(value: 0)
            try serializer.serialize_u8(value: level)
            try serializeArray(value: spans, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        case .paragraph(let spans):
            try serializer.serialize_variant_index(value: 1)
            try serializeArray(value: spans, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        case .listItem(let ordered, let number, let spans):
            try serializer.serialize_variant_index(value: 2)
            try serializer.serialize_bool(value: ordered)
            try serializer.serialize_u32(value: number)
            try serializeArray(value: spans, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        case .codeBlock(let text):
            try serializer.serialize_variant_index(value: 3)
            try serializer.serialize_str(value: text)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> MarkdownBlock {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            let level = try deserializer.deserialize_u8()
            let spans = try deserializeArray(deserializer: deserializer) { deserializer in
                try Span.deserialize(deserializer: deserializer)
            }
            try deserializer.decrease_container_depth()
            return .heading(level: level, spans: spans)
        case 1:
            let spans = try deserializeArray(deserializer: deserializer) { deserializer in
                try Span.deserialize(deserializer: deserializer)
            }
            try deserializer.decrease_container_depth()
            return .paragraph(spans: spans)
        case 2:
            let ordered = try deserializer.deserialize_bool()
            let number = try deserializer.deserialize_u32()
            let spans = try deserializeArray(deserializer: deserializer) { deserializer in
                try Span.deserialize(deserializer: deserializer)
            }
            try deserializer.decrease_container_depth()
            return .listItem(ordered: ordered, number: number, spans: spans)
        case 3:
            let text = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .codeBlock(text: text)
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for MarkdownBlock: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> MarkdownBlock {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum MessageKind: Hashable, Equatable {
    case user
    case agentText
    case toolCall

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .user:
            try serializer.serialize_variant_index(value: 0)
        case .agentText:
            try serializer.serialize_variant_index(value: 1)
        case .toolCall:
            try serializer.serialize_variant_index(value: 2)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> MessageKind {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            try deserializer.decrease_container_depth()
            return .user
        case 1:
            try deserializer.decrease_container_depth()
            return .agentText
        case 2:
            try deserializer.decrease_container_depth()
            return .toolCall
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for MessageKind: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> MessageKind {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

/// One ordered part of an agent message. The shells render these IN ORDER so a
/// message reads exactly as it does in the Dioxus app: interleaved prose,
/// thinking blocks, and tool cards.
indirect public enum MessagePartView: Hashable, Equatable {
    /// A run of prose, pre-parsed into render-ready markdown blocks.
    case text(blocks: [MarkdownBlock])
    /// A collapsible "thinking" block (raw text, not markdown-styled).
    case thinking(text: String)
    /// A tool-call card.
    case tool(tool: ToolCallView)

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .text(let blocks):
            try serializer.serialize_variant_index(value: 0)
            try serializeArray(value: blocks, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        case .thinking(let text):
            try serializer.serialize_variant_index(value: 1)
            try serializer.serialize_str(value: text)
        case .tool(let tool):
            try serializer.serialize_variant_index(value: 2)
            try tool.serialize(serializer: serializer)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> MessagePartView {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            let blocks = try deserializeArray(deserializer: deserializer) { deserializer in
                try MarkdownBlock.deserialize(deserializer: deserializer)
            }
            try deserializer.decrease_container_depth()
            return .text(blocks: blocks)
        case 1:
            let text = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .thinking(text: text)
        case 2:
            let tool = try ToolCallView.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .tool(tool: tool)
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for MessagePartView: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> MessagePartView {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct MessageView: Hashable, Equatable {
    public var sender: String
    public var kind: MessageKind
    /// Ordered parts (text/thinking/tool). Shells prefer this over the legacy
    /// flattened `markdown`/`blocks`/`tool` fields, which are kept for a smooth
    /// migration and are derived from the same source message.
    public var parts: [MessagePartView]
    public var markdown: String
    /// Pre-parsed markdown blocks for native rendering. Derived from `markdown`.
    public var blocks: [MarkdownBlock]
    public var tool: ToolCallView?

    public init(sender: String, kind: MessageKind, parts: [MessagePartView], markdown: String, blocks: [MarkdownBlock], tool: ToolCallView?) {
        self.sender = sender
        self.kind = kind
        self.parts = parts
        self.markdown = markdown
        self.blocks = blocks
        self.tool = tool
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.serialize_str(value: self.sender)
        try self.kind.serialize(serializer: serializer)
        try serializeArray(value: self.parts, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializer.serialize_str(value: self.markdown)
        try serializeArray(value: self.blocks, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializeOption(value: self.tool, serializer: serializer) { value, serializer in
            try value.serialize(serializer: serializer)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> MessageView {
        try deserializer.increase_container_depth()
        let sender = try deserializer.deserialize_str()
        let kind = try MessageKind.deserialize(deserializer: deserializer)
        let parts = try deserializeArray(deserializer: deserializer) { deserializer in
            try MessagePartView.deserialize(deserializer: deserializer)
        }
        let markdown = try deserializer.deserialize_str()
        let blocks = try deserializeArray(deserializer: deserializer) { deserializer in
            try MarkdownBlock.deserialize(deserializer: deserializer)
        }
        let tool = try deserializeOption(deserializer: deserializer) { deserializer in
            try ToolCallView.deserialize(deserializer: deserializer)
        }
        try deserializer.decrease_container_depth()
        return MessageView(sender: sender, kind: kind, parts: parts, markdown: markdown, blocks: blocks, tool: tool)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> MessageView {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum PentestOperation: Hashable, Equatable {
    case signIn(apiUrl: String)
    case connect(apiUrl: String, tenant: String, token: String)
    case sendScan(conversationId: String?, prompt: String)
    case sendMessage(conversationId: String?, text: String)
    case pollConversation(conversationId: String)
    case listConversations
    case loadConversation(conversationId: String)
    case listDocuments(agentId: String?)
    case getDocumentContent(documentId: String, conversationId: String)
    case createSharedLink(conversationId: String, documentId: String)

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .signIn(let apiUrl):
            try serializer.serialize_variant_index(value: 0)
            try serializer.serialize_str(value: apiUrl)
        case .connect(let apiUrl, let tenant, let token):
            try serializer.serialize_variant_index(value: 1)
            try serializer.serialize_str(value: apiUrl)
            try serializer.serialize_str(value: tenant)
            try serializer.serialize_str(value: token)
        case .sendScan(let conversationId, let prompt):
            try serializer.serialize_variant_index(value: 2)
            try serializeOption(value: conversationId, serializer: serializer) { value, serializer in
                try serializer.serialize_str(value: value)
            }
            try serializer.serialize_str(value: prompt)
        case .sendMessage(let conversationId, let text):
            try serializer.serialize_variant_index(value: 3)
            try serializeOption(value: conversationId, serializer: serializer) { value, serializer in
                try serializer.serialize_str(value: value)
            }
            try serializer.serialize_str(value: text)
        case .pollConversation(let conversationId):
            try serializer.serialize_variant_index(value: 4)
            try serializer.serialize_str(value: conversationId)
        case .listConversations:
            try serializer.serialize_variant_index(value: 5)
        case .loadConversation(let conversationId):
            try serializer.serialize_variant_index(value: 6)
            try serializer.serialize_str(value: conversationId)
        case .listDocuments(let agentId):
            try serializer.serialize_variant_index(value: 7)
            try serializeOption(value: agentId, serializer: serializer) { value, serializer in
                try serializer.serialize_str(value: value)
            }
        case .getDocumentContent(let documentId, let conversationId):
            try serializer.serialize_variant_index(value: 8)
            try serializer.serialize_str(value: documentId)
            try serializer.serialize_str(value: conversationId)
        case .createSharedLink(let conversationId, let documentId):
            try serializer.serialize_variant_index(value: 9)
            try serializer.serialize_str(value: conversationId)
            try serializer.serialize_str(value: documentId)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> PentestOperation {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            let apiUrl = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .signIn(apiUrl: apiUrl)
        case 1:
            let apiUrl = try deserializer.deserialize_str()
            let tenant = try deserializer.deserialize_str()
            let token = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .connect(apiUrl: apiUrl, tenant: tenant, token: token)
        case 2:
            let conversationId = try deserializeOption(deserializer: deserializer) { deserializer in
                try deserializer.deserialize_str()
            }
            let prompt = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .sendScan(conversationId: conversationId, prompt: prompt)
        case 3:
            let conversationId = try deserializeOption(deserializer: deserializer) { deserializer in
                try deserializer.deserialize_str()
            }
            let text = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .sendMessage(conversationId: conversationId, text: text)
        case 4:
            let conversationId = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .pollConversation(conversationId: conversationId)
        case 5:
            try deserializer.decrease_container_depth()
            return .listConversations
        case 6:
            let conversationId = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .loadConversation(conversationId: conversationId)
        case 7:
            let agentId = try deserializeOption(deserializer: deserializer) { deserializer in
                try deserializer.deserialize_str()
            }
            try deserializer.decrease_container_depth()
            return .listDocuments(agentId: agentId)
        case 8:
            let documentId = try deserializer.deserialize_str()
            let conversationId = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .getDocumentContent(documentId: documentId, conversationId: conversationId)
        case 9:
            let conversationId = try deserializer.deserialize_str()
            let documentId = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .createSharedLink(conversationId: conversationId, documentId: documentId)
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for PentestOperation: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> PentestOperation {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum PentestOutcome: Hashable, Equatable {
    case signedIn(token: String)
    case connected
    case scanQueued(conversationId: String)
    case delta(ConversationDelta)
    case conversations(list: [ConversationRef])
    case loadedMessages(messages: [MessageView])
    case documents(list: [DocRef])
    case documentContent(markdown: String)
    case sharedLink(url: String)
    case error(message: String)

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .signedIn(let token):
            try serializer.serialize_variant_index(value: 0)
            try serializer.serialize_str(value: token)
        case .connected:
            try serializer.serialize_variant_index(value: 1)
        case .scanQueued(let conversationId):
            try serializer.serialize_variant_index(value: 2)
            try serializer.serialize_str(value: conversationId)
        case .delta(let x):
            try serializer.serialize_variant_index(value: 3)
            try x.serialize(serializer: serializer)
        case .conversations(let list):
            try serializer.serialize_variant_index(value: 4)
            try serializeArray(value: list, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        case .loadedMessages(let messages):
            try serializer.serialize_variant_index(value: 5)
            try serializeArray(value: messages, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        case .documents(let list):
            try serializer.serialize_variant_index(value: 6)
            try serializeArray(value: list, serializer: serializer) { item, serializer in
                try item.serialize(serializer: serializer)
            }
        case .documentContent(let markdown):
            try serializer.serialize_variant_index(value: 7)
            try serializer.serialize_str(value: markdown)
        case .sharedLink(let url):
            try serializer.serialize_variant_index(value: 8)
            try serializer.serialize_str(value: url)
        case .error(let message):
            try serializer.serialize_variant_index(value: 9)
            try serializer.serialize_str(value: message)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> PentestOutcome {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            let token = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .signedIn(token: token)
        case 1:
            try deserializer.decrease_container_depth()
            return .connected
        case 2:
            let conversationId = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .scanQueued(conversationId: conversationId)
        case 3:
            let x = try ConversationDelta.deserialize(deserializer: deserializer)
            try deserializer.decrease_container_depth()
            return .delta(x)
        case 4:
            let list = try deserializeArray(deserializer: deserializer) { deserializer in
                try ConversationRef.deserialize(deserializer: deserializer)
            }
            try deserializer.decrease_container_depth()
            return .conversations(list: list)
        case 5:
            let messages = try deserializeArray(deserializer: deserializer) { deserializer in
                try MessageView.deserialize(deserializer: deserializer)
            }
            try deserializer.decrease_container_depth()
            return .loadedMessages(messages: messages)
        case 6:
            let list = try deserializeArray(deserializer: deserializer) { deserializer in
                try DocRef.deserialize(deserializer: deserializer)
            }
            try deserializer.decrease_container_depth()
            return .documents(list: list)
        case 7:
            let markdown = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .documentContent(markdown: markdown)
        case 8:
            let url = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .sharedLink(url: url)
        case 9:
            let message = try deserializer.deserialize_str()
            try deserializer.decrease_container_depth()
            return .error(message: message)
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for PentestOutcome: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> PentestOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

/// The single operation `Render` implements.
public struct RenderOperation: Hashable, Equatable {
    public init() {
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> RenderOperation {
        try deserializer.increase_container_depth()
        try deserializer.decrease_container_depth()
        return RenderOperation()
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> RenderOperation {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

/// Request for a side-effect passed from the Core to the Shell.
/// 
/// The `EffectId` links the `Request` with the corresponding call to [`Core::resolve`] to pass the data back
/// to the [`App::update`] function (wrapped in the event provided to the capability originating the effect).
public struct Request: Hashable, Equatable {
    public var id: UInt32
    public var effect: Effect

    public init(id: UInt32, effect: Effect) {
        self.id = id
        self.effect = effect
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.serialize_u32(value: self.id)
        try self.effect.serialize(serializer: serializer)
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> Request {
        try deserializer.increase_container_depth()
        let id = try deserializer.deserialize_u32()
        let effect = try Effect.deserialize(deserializer: deserializer)
        try deserializer.decrease_container_depth()
        return Request(id: id, effect: effect)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> Request {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
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
public struct Requests: Hashable, Equatable {
    public var value: [Request]

    public init(value: [Request]) {
        self.value = value
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeArray(value: self.value, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> Requests {
        try deserializer.increase_container_depth()
        let value = try deserializeArray(deserializer: deserializer) { deserializer in
            try Request.deserialize(deserializer: deserializer)
        }
        try deserializer.decrease_container_depth()
        return Requests(value: value)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> Requests {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ScanOutcome: Hashable, Equatable {
    public var conversationId: String?
    public var error: String?

    public init(conversationId: String?, error: String?) {
        self.conversationId = conversationId
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.conversationId, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ScanOutcome {
        try deserializer.increase_container_depth()
        let conversationId = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return ScanOutcome(conversationId: conversationId, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ScanOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum Screen: Hashable, Equatable {
    case scan
    case chat
    case documents
    case docViewer
    case needsSignIn

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .scan:
            try serializer.serialize_variant_index(value: 0)
        case .chat:
            try serializer.serialize_variant_index(value: 1)
        case .documents:
            try serializer.serialize_variant_index(value: 2)
        case .docViewer:
            try serializer.serialize_variant_index(value: 3)
        case .needsSignIn:
            try serializer.serialize_variant_index(value: 4)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> Screen {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            try deserializer.decrease_container_depth()
            return .scan
        case 1:
            try deserializer.decrease_container_depth()
            return .chat
        case 2:
            try deserializer.decrease_container_depth()
            return .documents
        case 3:
            try deserializer.decrease_container_depth()
            return .docViewer
        case 4:
            try deserializer.decrease_container_depth()
            return .needsSignIn
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for Screen: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> Screen {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ShareLinkOutcome: Hashable, Equatable {
    public var url: String?
    public var error: String?

    public init(url: String?, error: String?) {
        self.url = url
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.url, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ShareLinkOutcome {
        try deserializer.increase_container_depth()
        let url = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return ShareLinkOutcome(url: url, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ShareLinkOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct SignInOutcome: Hashable, Equatable {
    public var token: String?
    public var error: String?

    public init(token: String?, error: String?) {
        self.token = token
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializeOption(value: self.token, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> SignInOutcome {
        try deserializer.increase_container_depth()
        let token = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return SignInOutcome(token: token, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> SignInOutcome {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

/// A run of text with a single inline style.
public struct Span: Hashable, Equatable {
    public var text: String
    public var style: SpanStyle

    public init(text: String, style: SpanStyle) {
        self.text = text
        self.style = style
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.serialize_str(value: self.text)
        try self.style.serialize(serializer: serializer)
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> Span {
        try deserializer.increase_container_depth()
        let text = try deserializer.deserialize_str()
        let style = try SpanStyle.deserialize(deserializer: deserializer)
        try deserializer.decrease_container_depth()
        return Span(text: text, style: style)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> Span {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

/// The inline style applied to a span of text. Bold+italic collapses to Bold.
indirect public enum SpanStyle: Hashable, Equatable {
    case plain
    case bold
    case italic
    case code

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .plain:
            try serializer.serialize_variant_index(value: 0)
        case .bold:
            try serializer.serialize_variant_index(value: 1)
        case .italic:
            try serializer.serialize_variant_index(value: 2)
        case .code:
            try serializer.serialize_variant_index(value: 3)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> SpanStyle {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            try deserializer.decrease_container_depth()
            return .plain
        case 1:
            try deserializer.decrease_container_depth()
            return .bold
        case 2:
            try deserializer.decrease_container_depth()
            return .italic
        case 3:
            try deserializer.decrease_container_depth()
            return .code
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for SpanStyle: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> SpanStyle {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ToolCallView: Hashable, Equatable {
    public var name: String
    public var status: ToolStatus
    /// Raw JSON arguments the agent invoked the tool with, when available.
    public var arguments: String?
    /// Raw tool result payload, when the call has completed.
    public var result: String?
    /// Error text, when the call failed.
    public var error: String?

    public init(name: String, status: ToolStatus, arguments: String?, result: String?, error: String?) {
        self.name = name
        self.status = status
        self.arguments = arguments
        self.result = result
        self.error = error
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try serializer.serialize_str(value: self.name)
        try self.status.serialize(serializer: serializer)
        try serializeOption(value: self.arguments, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializeOption(value: self.result, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ToolCallView {
        try deserializer.increase_container_depth()
        let name = try deserializer.deserialize_str()
        let status = try ToolStatus.deserialize(deserializer: deserializer)
        let arguments = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        let result = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        try deserializer.decrease_container_depth()
        return ToolCallView(name: name, status: status, arguments: arguments, result: result, error: error)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ToolCallView {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

indirect public enum ToolStatus: Hashable, Equatable {
    case running
    case success
    case error

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        switch self {
        case .running:
            try serializer.serialize_variant_index(value: 0)
        case .success:
            try serializer.serialize_variant_index(value: 1)
        case .error:
            try serializer.serialize_variant_index(value: 2)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ToolStatus {
        let index = try deserializer.deserialize_variant_index()
        try deserializer.increase_container_depth()
        switch index {
        case 0:
            try deserializer.decrease_container_depth()
            return .running
        case 1:
            try deserializer.decrease_container_depth()
            return .success
        case 2:
            try deserializer.decrease_container_depth()
            return .error
        default: throw DeserializationError.invalidInput(issue: "Unknown variant index for ToolStatus: \(index)")
        }
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ToolStatus {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}

public struct ViewModel: Hashable, Equatable {
    public var screen: Screen
    public var connection: ConnectionView
    public var messages: [MessageView]
    public var scanInProgress: Bool
    public var showScanCard: Bool
    public var conversationDocs: [DocRef]
    public var allDocuments: [DocRef]
    public var history: [ConversationRef]
    public var openDocument: DocView?
    public var needsSignIn: Bool
    public var error: String?
    public var toolCalls: [ToolCallView]

    public init(screen: Screen, connection: ConnectionView, messages: [MessageView], scanInProgress: Bool, showScanCard: Bool, conversationDocs: [DocRef], allDocuments: [DocRef], history: [ConversationRef], openDocument: DocView?, needsSignIn: Bool, error: String?, toolCalls: [ToolCallView]) {
        self.screen = screen
        self.connection = connection
        self.messages = messages
        self.scanInProgress = scanInProgress
        self.showScanCard = showScanCard
        self.conversationDocs = conversationDocs
        self.allDocuments = allDocuments
        self.history = history
        self.openDocument = openDocument
        self.needsSignIn = needsSignIn
        self.error = error
        self.toolCalls = toolCalls
    }

    public func serialize<S: Serializer>(serializer: S) throws {
        try serializer.increase_container_depth()
        try self.screen.serialize(serializer: serializer)
        try self.connection.serialize(serializer: serializer)
        try serializeArray(value: self.messages, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializer.serialize_bool(value: self.scanInProgress)
        try serializer.serialize_bool(value: self.showScanCard)
        try serializeArray(value: self.conversationDocs, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializeArray(value: self.allDocuments, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializeArray(value: self.history, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializeOption(value: self.openDocument, serializer: serializer) { value, serializer in
            try value.serialize(serializer: serializer)
        }
        try serializer.serialize_bool(value: self.needsSignIn)
        try serializeOption(value: self.error, serializer: serializer) { value, serializer in
            try serializer.serialize_str(value: value)
        }
        try serializeArray(value: self.toolCalls, serializer: serializer) { item, serializer in
            try item.serialize(serializer: serializer)
        }
        try serializer.decrease_container_depth()
    }

    public func bincodeSerialize() throws -> [UInt8] {
        let serializer = BincodeSerializer.init();
        try self.serialize(serializer: serializer)
        return serializer.get_bytes()
    }

    public static func deserialize<D: Deserializer>(deserializer: D) throws -> ViewModel {
        try deserializer.increase_container_depth()
        let screen = try Screen.deserialize(deserializer: deserializer)
        let connection = try ConnectionView.deserialize(deserializer: deserializer)
        let messages = try deserializeArray(deserializer: deserializer) { deserializer in
            try MessageView.deserialize(deserializer: deserializer)
        }
        let scanInProgress = try deserializer.deserialize_bool()
        let showScanCard = try deserializer.deserialize_bool()
        let conversationDocs = try deserializeArray(deserializer: deserializer) { deserializer in
            try DocRef.deserialize(deserializer: deserializer)
        }
        let allDocuments = try deserializeArray(deserializer: deserializer) { deserializer in
            try DocRef.deserialize(deserializer: deserializer)
        }
        let history = try deserializeArray(deserializer: deserializer) { deserializer in
            try ConversationRef.deserialize(deserializer: deserializer)
        }
        let openDocument = try deserializeOption(deserializer: deserializer) { deserializer in
            try DocView.deserialize(deserializer: deserializer)
        }
        let needsSignIn = try deserializer.deserialize_bool()
        let error = try deserializeOption(deserializer: deserializer) { deserializer in
            try deserializer.deserialize_str()
        }
        let toolCalls = try deserializeArray(deserializer: deserializer) { deserializer in
            try ToolCallView.deserialize(deserializer: deserializer)
        }
        try deserializer.decrease_container_depth()
        return ViewModel(screen: screen, connection: connection, messages: messages, scanInProgress: scanInProgress, showScanCard: showScanCard, conversationDocs: conversationDocs, allDocuments: allDocuments, history: history, openDocument: openDocument, needsSignIn: needsSignIn, error: error, toolCalls: toolCalls)
    }

    public static func bincodeDeserialize(input: [UInt8]) throws -> ViewModel {
        let deserializer = BincodeDeserializer.init(input: input);
        let obj = try deserialize(deserializer: deserializer)
        if deserializer.get_buffer_offset() < input.count {
            throw DeserializationError.invalidInput(issue: "Some input bytes were not read")
        }
        return obj
    }
}
