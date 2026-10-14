-- Add conversation_id to chat_messages for grouping history into conversations
ALTER TABLE chat_messages
ADD COLUMN IF NOT EXISTS conversation_id UUID;

CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation_id ON chat_messages (conversation_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_user_conv ON chat_messages (user_id, customer_id, conversation_id);