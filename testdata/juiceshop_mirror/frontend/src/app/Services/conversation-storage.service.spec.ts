/*
 * Shape mirror of OWASP Juice Shop (upstream 1618a61) for ECDAT ADR-0034.
 * Juice Shop: Copyright (c) 2014-2026 Bjoern Kimminich & contributors. SPDX-License-Identifier: MIT
 */

import { ConversationStorageService } from './conversation-storage.service'
import { type StoredConversation } from '../chatbot/chat.model'

const STORAGE_KEY = 'juiceshop_chat_conversations'

describe('ConversationStorageService', () => {
    let service: ConversationStorageService

    beforeEach(() => {
        service = new ConversationStorageService()
        localStorage.clear()
    })

    it('reads what is stored under its key', () => {
        const stored: StoredConversation[] = []
        localStorage.setItem(STORAGE_KEY, JSON.stringify(stored))
        expect(service.getAll()).toEqual([])
    })
})

// ECDAT: line 9 again, in the spec -- the same localStorage key, the same
// false positive. Nothing may fire in this file.
