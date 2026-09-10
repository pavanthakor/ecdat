/*
 * Shape mirror of OWASP Juice Shop (upstream 1618a61) for ECDAT ADR-0034.
 * Juice Shop: Copyright (c) 2014-2026 Bjoern Kimminich & contributors. SPDX-License-Identifier: MIT
 */

import { Injectable } from '@angular/core'
import { type StoredConversation } from '../chatbot/chat.model'

const STORAGE_KEY = 'juiceshop_chat_conversations'

@Injectable({
  providedIn: 'root'
})
export class ConversationStorageService {
  getAll (): StoredConversation[] {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const conversations: StoredConversation[] = JSON.parse(raw)
    return conversations.sort((a, b) => b.updatedAt - a.updatedAt)
  }

  save (conversation: StoredConversation): void {
    const all = this.getAll().filter(c => c.id !== conversation.id)
    all.push(conversation)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(all))
  }
}

// ECDAT: line 9 is a localStorage key the pre-ADR-0034 js-hardcoded-key rule
// reported as key material. Nothing may fire in this file.
