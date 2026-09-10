// must_not_fire (ADR-0034): the Juice Shop false-positive class. Every name
// below reads like a key and every value is a storage key, cookie name, header
// name or config constant. None of them is key material, none reaches a key
// parameter, and nothing may fire. The pre-ADR-0034 js-hardcoded-key rule
// fired on the first three shapes in the real scan.

export class BasketService {
  private readonly guestBasketKey = 'guestBasket'

  getGuestBasket (): string | null {
    return sessionStorage.getItem(this.guestBasketKey)
  }
}

export class WelcomeBannerComponent {
  private readonly welcomeBannerStatusCookieKey = 'welcomebanner_status'

  constructor (private readonly cookieService: { put: (key: string, value: string) => void }) {}

  dismiss (): void {
    this.cookieService.put(this.welcomeBannerStatusCookieKey, 'dismiss')
  }
}

const STORAGE_KEY = 'juiceshop_chat_conversations'

export function saveConversations (json: string): void {
  localStorage.setItem(STORAGE_KEY, json)
}

export const API_KEY_HEADER = 'X-Api-Key'
export const tokenStorageKey = 'token'
export const cacheKey = 'basket-42'
export const passwordFieldName = 'password'
export const secretQuestionKey = 'securityQuestion'
export const credentialsMode = 'include'
