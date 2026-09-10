/*
 * Shape mirror of OWASP Juice Shop (upstream 1618a61) for ECDAT ADR-0034.
 * Juice Shop: Copyright (c) 2014-2026 Bjoern Kimminich & contributors. SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'
import { type Observable, Subject, forkJoin, of } from 'rxjs'
import { switchMap, tap } from 'rxjs/operators'

interface OrderDetail {
  paymentId: string
  addressId: string
  deliveryMethodId: string
}

interface GuestBasketItem {
  ProductId: number
  quantity: number
}

@Injectable({
  providedIn: 'root'
})
export class BasketService {
  private readonly http = inject(HttpClient)

  public hostServer = environment.hostServer
  public itemTotal = new Subject<any>()
  private readonly host = this.hostServer + '/api/BasketItems'
  private readonly guestBasketKey = 'guestBasket'

  get (id: number) {
    return this.http.get(`${this.host}/${id}`).pipe(map((response: any) => response.data), catchError((error) => { throw error }))
  }

  getGuestBasket (): GuestBasketItem[] {
    return JSON.parse(sessionStorage.getItem(this.guestBasketKey) ?? '[]')
  }
}

// ECDAT: line 33 is the declaration the pre-ADR-0034 js-hardcoded-key rule
// reported as "hard-coded key material" in the real Juice Shop scan. It is a
// sessionStorage key. Nothing may fire in this file.
