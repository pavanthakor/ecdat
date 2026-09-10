/*
 * Shape mirror of OWASP Juice Shop (upstream 1618a61) for ECDAT ADR-0034.
 * Juice Shop: Copyright (c) 2014-2026 Bjoern Kimminich & contributors. SPDX-License-Identifier: MIT
 */

import { Component, type OnInit, inject, ChangeDetectionStrategy } from '@angular/core'
import { ConfigurationService } from '../Services/configuration.service'
import { MatDialog } from '@angular/material/dialog'
import { WelcomeBannerComponent } from '../welcome-banner/welcome-banner.component'
import { CookieService } from 'ngy-cookie'

@Component({
  changeDetection: ChangeDetectionStrategy.Eager,
  selector: 'app-welcome',
  templateUrl: 'welcome.component.html',
  styleUrls: ['./welcome.component.scss'],
  standalone: true
})

export class WelcomeComponent implements OnInit {
  private readonly dialog = inject(MatDialog)
  private readonly configurationService = inject(ConfigurationService)
  private readonly cookieService = inject(CookieService)

  private readonly welcomeBannerStatusCookieKey = 'welcomebanner_status'

  ngOnInit (): void {
    const welcomeBannerStatus = this.cookieService.get(this.welcomeBannerStatusCookieKey)
    if (welcomeBannerStatus !== 'dismiss') {
      this.dialog.open(WelcomeBannerComponent, { minWidth: '320px', width: '35%' })
    }
  }
}

// ECDAT: line 25 is the same cookie NAME, read back. Nothing may fire here.
