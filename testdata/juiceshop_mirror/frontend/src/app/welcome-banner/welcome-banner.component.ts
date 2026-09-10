/*
 * Shape mirror of OWASP Juice Shop (upstream 1618a61) for ECDAT ADR-0034.
 * Juice Shop: Copyright (c) 2014-2026 Bjoern Kimminich & contributors. SPDX-License-Identifier: MIT
 */

import { Component, type OnInit, inject, ChangeDetectionStrategy } from '@angular/core'
import { ConfigurationService } from '../Services/configuration.service'
import { MatDialogRef } from '@angular/material/dialog'
import { CookieService } from 'ngy-cookie'
import { TranslateModule } from '@ngx-translate/core'

import { MatIconModule } from '@angular/material/icon'
import { MatTooltip } from '@angular/material/tooltip'
import { MatButtonModule } from '@angular/material/button'

@Component({
  changeDetection: ChangeDetectionStrategy.Eager,
  selector: 'app-welcome-banner',
  templateUrl: 'welcome-banner.component.html',
  styleUrls: ['./welcome-banner.component.scss'],
  imports: [MatButtonModule, MatTooltip, MatIconModule, TranslateModule]
})
export class WelcomeBannerComponent implements OnInit {
  dialogRef = inject<MatDialogRef<WelcomeBannerComponent>>(MatDialogRef)
  private readonly configurationService = inject(ConfigurationService)
  private readonly cookieService = inject(CookieService)

  public title = 'Welcome to OWASP Juice Shop'
  public message = '<p>A web application with a vast number of intended security vulnerabilities.</p>'
  public showHackingInstructor = true
  public showDismissBtn = true

  private readonly welcomeBannerStatusCookieKey = 'welcomebanner_status'

  ngOnInit (): void {
    this.configurationService.getApplicationConfiguration().subscribe({
      error: (err) => { console.log(err) }
    })
  }

  closeWelcome (): void {
    this.dialogRef.close()
    const expires = new Date()
    expires.setFullYear(expires.getFullYear() + 1)
    this.cookieService.put(this.welcomeBannerStatusCookieKey, 'dismiss', { expires })
  }
}

// ECDAT: line 33 is a cookie NAME the pre-ADR-0034 js-hardcoded-key rule
// reported as key material. Nothing may fire in this file.
