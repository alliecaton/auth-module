import { RefreshScheme } from '../../dist/runtime'
import { RefreshToken } from '../../dist/runtime'
import { SchemeCheck } from '../../src/types'
import {RefreshSchemeOptions} from '../../dist/runtime'

import jwtDecode from 'jwt-decode'

interface AtlasRefreshSchemeOptions extends RefreshSchemeOptions {
  allowedDomain: string
}

interface DecodedToken extends RefreshToken {
  accessible_domains: string[]
}

export default class AtlasRefresh extends RefreshScheme {
    check(checkStatus = false): SchemeCheck {
        const response = {
          valid: false,
          tokenExpired: false,
          refreshTokenExpired: false,
          isRefreshable: true
        }

        // Sync tokens
        const token = this.token.sync()
        const refreshToken = this.refreshToken.sync()

        if (!token || !refreshToken) {
          return response
        }

        
        if (token) {
          const formattedToken = (token as string).replace('Bearer ', '')
          const decodedToken: DecodedToken = jwtDecode(formattedToken)
    
          const allowedDomain = (this.options as AtlasRefreshSchemeOptions)?.allowedDomain

          if (
            decodedToken && !decodedToken.accessible_domains?.includes(allowedDomain)
          ) {
            response.valid = false
            return response
          }
        }
    
        // Check status wasn't enabled, let it pass
        if (!checkStatus) {
          response.valid = true
          return response
        }
    
        // Get status
        const tokenStatus = this.token.status()
        const refreshTokenStatus = this.refreshToken.status()
    
        // Refresh token has expired. There is no way to refresh. Force reset.
        if (refreshTokenStatus.expired()) {
          response.refreshTokenExpired = true
          return response
        }
    
        // Token has expired, Force reset.
        if (tokenStatus.expired()) {
          response.tokenExpired = true
          return response
        }
    
        response.valid = true
        return response
      }
}