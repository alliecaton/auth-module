import { RefreshScheme } from '../../../dist/runtime'
import jwtDecode from 'jwt-decode'


export default class AtlasRefresh extends RefreshScheme {
    check(checkStatus = false) {
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
          console.log('hit')
          const formattedToken = token.replace('Bearer ', '')
          const decodedToken = jwtDecode(formattedToken)
    
          const allowedDomain = this.options?.allowedDomain

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