import { Router } from 'express'
import Boom from '@hapi/boom'
import { PROVIDERS } from '@shared/config'
import { initProvider } from './utils'
import { UserData } from '@shared/types'

// password-pipedrive doesn't have corresponding @types package, so TS will error on the import syntax.
const { Strategy } = require('passport-pipedrive')

const transformProfile = ({ id, name, email, icon_url }: any): UserData => ({
    id: id.toString(),
    email,
    display_name: name,
    avatar_url: icon_url
  })

export default (router: Router): void => {
  const options = PROVIDERS.pipedrive
  // Checks if the strategy is enabled. Don't create any route otherwise
  if (options) {
    // Checks if the strategy has at least a client ID and a client secret
    if (!options.clientID || !options.clientSecret) {
      throw Boom.badImplementation(`Missing environment variables for Pipedrive OAuth.`)
    }
    initProvider(router, 'pipedrive', Strategy, { transformProfile })
  }
}
