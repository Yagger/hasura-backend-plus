import { Router } from 'express'
import { Strategy, Profile } from 'passport-pipedrive'
import Boom from '@hapi/boom'
import { PROVIDERS } from '@shared/config'
import { initProvider } from './utils'
import { UserData } from '@shared/types'

const transformProfile = ({ id, name, email, icon_url }: Profile): UserData => ({
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
