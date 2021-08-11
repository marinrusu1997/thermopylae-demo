import { PAYLOAD_ACCESS_TOKEN_COOKIE_NAME } from './contants.js';
import Cookies from '../vendor/js.cookie.mjs';

/**
 * @typedef {{
 *    anc: string,
 *    iat: number,
 *    exp: number,
 *    aud: string,
 *    iss: string,
 *    sub: string
 * }} JwtPayload
 */

class Storage {
    /**
     * @param {AccountDTO} account
     */
    storeAccount(account) {
        localStorage.setItem('acc',JSON.stringify(account));
    }

    /**
     * @returns {AccountDTO | null}
     */
    retrieveAccount() {
        const account = localStorage.getItem('acc');
        if (account != null) {
            return JSON.parse(account);
        }
        return null;
    }

    /**
     * @returns {boolean}
     */
    hasJwt() {
        return Cookies.get(PAYLOAD_ACCESS_TOKEN_COOKIE_NAME) != null;
    }

    /**
     * @returns {JwtPayload | null}
     */
    retrieveJwt() {
        /** @type {string|null} */
        const payloadAccessTokenCookie = Cookies.get(PAYLOAD_ACCESS_TOKEN_COOKIE_NAME);
        if (!payloadAccessTokenCookie) {
            return null;
        }
        return JSON.parse(btoa(payloadAccessTokenCookie.split('.')[1]));
    }
}

const STORAGE = new Storage();
export { STORAGE };
