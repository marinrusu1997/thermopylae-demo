import { STORAGE } from './storage.js';
import { ApiError } from './api-error.js';

const BASE_URL = 'http://127.0.0.1:8080';
const METHODS = {
    AUTHENTICATE: {
        method: 'post',
        path: '/api/auth/authenticate',
    },
    REGISTER: {
        method: 'post',
        path: '/api/auth/register',
    },
    ACTIVATE_ACCOUNT: {
        method: 'put',
        path: '/api/auth/account/activate',
    },
    CREATE_FORGOT_PASSWORD_SESSION: {
        method: 'post',
        path: '/api/auth/forgot/password/session',
    },
    REFRESH_SESSION: {
        method: 'put',
        path: '/api/auth/session/refresh'
    }
};

/**
 * @typedef {{
 *     username?: string,
 *     password?: string,
 *     '2fa-token'?: string,
 *	   recaptcha?: string
 * }} AuthenticateArgs
 */

/**
 * @typedef {{
 *  id: string,
 *  email: string,
 *  telephone: string,
 *  mfa: boolean
 * }} AccountDTO
 */

/**
 * @typedef {{
 *      account: AccountDTO | undefined,
 *	    nextStep: 'PASSWORD' | 'TWO_FACTOR_AUTH_CHECK' | 'RECAPTCHA' | undefined,
 *	    token: string | undefined,
 *	    error: {
 *		    code: string,
 *		    message: string
 *	    } | undefined
 * }} AuthenticationStatus
 */

/**
 * @typedef {{
 *  username: string,
 *  password: string,
 *	email: string,
 *	telephone: string,
 *	pubKey: string | undefined
 * }} RegistrationInfo
 */

/**
 * @typedef {{
 *     error: {
 *         code: string,
 *         message: string
 *     }
 * }} ErrorBody
 */

class Api {
    /**
     * @param {AuthenticateArgs} args
     * @return {Promise<AuthenticationStatus>}
     */
    async authenticate(args) {
        const response = await fetch(new URL(METHODS.AUTHENTICATE.path, BASE_URL).href, {
            method: METHODS.AUTHENTICATE.method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(args),
            referrerPolicy: 'no-referrer',
            credentials: 'include' // @fixme remove
        });

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (response.status === 410) {
            return {
                error: {
                    code: "ACCOUNT_DISABLED",
                    message: 'Authentication on disable.'
                }
            };
        }

        /** @type {AuthenticationStatus} */
        const authenticationStatus = await response.json();
        if (authenticationStatus.account != null) {
            STORAGE.storeAccount(authenticationStatus.account);
        }
        return authenticationStatus;
    }

    /**
     * @param {RegistrationInfo} registrationInfo
     * @returns {Promise<void>}
     */
    async register(registrationInfo) {
        const response = await fetch(new URL(METHODS.REGISTER.path, BASE_URL).href, {
            method: METHODS.REGISTER.method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(registrationInfo),
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 201) {
            return;
        }

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (response.status === 400) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_INPUT') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'WEAK_PASSWORD') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 409) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'ACCOUNT_WITH_DUPLICATED_FIELDS') {
                throw new ApiError('DUPLICATE', `Account with same ${body.error.message.join(', ')} already exists.`);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Can't interpret server response. Status: ${response.status}.`);
    }

    /**
     * @param {string} token
     * @returns {Promise<void>}
     */
    async activateAccount(token) {
        const response = await fetch(new URL(`${METHODS.ACTIVATE_ACCOUNT.path}?token=${token}`, BASE_URL).href, {
            method: METHODS.ACTIVATE_ACCOUNT.method,
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 204) {
            return;
        }

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (response.status === 400) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_INPUT') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'INVALID_TOKEN') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 409) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'ACCOUNT_WITH_DUPLICATED_FIELDS') {
                throw new ApiError('DUPLICATE', `Account with same ${body.error.message.join(', ')} already exists.`);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Can't interpret server response. Status: ${response.status}.`);
    }

    /**
     * @param {'username' | 'email' | 'telephone'}  field
     * @param {string}                              value
     * @returns {Promise<void>}
     */
    async createForgotPasswordSession(field, value) {
        const response = await fetch(new URL(`${METHODS.CREATE_FORGOT_PASSWORD_SESSION.path}`, BASE_URL).href, {
            method: METHODS.CREATE_FORGOT_PASSWORD_SESSION.method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                [field]: value,
                sendTokenVia: field === 'telephone' ? 'sms' : 'email'
            }),
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 202) {
            return;
        }

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (response.status === 400) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_INPUT') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Can't interpret server response. Status: ${response.status}.`);
    }

    /**
     * @returns {Promise<boolean>}
     */
    async refreshUserSession() {
        const account = STORAGE.retrieveAccount();
        if (account == null) {
            return false; // @fixme remove account from storage
        }

        const response = await fetch(new URL(METHODS.REFRESH_SESSION.path, BASE_URL).href, {
            method: METHODS.REFRESH_SESSION.method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ accountId: account.id }),
            referrerPolicy: 'no-referrer',
            credentials: 'include' // @fixme remove
        });

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (!response.ok) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (response.status === 400) {
                if (body.error.code === 'INVALID_INPUT') {
                    throw new ApiError(body.error.code, body.error.message);
                }

                if (body.error.code === 'REFRESH_TOKEN_REQUIRED') {
                    console.error(body.error);
                    return false;
                }

                if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                    throw new ApiError(body.error.code, body.error.message);
                }

                if (body.error.code === 'AUTHENTICATION_DEVICE_MISMATCH') {
                    throw new ApiError(body.error.code, body.error.message);
                }
            }

            if (response.status === 404) {
                if (body.error.code === 'INVALID_REFRESH_TOKEN') {
                    console.error(body.error);
                    return false;
                }
            }

            throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}. Body: ${JSON.stringify(body)}`);
        }

        return false;
    }
}

const API = new Api();

export { API };
