import { STORAGE } from './storage.js';
import { ApiError } from './api-error.js';

const BASE_URL = window.location.origin;
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
    CHANGE_FORGOTTEN_PASSWORD: {
        method: 'put',
        path: '/api/auth/account/password/forgotten',
    },
    REFRESH_SESSION: {
        method: 'put',
        path: '/api/auth/session/refresh'
    },
    GET_ACTIVE_SESSIONS: {
        method: 'get',
        path: '/api/auth/session/active',
    },
    GET_SUCCESSFUL_AUTHENTICATIONS: {
        method: 'get',
        path: '/api/auth/successful/attempts',
    },
    GET_FAILED_AUTHENTICATIONS: {
        method: 'get',
        path: '/api/auth/failed/attempts',
    },
    CHANGE_PASSWORD: {
        method: 'put',
        path: '/api/auth/account/password',
    },
    SET_TWO_FACTOR_AUTH: {
        method: 'put',
        path: '/api/auth/two/factor',
    },
    LOGOUT: {
        method: 'delete',
        path: '/api/auth/session/logout',
    },
    LOGOUT_ONE: {
        method: 'delete',
        path: '/api/auth/session/logout/one',
    },
    LOGOUT_ALL: {
        method: 'delete',
        path: '/api/auth/session/logout/all',
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
 *     ip: string,
 *     device: object | null | undefined,
 *     location: object | null | undefined,
 *     createdAt: number,
 *     expiresAt: number
 * }} UserSessionMetaData
 */

/**
 * @typedef {{
 *      id: string,
 *      accountId: string,
 *      ip: string,
 *      device: object | null | undefined,
 *      location: object | null | undefined,
 *      authenticatedAt: number
 * }} SuccessfulAuthenticationModel
 */

/**
 * @typedef {{
 *      id: string,
 *      accountId: string,
 *      ip: string,
 *      device: object | null | undefined,
 *      location: object | null | undefined,
 *      detectedAt: number
 * }} FailedAuthenticationModel
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
            referrerPolicy: 'no-referrer'
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
     * @param {string}  token
     * @param {string}  newPassword
     * @returns {Promise<void>}
     */
    async changeForgottenPassword(token, newPassword) {
        const response = await fetch(new URL(`${METHODS.CHANGE_FORGOTTEN_PASSWORD.path}`, BASE_URL).href, {
            method: METHODS.CHANGE_FORGOTTEN_PASSWORD.method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token, newPassword }),
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 204) {
            return;
        }

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (response.status === 400 || response.status === 404 || response.status === 410) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_INPUT') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'ACCOUNT_NOT_FOUND') {
                throw new ApiError(body.error.code, 'Account was deleted.');
            }

            if (body.error.code === 'ACCOUNT_DISABLED') {
                throw new ApiError(body.error.code, 'Account was disabled.');
            }

            if (body.error.code === 'SESSION_NOT_FOUND') {
                throw new ApiError(body.error.code, 'Reset password token is not valid.');
            }

            if (body.error.code === 'WEAK_PASSWORD') {
                throw new ApiError(body.error.code, 'Newly password is too weak.');
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
                'Content-Type': 'application/json',
                'X-Requested-With': 'XmlHttpRequest'
            },
            body: JSON.stringify({ accountId: account.id }),
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 204) {
            return true;
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
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_REFRESH_TOKEN') {
                console.error(body.error);
                return false;
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @returns {Promise<object>}
     */
    async getActiveSessions() {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                throw new ApiError('INVALID_SESSION', 'Session expired.');
            }
        }

        const response = await fetch(new URL(METHODS.GET_ACTIVE_SESSIONS.path, BASE_URL).href, {
            method: METHODS.GET_ACTIVE_SESSIONS.method,
            headers: {
                'X-Requested-With': 'XmlHttpRequest'
            },
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 200) {
            return await response.json();
        }

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (response.status === 400) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please retry operation.');
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @returns {Promise<SuccessfulAuthenticationModel[]>}
     */
    async getSuccessfulAuthentications() {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                throw new ApiError('INVALID_SESSION', 'Session expired.');
            }
        }

        const response = await fetch(new URL(METHODS.GET_SUCCESSFUL_AUTHENTICATIONS.path, BASE_URL).href, {
            method: METHODS.GET_SUCCESSFUL_AUTHENTICATIONS.method,
            headers: {
                'X-Requested-With': 'XmlHttpRequest'
            },
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 200) {
            return await response.json();
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

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please retry operation.');
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @returns {Promise<FailedAuthenticationModel[]>}
     */
    async getFailedAuthentications() {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                throw new ApiError('INVALID_SESSION', 'Session expired.');
            }
        }

        const response = await fetch(new URL(METHODS.GET_FAILED_AUTHENTICATIONS.path, BASE_URL).href, {
            method: METHODS.GET_FAILED_AUTHENTICATIONS.method,
            headers: {
                'X-Requested-With': 'XmlHttpRequest'
            },
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 200) {
            return await response.json();
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

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please retry operation.');
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @param {string}  oldPassword
     * @param {string}  newPassword
     * @returns {Promise<void>}
     */
    async changePassword(oldPassword, newPassword) {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                throw new ApiError('INVALID_SESSION', 'Session expired.');
            }
        }

        const response = await fetch(new URL(METHODS.CHANGE_PASSWORD.path, BASE_URL).href, {
            method: METHODS.CHANGE_PASSWORD.method,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XmlHttpRequest'
            },
            body: JSON.stringify({ oldPassword, newPassword }),
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

            if (body.error.code === 'INCORRECT_PASSWORD') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'SIMILAR_PASSWORDS') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'WEAK_PASSWORD') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please retry operation.');
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 404) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'ACCOUNT_NOT_FOUND') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 410) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'ACCOUNT_DISABLED') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @param {string}      password
     * @param {boolean}     enabled
     * @returns {Promise<{ totpSecretQRImageUrl: string } | undefined>}
     */
    async setTwoFactorAuth(password, enabled) {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                throw new ApiError('INVALID_SESSION', 'Session expired.');
            }
        }

        const response = await fetch(new URL(METHODS.SET_TWO_FACTOR_AUTH.path, BASE_URL).href, {
            method: METHODS.SET_TWO_FACTOR_AUTH.method,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XmlHttpRequest'
            },
            body: JSON.stringify({ enabled, password }),
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 200) {
            return await response.json();
        }
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

            if (body.error.code === 'INCORRECT_PASSWORD') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please retry operation.');
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 404) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'ACCOUNT_NOT_FOUND') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 410) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'ACCOUNT_DISABLED') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @returns {Promise<void>}
     */
    async logout() {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                return; // session is already invalid, nothing to do
            }
        }

        const response = await fetch(new URL(METHODS.LOGOUT.path, BASE_URL).href, {
            method: METHODS.LOGOUT.method,
            headers: {
                'X-Requested-With': 'XmlHttpRequest'
            },
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

            if (body.error.code === 'REFRESH_TOKEN_REQUIRED') {
                console.error(body.error);
                return; // cookie expired, consider logout successful
            }

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please retry logout operation.');
            }

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, 'Please retry logout operation.');
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @param {string} refreshToken
     * @returns {Promise<void>}
     */
    async logoutOne(refreshToken) {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                throw new ApiError('INVALID_SESSION', 'Session expired.');
            }
        }

        const response = await fetch(new URL(METHODS.LOGOUT_ONE.path, BASE_URL).href, {
            method: METHODS.LOGOUT_ONE.method,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XmlHttpRequest'
            },
            body: JSON.stringify({ 'refresh-token': refreshToken }),
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

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please retry operation.');
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }

    /**
     * @returns {Promise<{ numberOfDeletedSessions: number }>}
     */
    async logoutAll() {
        if (!STORAGE.hasJwt()) {
            if (!(await this.refreshUserSession())) {
                throw new Error('Current session can\'t be refreshed. Please perform a simple logout.');
            }
        }

        const response = await fetch(new URL(METHODS.LOGOUT_ALL.path, BASE_URL).href, {
            method: METHODS.LOGOUT_ALL.method,
            headers: {
                'X-Requested-With': 'XmlHttpRequest'
            },
            referrerPolicy: 'no-referrer'
        });

        if (response.status === 200) {
            return await response.json();
        }

        if (response.status === 500) {
            throw new ApiError('INTERNAL_SERVER_ERROR','Internal server error.');
        }

        if (response.status === 400) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'ACCESS_TOKEN_REQUIRED') {
                throw new ApiError(body.error.code, 'Please perform a simple logout.');
            }

            if (body.error.code === 'CSRF_HEADER_REQUIRED') {
                throw new ApiError(body.error.code, body.error.message);
            }
        }

        if (response.status === 401) {
            /** @type {ErrorBody} */
            const body = await response.json();

            if (body.error.code === 'INVALID_SESSION') {
                throw new ApiError(body.error.code, 'Please perform a simple logout.');
            }
        }

        throw new ApiError('MISCONFIGURATION', `Unable to interpret server response. Status: ${response.status}.`);
    }
}

const API = new Api();

export { API };
