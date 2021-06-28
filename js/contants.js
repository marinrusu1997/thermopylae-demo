
const REFRESH_TOKEN_COOKIE_NAME = 'rfh';
const SIGNATURE_ACCESS_TOKEN_COOKIE_NAME = 'sig';
const PAYLOAD_ACCESS_TOKEN_COOKIE_NAME = 'pld';

const PAGES = {
    get LOGIN() {
       return window.location.origin + '/Login_v4' + '/pages/login'; // @fixme remove Login_v4
    },
    get MAIN() {
        return window.location.origin + '/Login_v4' + '/pages/main';  // @fixme remove Login_v4
    },
    get REGISTER() {
        return window.location.origin + '/Login_v4' + '/pages/register';  // @fixme remove Login_v4
    },
    get FORGOT_PASSWORD() {
        return window.location.origin + '/Login_v4' + '/pages/forgot/password';  // @fixme remove Login_v4
    },
    get ACTIVATE_ACCOUNT() {
        return window.location.origin + '/Login_v4' + '/pages/activate/account';  // @fixme remove Login_v4
    }
};
Object.freeze(PAGES);

const SYMBOLS = {
    WINDOW_RECAPTCHA_TOKEN: Symbol('WINDOW_RECAPTCHA_TOKEN')
};
Object.freeze(SYMBOLS);

export { REFRESH_TOKEN_COOKIE_NAME, SIGNATURE_ACCESS_TOKEN_COOKIE_NAME, PAYLOAD_ACCESS_TOKEN_COOKIE_NAME, PAGES, SYMBOLS };
