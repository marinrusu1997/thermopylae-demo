
const REFRESH_TOKEN_COOKIE_NAME = 'rfh';
const SIGNATURE_ACCESS_TOKEN_COOKIE_NAME = 'sig';
const PAYLOAD_ACCESS_TOKEN_COOKIE_NAME = 'pld';

const PAGES = {
    get LOGIN() {
       return window.location.origin + '/pages/login';
    },
    get MAIN() {
        return window.location.origin + '/pages/main';
    },
    get REGISTER() {
        return window.location.origin + '/pages/register';
    },
    get FORGOT_PASSWORD() {
        return window.location.origin + '/pages/forgot/password';
    }
};
Object.freeze(PAGES);

const SYMBOLS = {
    WINDOW_RECAPTCHA_TOKEN: Symbol('WINDOW_RECAPTCHA_TOKEN')
};
Object.freeze(SYMBOLS);

export { REFRESH_TOKEN_COOKIE_NAME, SIGNATURE_ACCESS_TOKEN_COOKIE_NAME, PAYLOAD_ACCESS_TOKEN_COOKIE_NAME, PAGES, SYMBOLS };
